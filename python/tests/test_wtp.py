"""wtp.Session auto-echo behavior: answering AC keep-alives while waiting.

Copyright (c) 2026  Wang Jian
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wtpan.ctrl import CtrlMsg
from wtpan.frame import CtrlFrame
from wtpan.wtp import Session


class FakeTransports:
    """Records sent payloads and serves a scripted reply queue."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []  # (mtype, wire)

    def send(self, payload, mtype):
        self.sent.append((mtype, bytes(payload)))

    def recv(self):
        return self.replies.pop(0) if self.replies else None

    def close(self):
        pass


def _h3c():
    return CtrlFrame(CtrlFrame.H3C)


def _echo_req(seq=100):
    return CtrlMsg(msg_type=13, seq=seq, elems=[]).encode(_h3c())


def _join_resp(seq=2):
    return CtrlMsg(msg_type=4, seq=seq, elems=[]).encode(_h3c())


def _discovery_resp(seq=1):
    return CtrlMsg(msg_type=2, seq=seq, elems=[]).encode(_h3c())


def _make_session(replies):
    sess = Session(templates={}, frm=CtrlFrame.H3C)
    sess.transports = FakeTransports(replies)
    return sess


def test_echo_request_is_answered_not_surfaced():
    sess = _make_session([_echo_req(100), _join_resp(2)])
    res = sess.send(3, fallback="join")
    # the join reply is what the caller asked for
    assert res.resp is not None and res.resp.msg_type == 4
    answered = [w for m, w in sess.transports.sent if m == 14]
    assert len(answered) == 1
    resp = CtrlMsg.decode(_h3c(), _h3c().wire_to_control(answered[0]))
    assert resp.msg_type == 14 and resp.seq == 100


def test_plain_reply_is_not_intercepted():
    sess = _make_session([_join_resp(2)])
    res = sess.send(3, fallback="join")
    assert res.resp.msg_type == 4
    assert all(m != 14 for m, _ in sess.transports.sent)


def test_empty_template_fallback_echo_response():
    # Without an mtype-14 template the auto-echo is an element-less
    # Echo Response with the request's sequence number.
    sess = _make_session([_echo_req(7), _join_resp(2)])
    sess.send(3, fallback="join")
    answered = [w for m, w in sess.transports.sent if m == 14]
    resp = CtrlMsg.decode(_h3c(), _h3c().wire_to_control(answered[0]))
    assert resp.msg_type == 14 and resp.seq == 7 and resp.elems == []


def test_multi_echo_before_reply_all_answered():
    sess = _make_session([_echo_req(1), _echo_req(2), _join_resp(2)])
    res = sess.send(3, fallback="join")
    assert res.resp.msg_type == 4
    answered = [w for m, w in sess.transports.sent if m == 14]
    assert len(answered) == 2


def _make_gated_session(replies, require_discovery):
    sess = Session(templates={}, frm=CtrlFrame.H3C,
                   require_discovery=require_discovery)
    sess.transports = FakeTransports(replies)
    return sess


def test_require_discovery_stops_when_silent():
    sess = _make_gated_session([], require_discovery=True)
    results = sess.session()
    # gate tripped: only the discovery phase ran, nothing after it
    assert len(results) == 1 and results[0].phase == "discover"
    sent_types = [m for m, _ in sess.transports.sent]
    assert sent_types == [1]


def test_require_discovery_proceeds_when_answered():
    sess = _make_gated_session([_discovery_resp(1)], require_discovery=True)
    results = sess.session()
    assert len(results) == 3
    sent_types = [m for m, _ in sess.transports.sent]
    assert sent_types == [1, 3, 5]


def test_default_lenient_proceeds_when_silent():
    # Without the gate a silent discovery does not stop the flow (the M60
    # simulator skips the discovery exchange, for example).
    sess = _make_gated_session([], require_discovery=False)
    results = sess.session()
    assert len(results) == 3
    sent_types = [m for m, _ in sess.transports.sent]
    assert sent_types == [1, 3, 5]
