"""Phase-driven CAPWAP WTP client.

Copyright (c) 2026  Wang Jian

For each protocol phase (discovery, join, config status, echo, chan-util,
...) the client packet is *constructed* on demand: the recorded AX60 packet
for that phase (extracted into `templates.py`) supplies the byte-level layout,
runtime elements (IPs, MAC, seq) are rewritten, and the packet is sent to the
target AC to observe its reply. The whole dump is never re-sent wholesale.
"""

import json
import os
import time
from dataclasses import dataclass, field

from .ctrl import CtrlMsg
from .ctrl_names import MsgElemType, MsgType, elem_name, msg_name
from .frame import CtrlFrame
from .subst import Substitution
from .transport import Transports

#: Recorded AX60 Join Request control payload (app_data[8..], no base header):
#: msg_type 3, 4-byte seq, elements incl. Location/WTP Board Data/WTP
#: Descriptor/WTP Frame Tunnel Mode/Session ID/WTP MAC Type/WTP Radio Info/
#: Local IPv4/Name/Vendor Specific/Radio Stats etc. The real device sent
#: WTP_NAME="SWBA1B0" and MAC c4:c0:63:ef:ca:25. Used as the fallback builder
#: when the dump has no Join Request template.
JOIN_CTRL_HEX = (
    "000000030000011d019300001c001020204e65787420746f2046726964676500260030000000"
    "30000000205357424131423000000000000000000000000000000000000000000000000000"
    "00010004000000000027002a0202010100000000003000000004000000000000003000010004"
    "00513301000000300002000400000000001e0004c0a80032002d000753574241314230002300"
    "10bc6806000000020000002c2e0148a9210029000102002c0001000418000500000000140418"
    "0005010000001400500004000000020054000400000001006400040000000100360006c4c063"
    "efca250037001432313938303141325932503232353031303856480038000400000001003900"
    "0400000006003f000400000024003a000400000000003c000400000000003d000f5357424131"
    "423056313030443031370040000f535742413142305631303052303130006500040000000000"
    "66000400000000010042000b313030304dc8abcbabb9a4005500044158363000680004000000"
    "010067000400000001006b00040000000100690004000000010083000400000001"
)

#: Recorded AX60 Configuration Status Request (full wire, H3C framing): the
#: live request carries the 01 10 base header, AC Name "My AC", two Radio
#: Administrative State elements and a 15-byte all-zero CAPWAP Local IPv4
#: Address variant. Used as the fallback builder when the dump has no
#: Configuration Status Request template.
CFG_REQ_WIRE_HEX = (
    "0110020000000000000000050000011e004f00000400054d792041430005000a004143507269"
    "6d6172790005000c0141435365636f6e64617279001f00020001001f00020101002400020078"
    "0030000f000000000000000000000000000000"
)


def discovery_request(ac_ip, wtp_mac, seq=1, frm=CtrlFrame.H3C):
    """Construct a minimal RFC 5415-shaped Discovery Request (fallback when
    the dump has no discovery template)."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    board = bytes(wtp_mac) + bytes([0]) + (0).to_bytes(2, "big")
    desc = bytes([1, 1]) + (0).to_bytes(2, "big") + (5).to_bytes(2, "big") + \
        bytes(wtp_mac) + (0).to_bytes(4, "big")
    elems = [
        (MsgElemType.DISC_TYPE, bytes([1])),
        (MsgElemType.WTP_BOARD_DATA, board),
        (MsgElemType.WTP_DESCRIPTOR, desc),
        (MsgElemType.WTP_FRAME_TUNNEL_MODE, bytes([1])),
        (MsgElemType.WTP_MAC_TYPE, bytes([0])),
        (MsgElemType.ECN_SUPPORT, bytes([1])),
        (MsgElemType.WTP_RADIO_INFO, bytes([1, 1, 1, 2, 0, 0, 0, 0, 0])),
    ]
    return CtrlMsg(msg_type=1, seq=seq, elems=elems)


def join_request(seq, frm=CtrlFrame.H3C):
    """Join Request from the recorded AX60 control payload, re-sequenced."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    msg = CtrlMsg.decode(frm, bytes.fromhex(JOIN_CTRL_HEX))
    msg.seq = seq
    return msg


def config_status_request(seq, frm=CtrlFrame.H3C):
    """Configuration Status Request from the recorded AX60 wire bytes. The
    template is H3C-framed (includes the base header)."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    if frm.name != frm.H3C:
        raise ValueError("config_status_request template is H3C-framed only")
    msg = CtrlMsg.decode(frm, bytes.fromhex(CFG_REQ_WIRE_HEX)[8:])
    msg.seq = seq
    return msg


def build(which, seq=1, frm=CtrlFrame.H3C, **kw):
    """Builder dispatch (fallback messages for phases without a template)."""
    if which == "discovery":
        return discovery_request(kw["ac_ip"], kw["wtp_mac"], seq, frm)
    if which == "join":
        return join_request(seq, frm)
    if which == "config-status":
        return config_status_request(seq, frm)
    raise ValueError(f"unknown builder {which!r}")


@dataclass
class ExchangeResult:
    """Outcome of one phase: the built/sent message and the AC's reply."""

    phase: str
    sent_mtype: int
    sent_seq: int
    subst_diff: list = field(default_factory=list)  # (tag, before, after, note)
    resp: CtrlMsg = None  # parsed reply from the target (None on timeout)
    resp_wire: bytes = None
    expected: CtrlMsg = None  # parsed reference reply from the dump
    diffs: list = field(default_factory=list)  # human-readable diff lines

    @property
    def ok(self):
        return self.resp is not None and not self.diffs


def _diff_msgs(name, got, expected):
    """Element-level comparison of the target reply vs the reference reply."""
    lines = []
    if expected is None:
        if got is not None:
            lines.append(f"no reference reply recorded, target replied "
                         f"{msg_name(got.msg_type)} seq {got.seq}")
        return lines
    if got is None:
        lines.append(f"no reply within timeout (expected "
                     f"{msg_name(expected.msg_type)} seq {expected.seq})")
        return lines
    if got.msg_type != expected.msg_type:
        lines.append(f"mtype mismatch: got {got.msg_type}"
                     f"({msg_name(got.msg_type)}) vs expected "
                     f"{expected.msg_type}({msg_name(expected.msg_type)})")
    if got.seq != expected.seq:
        lines.append(f"seq mismatch: got {got.seq} vs expected {expected.seq}")
    got_map = {}
    for t, d in got.elems:
        got_map.setdefault(t, []).append(d.hex())
    exp_map = {}
    for t, d in expected.elems:
        exp_map.setdefault(t, []).append(d.hex())
    for t in sorted(set(exp_map) | set(got_map)):
        if t not in got_map:
            lines.append(f"missing elem {elem_name(t)} (0x{t:04x})")
        elif t not in exp_map:
            lines.append(f"unexpected elem {elem_name(t)} (0x{t:04x})")
        elif got_map[t] != exp_map[t]:
            lines.append(f"elem {elem_name(t)} (0x{t:04x}) value diff: "
                         f"got {got_map[t]} vs expected {exp_map[t]}")
    return lines


class Session:
    """Phase-driven WTP client against a target AC.

    `templates` maps message type -> Template (see templates.py). For each
    phase the client builds one message from the template (or a fallback
    builder), applies the runtime substitution, sends it, and records the
    AC's reply with a diff against the dump reference.
    """

    def __init__(self, templates, frm=CtrlFrame.H3C, subst=None,
                 target=("127.0.0.1", 5246), dtls=True, client_pem=None,
                 ca=None, verify=False, timeout=5.0, keep_seq=False,
                 seq_start=1, require_discovery=False):
        self.templates = templates or {}
        self.frm = CtrlFrame(frm) if isinstance(frm, str) else frm
        self.subst = subst or Substitution()
        self.target = target
        self.timeout = timeout
        self.keep_seq = keep_seq
        self.next_seq = seq_start
        #: When True, `session()` aborts after the discovery phase unless the
        #: AC answered the Discovery Request with a Discovery Response,
        #: enforcing the RFC 5415 discovery-first handshake. Defaults to
        #: lenient (proceed anyway) so the tool still works against ACs that
        #: skip the discovery exchange.
        self.require_discovery = require_discovery
        self.transports = Transports(target[0], target[1], dtls=dtls,
                                     client_pem=client_pem, ca=ca,
                                     verify=verify, timeout=timeout)

    def _take_seq(self, seq):
        if seq is None and not self.keep_seq:
            seq = self.next_seq
            self.next_seq += 1
        return seq

    def _build(self, mtype, seq, fallback=None, ac_ip=None, wtp_mac=None):
        if mtype in self.templates:
            tpl = self.templates[mtype]
            msg = CtrlMsg.decode(self.frm,
                                 self.frm.wire_to_control(tpl.wire))
            msg.seq = seq
            return msg, tpl
        if fallback:
            kw = {"ac_ip": ac_ip or "192.168.0.50",
                  "wtp_mac": wtp_mac or bytes.fromhex("c4c063efca25")}
            return build(fallback, seq, self.frm, **kw), None
        raise KeyError(f"no template for message type {mtype} "
                       f"({msg_name(mtype)}); provide --build or a template")

    def _auto_echo(self, resp_wire):
        """Answer an AC-initiated Echo Request, mirroring a real WTP.

        Returns True when `resp_wire` is an Echo Request (already answered);
        the caller then keeps waiting for the reply it actually wants. The
        response mirrors the recorded AX60 Echo Response template when one
        exists, otherwise it is an element-less Echo Response with the same
        sequence number (what miniac accepts)."""
        try:
            msg = CtrlMsg.decode(self.frm, self.frm.wire_to_control(resp_wire))
        except ValueError:
            return False
        if msg.msg_type != MsgType.ECHO_REQ:
            return False
        if 14 in self.templates:
            tpl = self.templates[14]
            echo = CtrlMsg.decode(self.frm, self.frm.wire_to_control(tpl.wire))
            echo.seq = msg.seq
        else:
            echo = CtrlMsg(msg_type=MsgType.ECHO_RESP, seq=msg.seq, elems=[])
        self.transports.send(echo.encode(self.frm), echo.msg_type)
        print(f"[auto-echo] answered AC Echo Request seq {msg.seq}")
        return True

    def send(self, mtype, seq=None, fallback=None, phase=None, out=None):
        """Build and send ONE message of `mtype`, then capture the reply."""
        phase = phase or msg_name(mtype).lower()
        seq = self._take_seq(seq)
        msg, tpl = self._build(mtype, seq, fallback=fallback,
                               ac_ip=self.subst.ac_ip,
                               wtp_mac=self.subst.wtp_mac)
        new_msg, subst_diff = self.subst.apply(msg)
        new_msg.seq = seq
        wire = new_msg.encode(self.frm)
        self.transports.send(wire, new_msg.msg_type)
        while True:
            resp_wire = self.transports.recv()
            if resp_wire is None:
                break  # timeout waiting for the reply
            if self._auto_echo(resp_wire):
                continue  # answered an AC keep-alive, keep waiting
            break
        resp = None
        if resp_wire:
            try:
                resp = CtrlMsg.decode(self.frm,
                                      self.frm.wire_to_control(resp_wire))
            except ValueError:
                resp = None
        expected = None
        if tpl is not None and tpl.resp_wire:
            try:
                expected = CtrlMsg.decode(
                    self.frm, self.frm.wire_to_control(tpl.resp_wire))
                expected, _ = self.subst.apply(expected)
            except ValueError:
                expected = None
        diffs = _diff_msgs(phase, resp, expected)
        res = ExchangeResult(phase=phase, sent_mtype=new_msg.msg_type,
                             sent_seq=new_msg.seq, subst_diff=subst_diff,
                             resp=resp, resp_wire=resp_wire,
                             expected=expected, diffs=diffs)
        self._report(res)
        if out:
            self._append_export(out, res)
        return res

    def do_discovery(self, **kw):
        """Discovery phase: plaintext Discovery Request -> Discovery Response."""
        return self.send(1, fallback="discovery", phase="discover", **kw)

    def do_join(self, **kw):
        """Join phase: DTLS handshake, then Join Request -> Join Response."""
        return self.send(3, fallback="join", phase="join", **kw)

    def do_config_status(self, **kw):
        """Config phase: Configuration Status Request -> Response."""
        return self.send(5, fallback="config-status", phase="config-status",
                         **kw)

    def do_change_state_event(self, **kw):
        """Change-state phase: Change State Event Request -> Response.

        Sends the recorded Change State Event Request (radio operational
        states); the AC moves the WTP into Run state on receipt."""
        return self.send(11, phase="change-state-event", **kw)

    def do_echo(self, **kw):
        """Echo phase: Echo Request -> Echo Response."""
        return self.send(13, phase="echo", **kw)

    def do_chan_util(self, **kw):
        """Chan-util phase: H3C channel utilization report -> ack."""
        return self.send(145, phase="chan-util", **kw)

    def session(self, out=None, run=False, hold=0):
        """Full flow: discovery (plaintext) -> DTLS join -> config status.

        With `run=True` the flow continues into the Run state: change-state
        event, echo and channel-utilization phases, mirroring a WTP that has
        completed registration and keeps reporting to the AC. With `hold>0`
        the session then stays connected for that many seconds, answering the
        AC's keep-alive Echo Requests so it survives miniac's Run-state
        active echo timer (30s).

        With `require_discovery` (constructor) the flow stops after the
        discovery phase unless the AC replied: RFC 5415 wants every control
        exchange to start with discovery, so a silent discovery usually means
        the AC is not reachable on the CAPWAP port at all."""
        results = []
        results.append(self.do_discovery(out=out))
        if self.require_discovery and results[-1].resp is None:
            print("[session] no Discovery Response within timeout; stopping "
                  "(use without --require-discovery to continue anyway)")
            return results
        results.append(self.do_join(out=out))
        results.append(self.do_config_status(out=out))
        if run:
            results.append(self.do_change_state_event(out=out))
            results.append(self.do_echo(out=out))
            results.append(self.do_chan_util(out=out))
        if run and hold > 0:
            self.hold(hold)
        return results

    def hold(self, seconds):
        """Stay connected for `seconds`, answering AC Echo Requests so a
        Run-state session survives the AC's active keep-alive. Returns the
        number of Echo Requests answered."""
        deadline = time.monotonic() + seconds
        answered = 0
        while time.monotonic() < deadline:
            resp_wire = self.transports.recv()
            if resp_wire is None:
                continue
            if self._auto_echo(resp_wire):
                answered += 1
        print(f"[hold] {seconds}s in Run state, answered {answered} AC "
              f"Echo Request(s)")
        return answered

    def _report(self, res):
        print(f"[{res.phase}] sent {msg_name(res.sent_mtype)} seq "
              f"{res.sent_seq}")
        for tag, before, after, note in res.subst_diff:
            print(f"    subst tag={tag:04x}({elem_name(tag)}): "
                  f"{before.hex()} -> {after.hex()} ({note})")
        if res.resp is None:
            print("    no reply within timeout")
        else:
            print(f"    reply {msg_name(res.resp.msg_type)} seq "
                  f"{res.resp.seq} ({len(res.resp_wire)}B)")
            for tag, data in res.resp.elems:
                print(f"      {elem_name(tag)} (0x{tag:04x}) len {len(data)} "
                      f"{data.hex()[:64]}")
        for d in res.diffs:
            print(f"    diff: {d}")

    def _append_export(self, path, res):
        rows = []
        if os.path.exists(path):
            with open(path) as fh:
                rows = json.load(fh)
        rows.append({
            "phase": res.phase,
            "sent_mtype": res.sent_mtype,
            "sent_seq": res.sent_seq,
            "resp_wire": res.resp_wire.hex() if res.resp_wire else None,
        })
        with open(path, "w") as fh:
            json.dump(rows, fh, indent=2)
        print(f"transcript updated in {path}")

    def close(self):
        self.transports.close()
