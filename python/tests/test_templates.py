"""templates.py loading tests against the checked-in generated file.

Copyright (c) 2026  Wang Jian
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wtpan import dumpsrc
from wtpan.ctrl import decode_wire
from wtpan.frame import CtrlFrame

TPL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "wtpan", "templates.py")


class TestTemplates:
    def setup_method(self):
        self.templates = dumpsrc.load_templates(TPL)

    def test_message_types(self):
        assert set(self.templates) == {3, 5, 11, 13, 14, 145}

    def test_join(self):
        tpl = self.templates[3]
        msg = decode_wire(CtrlFrame("h3c"), tpl.wire)
        assert (msg.msg_type, msg.seq) == (3, 285)
        assert msg.one(28) == b"  Next to Fridge"
        assert msg.one(45) == b"SWBA1B0"

    def test_config_status_req(self):
        tpl = self.templates[5]
        msg = decode_wire(CtrlFrame("h3c"), tpl.wire)
        assert (msg.msg_type, msg.seq) == (5, 286)
        assert msg.one(4) == b"My AC"
        assert len(tpl.wire) == 95
        # Reference reply is the Configuration Status Response.
        assert tpl.resp_wire is not None
        resp = decode_wire(CtrlFrame("h3c"), tpl.resp_wire)
        assert resp.msg_type == 6
        assert resp.one(0xFDE8) is not None

    def test_echo_request_keepalive(self):
        tpl = self.templates[13]
        msg = decode_wire(CtrlFrame("h3c"), tpl.wire)
        assert (msg.msg_type, msg.seq) == (13, 590)
        assert msg.elems == []  # 19B zero-element keepalive

    def test_chan_util(self):
        tpl = self.templates[145]
        msg = decode_wire(CtrlFrame("h3c"), tpl.wire)
        assert (msg.msg_type, msg.seq) == (145, 288)
        util = msg.one(0xFE20)
        assert util is not None and len(util) == 8
