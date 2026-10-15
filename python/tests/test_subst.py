"""Substitution unit tests: runtime IP/MAC rewriting for replay.

Copyright (c) 2026  Wang Jian
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wtpan.ctrl import CtrlMsg
from wtpan.ctrl_names import MsgElemType as M
from wtpan.subst import Substitution


class TestSubst:
    def test_local_ipv4(self):
        msg = CtrlMsg(3, 1, [(M.CAPWAP_LOCAL_IPV4_ADDR,
                              bytes.fromhex("c0a80032"))])
        new, diff = Substitution(local_ip="127.0.0.1").apply(msg)
        assert new.one(M.CAPWAP_LOCAL_IPV4_ADDR) == bytes.fromhex("7f000001")
        assert len(diff) == 1
        assert diff[0][1] == bytes.fromhex("c0a80032")
        assert diff[0][2] == bytes.fromhex("7f000001")

    def test_ctrl_ipv4_6byte_entry(self):
        entry = bytes.fromhex("c0a800fe0002")  # [4B IP][2B hint]
        msg = CtrlMsg(3, 1, [(M.CAPWAP_CTRL_IPV4_ADDR, entry)])
        new, _ = Substitution(ac_ip="127.0.0.1").apply(msg)
        assert new.one(M.CAPWAP_CTRL_IPV4_ADDR) == bytes.fromhex("7f0000010002")

    def test_static_ip_info(self):
        info = bytes.fromhex("c0a8003200000000c0a80001")  # ip + gw
        msg = CtrlMsg(3, 1, [(M.WTP_STATIC_IP_ADDR_INFO, info)])
        new, diff = Substitution(local_ip="10.0.0.5",
                                 gateway="10.0.0.1").apply(msg)
        got = new.one(M.WTP_STATIC_IP_ADDR_INFO)
        assert got[:4] == bytes.fromhex("0a000005")
        assert got[8:12] == bytes.fromhex("0a000001")
        assert len(diff) == 1

    def test_board_data_mac(self):
        body = bytes.fromhex("c4c063efca25") + bytes(42)
        msg = CtrlMsg(3, 1, [(M.WTP_BOARD_DATA, body)])
        mac = bytes.fromhex("aabbccddeeff")
        new, _ = Substitution(wtp_mac=mac).apply(msg)
        assert new.one(M.WTP_BOARD_DATA)[:6] == mac
        assert new.one(M.WTP_BOARD_DATA)[6:] == body[6:]

    def test_extra_override_wins(self):
        msg = CtrlMsg(3, 1, [(M.CAPWAP_LOCAL_IPV4_ADDR,
                              bytes.fromhex("c0a80032"))])
        new, diff = Substitution(
            local_ip="127.0.0.1",
            extra={M.CAPWAP_LOCAL_IPV4_ADDR: bytes.fromhex("0a000002")},
        ).apply(msg)
        assert new.one(M.CAPWAP_LOCAL_IPV4_ADDR) == bytes.fromhex("0a000002")
        assert len(diff) == 1
        assert diff[0][3] == "extra override"

    def test_unknown_element_untouched(self):
        data = bytes.fromhex("aabbccdd")
        msg = CtrlMsg(5, 286, [(0x0418, data)])
        new, diff = Substitution(local_ip="127.0.0.1").apply(msg)
        assert new.one(0x0418) == data
        assert diff == []

    def test_no_subst_no_diff(self):
        msg = CtrlMsg(13, 590, [])
        new, diff = Substitution().apply(msg)
        assert new.elems == []
        assert diff == []
