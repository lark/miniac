"""CtrlFrame unit tests: port of src/vendor/framing.rs test vectors.

Copyright (c) 2026  Wang Jian
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wtpan.ctrl import CtrlMsg
from wtpan.frame import BASE_HEADER, CtrlFrame

#: Confirmed AX60 JoinRequest control payload (= app_data[8..]): msg_type 3,
#: 4-byte seq 2, MsgElemLen self-inclusive, then elements (framing.rs JOIN).
JOIN = bytes([
    0x00, 0x00, 0x00, 0x03,  # Message Type: Join Request
    0x00, 0x00, 0x00, 0x02,  # Seq 4 bytes
    0x00, 0x19, 0x00,  # MsgElemLen 0x19 (elements+3), Flags
    0x00, 0x1c, 0x00, 0x15,  # element: LOCATION_DATA (28), len 21
    ord('N'), ord('e'), ord('x'), ord('t'), ord(' '), ord('t'), ord('o'),
    ord(' '), ord('F'), ord('r'), ord('i'), ord('d'), ord('g'), ord('e'),
    ord(' '), ord('x'), ord('x'), ord('x'), ord('x'), ord('x'), ord(' '),
])

KEEPALIVE = bytes([
    0x00, 0x00, 0x00, 0x0d,  # Message Type: Echo Request
    0x00, 0x00, 0x01, 0x77,  # Seq 375
    0x00, 0x03, 0x00,  # MsgElemLen self-inclusive 3, Flags
])

#: chan-util ack wire (control payload, no base header): mtype 146, seq 192.
ACK145 = bytes([0, 0, 0, 146, 0, 0, 0, 192, 0, 11, 0, 0, 33, 0, 4,
                0, 0, 0, 0])


class TestH3cJoin:
    def test_join_header_offsets(self):
        hdr = CtrlFrame("h3c").parse_hdr(JOIN)
        assert hdr == (3, 2, 0x19, 0)
        assert CtrlFrame("h3c").elem_off() == 11

    def test_join_decodes_location(self):
        msg = CtrlMsg.decode(CtrlFrame("h3c"), JOIN)
        assert msg.msg_type == 3
        assert msg.seq == 2
        assert len(msg.elems) == 1
        tag, data = msg.elems[0]
        assert tag == 28
        assert data == b"Next to Fridge xxxxx "


class TestH3cKeepalive:
    def test_zero_element_keepalive(self):
        hdr = CtrlFrame("h3c").parse_hdr(KEEPALIVE)
        assert hdr == (13, 375, 3, 0)
        msg = CtrlMsg.decode(CtrlFrame("h3c"), KEEPALIVE)
        assert msg.msg_type == 13
        assert msg.seq == 375
        assert msg.elems == []


class TestH3cFrameRoundtrip:
    def test_frame_roundtrip(self):
        msg = CtrlMsg(4, 2, [(1, bytes(4))])
        out = msg.encode(CtrlFrame("h3c"))
        assert out[:8] == BASE_HEADER
        assert out[8:12] == bytes([0, 0, 0, 4])
        assert out[12:16] == bytes([0, 0, 0, 2])
        # MsgElemLen self-inclusive: 3 + (4 + 4 element bytes).
        assert int.from_bytes(out[16:18], "big") == 11
        assert out[19:] == bytes([0, 1, 0, 4, 0, 0, 0, 0])
        back = CtrlMsg.decode(CtrlFrame("h3c"), out[8:])
        assert (back.msg_type, back.seq, len(back.elems)) == (4, 2, 1)

    def test_widens_result_code_to_4_bytes(self):
        msg = CtrlMsg(4, 2, [(33, b"\x00")])
        out = msg.encode(CtrlFrame("h3c"))
        # Elements start at byte 19: [tag 0x0021][len 4][4-byte value].
        assert out[19:29] == bytes([0, 0x21, 0, 4, 0, 0, 0, 0])
        back = CtrlMsg.decode(CtrlFrame("h3c"), out[8:])
        assert back.one(33) == b"\x00\x00\x00\x00"


class TestAck145:
    def test_decode_ack_wire(self):
        msg = CtrlMsg.decode(CtrlFrame("h3c"), ACK145)
        assert msg.msg_type == 146
        assert msg.seq == 192
        assert msg.one(33) == b"\x00\x00\x00\x00"

    def test_encode_ack_roundtrip(self):
        msg = CtrlMsg(146, 192, [(33, b"\x00\x00\x00\x00")])
        out = CtrlMsg.decode(CtrlFrame("h3c"),
                             msg.encode(CtrlFrame("h3c"))[8:])
        assert (out.msg_type, out.seq, out.one(33)) == (146, 192,
                                                        b"\x00\x00\x00\x00")


class TestRfc:
    def test_rfc_no_base_header(self):
        out = CtrlFrame("rfc").frame(1, 5, [(1, b"\x01\x02")])
        assert not out.startswith(BASE_HEADER)
        assert out[:4] == bytes([0, 0, 0, 1])
        assert out[4] == 5
        assert int.from_bytes(out[5:7], "big") == 6  # 4 + 2 element bytes
        assert out[7] == 0  # flags
        assert out[8:] == bytes([0, 1, 0, 2, 1, 2])

    def test_wire_to_control(self):
        frm = CtrlFrame("h3c")
        assert frm.wire_to_control(BASE_HEADER + b"\x01\x02") == b"\x01\x02"
        assert frm.control_to_wire(b"\x01\x02") == BASE_HEADER + b"\x01\x02"
        rfrm = CtrlFrame("rfc")
        assert rfrm.wire_to_control(b"\x01\x02") == b"\x01\x02"
        assert rfrm.control_to_wire(b"\x01\x02") == b"\x01\x02"
