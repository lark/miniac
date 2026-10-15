"""dumpsrc tests: log/pcap/dump parsing, correlation and template generation.

Copyright (c) 2026  Wang Jian
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wtpan import dumpsrc
from wtpan.ctrl import decode_wire
from wtpan.frame import CtrlFrame

#: Full-wire config-status request (mtype 5, seq 286) from templates.py.
CFG_REQ_WIRE = (
    "0010020000000000000000050000011e004f00000400054d792041430005000a0041"
    "435072696d6172790005000c0141435365636f6e64617279001f00020001001f0002"
    "01010024000200780030000f000000000000000000000000000000"
)

#: Join Request control payload (app_data[8..], H3C): mtype 3, seq 285,
#: one Location Data element "  Next to Fridge" (16 bytes).
JOIN_CTRL = [0, 0, 0, 3, 0, 0, 1, 29, 1, 147, 0, 0, 28, 0, 16,
             32, 32, 78, 101, 120, 116, 32, 116, 111, 32, 70,
             114, 105, 100, 103, 101]


class TestParseMiniacLog:
    def test_ctrl_payload_line(self):
        log = (
            "2026-09-30T18:22:01.757315Z DEBUG miniac: [?] ctrl payload:\n"
            + "[" + ", ".join(str(x) for x in JOIN_CTRL) + "]\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as fh:
            fh.write(log)
            path = fh.name
        try:
            script = dumpsrc.parse_miniac_log(path, "h3c")
        finally:
            os.unlink(path)
        assert len(script) == 1
        entry = script[0]
        assert entry.direction == dumpsrc.WTP_TO_AC
        # Full wire = base header + control payload.
        msg = decode_wire(CtrlFrame("h3c"), entry.payload)
        assert (msg.msg_type, msg.seq) == (3, 285)
        assert msg.one(28) == b"  Next to Fridge"

    def test_dbg_hex_lines(self):
        log = (
            "2026-09-30T18:22:01.765535Z  INFO miniac: "
            f"[DBG] cfg-status-req app_data (95B): {CFG_REQ_WIRE}\n"
            "2026-09-30T18:22:01.767371Z  INFO miniac: "
            "[DBG] cfg-status-resp wire (19B): 00100200000000000000000e0000"
            "0064000b000021000400000013\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as fh:
            fh.write(log)
            path = fh.name
        try:
            script = dumpsrc.parse_miniac_log(path, "h3c")
        finally:
            os.unlink(path)
        assert [e.direction for e in script] == [dumpsrc.WTP_TO_AC,
                                                 dumpsrc.AC_TO_WTP]
        req = decode_wire(CtrlFrame("h3c"), script[0].payload)
        resp = decode_wire(CtrlFrame("h3c"), script[1].payload)
        assert (req.msg_type, resp.msg_type) == (5, 14)


class TestParseDumpfile:
    def test_rx_tx_lines(self):
        hex1 = bytes.fromhex(CFG_REQ_WIRE)
        with tempfile.NamedTemporaryFile("w", suffix=".dump",
                                         delete=False) as fh:
            fh.write(f"RX 1000 {hex1.hex()}\n")
            fh.write("TX 2000 0010020000000000000000060000011e02b0\n")
            path = fh.name
        try:
            script = dumpsrc.parse_dumpfile(path, "h3c")
        finally:
            os.unlink(path)
        assert len(script) == 2
        assert script[0].direction == dumpsrc.WTP_TO_AC
        assert script[1].direction == dumpsrc.AC_TO_WTP
        assert script[0].payload == hex1


class TestCorrelateAndToCode:
    def test_correlate_pairs_by_seq(self):
        # WTP->AC config-status req (seq 286), an unrelated AC->WTP reply
        # (seq 100, does not echo), then the real reply (mtype 6, seq 286).
        script = [
            dumpsrc.ScriptEntry(dumpsrc.WTP_TO_AC, 1000,
                                bytes.fromhex(CFG_REQ_WIRE)),
            dumpsrc.ScriptEntry(
                dumpsrc.AC_TO_WTP, 2000,
                bytes.fromhex("00100200000000000000000e00000064000b00002100"
                              "0400000013")),  # echo resp, seq 100
            dumpsrc.ScriptEntry(
                dumpsrc.AC_TO_WTP, 3000,
                bytes.fromhex("0010020000000000000000060000011e0000"
                              "000000")),  # resp mtype 6 seq 286
        ]
        pairs = dumpsrc.correlate(script, "h3c")
        req, resp = pairs[0]
        assert resp is not None
        resp_msg = decode_wire(CtrlFrame("h3c"), resp.payload)
        assert resp_msg.msg_type == 6

    def test_to_code_roundtrip(self):
        script = [
            dumpsrc.ScriptEntry(dumpsrc.WTP_TO_AC, 1000,
                                bytes.fromhex(CFG_REQ_WIRE)),
            dumpsrc.ScriptEntry(
                dumpsrc.AC_TO_WTP, 2000,
                bytes.fromhex("0010020000000000000000060000011e0000"
                              "000000")),
        ]
        code = dumpsrc.to_code(script, "h3c", "test", "synthetic")
        assert "TEMPLATES = {" in code
        assert "resp_hex=" in code
        with tempfile.NamedTemporaryFile("w", suffix=".py",
                                         delete=False) as fh:
            path = fh.name
        try:
            dumpsrc.write_templates(path, code)
            templates = dumpsrc.load_templates(path)
        finally:
            os.unlink(path)
        assert 5 in templates
        tpl = templates[5]
        assert tpl.mtype == 5
        msg = decode_wire(CtrlFrame("h3c"), tpl.wire)
        assert msg.one(4) == b"My AC"
        assert tpl.resp_wire is not None
        assert decode_wire(CtrlFrame("h3c"), tpl.resp_wire).msg_type == 6


class TestParsePcap:
    def test_ethernet_ipv4_udp(self):
        # Build a classic little-endian pcap with one IPv4/UDP 5246 packet.
        eth = bytes.fromhex("00112233445566778899aabb0800")
        ip_total = 20 + 8 + len(b"\x00\x10\x02\x00")
        ip = bytes([0x45, 0x00]) + ip_total.to_bytes(2, "big")
        ip += bytes([0, 0, 0x40, 0x00])  # ident, flags+fragoff
        ip += bytes([0x40, 17, 0, 0])  # ttl, UDP, checksum
        ip += bytes([192, 168, 0, 50, 192, 168, 0, 254])
        udp_len = 8 + len(b"\x00\x10\x02\x00")
        udp = bytes([0x14, 0x7b]) + bytes([0x14, 0x7e])  # sport 5243 dport 5246
        udp += udp_len.to_bytes(2, "big") + bytes([0, 0])
        frame = eth + ip + udp + b"\x00\x10\x02\x00"
        gh = b"\xd4\xc3\xb2\xa1" + bytes(20)  # magic + zeros
        gh = gh[:20] + (1).to_bytes(4, "little")  # linktype Ethernet
        rec = (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
        rec += len(frame).to_bytes(4, "little") + len(frame).to_bytes(
            4, "little")
        with tempfile.NamedTemporaryFile("wb", suffix=".pcap",
                                         delete=False) as fh:
            fh.write(gh + rec + frame)
            path = fh.name
        try:
            script = dumpsrc.parse_pcap(path, "h3c")
        finally:
            os.unlink(path)
        assert len(script) == 1
        assert script[0].direction == dumpsrc.WTP_TO_AC
        assert script[0].opaque is False
        assert script[0].payload == b"\x00\x10\x02\x00"
