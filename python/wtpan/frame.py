"""CAPWAP control framing: RFC 5415, H3C AX60 and TP-Link wire layouts.

Copyright (c) 2026  Wang Jian

All forms share the RFC 5415 control header layout
  [Message Type 4B][Seq][MsgElemLen 2B][Flags 1B][elements]
where MsgElemLen is self-inclusive: it counts from the Sequence Number
field onward, i.e. elements + 3 (RFC 5415 4.5.1.3). RFC messages are bare,
with a 1-byte Seq and elements at byte 8. H3C AX60-style WTPs carry an
8-byte base header over the whole control session and widen Seq to 4 bytes,
with elements at byte 19. TP-Link WTPs (e.g. TL-AP1300GI) combine both: an
8-byte base header, a 1-byte Seq and elements at byte 16. All decode
functions here operate on the control payload that follows the 8-byte base
header (i.e. app_data[8..]) for the framed variants; `frame()` produces the
full wire bytes.
"""

from .ctrl_names import MsgElemType

#: Base header miniac echoes to the AX60: version/HLEN 0, control type,
#: Fragment ID 0 and 8-byte length. The AX60 parser addresses fields by
#: offset, so a fixed valid value is enough for responses.
BASE_HEADER = bytes([0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])

#: Base header a TP-Link WTP (TL-AP1300GI) puts on every control datagram;
#: captured verbatim from its Join Request/Configuration Status Request.
TPLINK_HEADER = bytes([0x01, 0x10, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00])


class CtrlFrame:
    """Vendor CAPWAP control framing (RFC, H3C AX60 or TP-Link)."""

    RFC = "rfc"
    H3C = "h3c"
    TPLINK = "tplink"

    def __init__(self, name):
        if name not in (self.RFC, self.H3C, self.TPLINK):
            raise ValueError(f"unknown frame {name!r}")
        self.name = name

    def __eq__(self, other):
        return isinstance(other, CtrlFrame) and other.name == self.name

    def __repr__(self):
        return f"CtrlFrame({self.name!r})"

    def base_header(self):
        """The 8-byte base header this variant prepends to every control
        datagram (empty for a bare RFC 5415 message)."""
        if self.name == self.H3C:
            return BASE_HEADER
        if self.name == self.TPLINK:
            return TPLINK_HEADER
        return b""

    def self_inclusive_elem_len(self):
        """MsgElemLen counts from the Sequence Number field onward, i.e. the
        element bytes plus the 3 trailing header bytes, for every variant."""
        return True

    def seq_len(self):
        """Width of the Seq field (1 byte RFC/TP-Link, 4 bytes H3C)."""
        return 4 if self.name == self.H3C else 1

    def elem_off(self):
        """Byte offset of the first element inside the control payload
        (content after the 8-byte base header): Message Type(4) + Seq +
        MsgElemLen(2) + Flags(1)."""
        return 7 + self.seq_len()

    def parse_hdr(self, buf):
        """Parse the control header from `buf`, the payload after the 8-byte
        base header. Returns (msg_type, seq, elem_len, flags)."""
        off = self.elem_off()
        if len(buf) < off:
            raise ValueError("control header too short")
        msg_type = int.from_bytes(buf[0:4], "big")
        s = self.seq_len()
        seq = int.from_bytes(buf[4:4 + s], "big")
        elem_len = int.from_bytes(buf[4 + s:6 + s], "big")
        flags = buf[6 + s]
        return msg_type, seq, elem_len, flags

    def decode_elems(self, buf, pos):
        """Decode t2l2 elements [Type:2 BE][Len:2 BE][value] from `buf` at
        `pos`; stops at end of buffer or on an overrunning element. Returns
        (elems, pos)."""
        elems = []
        n = len(buf)
        while pos + 4 <= n:
            tag = int.from_bytes(buf[pos:pos + 2], "big")
            length = int.from_bytes(buf[pos + 2:pos + 4], "big")
            pos += 4
            end = pos + length
            if end > n:
                break
            elems.append((tag, bytes(buf[pos:end])))
            pos = end
        return elems, pos

    def wire_elem_len(self, tag, data):
        """On-wire byte count of one element. The Result-Code element is a
        4-byte value on this wire (unlike the RFC 1-octet form), so a 1-byte
        value is widened before it is counted."""
        data_len = 4 if (tag == MsgElemType.RESULT_CODE and len(data) == 1) else len(data)
        return 4 + data_len

    def append_elems(self, out, elems):
        """Append elements in t2l2 framing, widening a 1-byte Result Code to
        the 4-byte on-wire form."""
        for tag, data in elems:
            out += tag.to_bytes(2, "big")
            if tag == MsgElemType.RESULT_CODE and len(data) == 1:
                out += (4).to_bytes(2, "big")
                out += data[0].to_bytes(4, "big")
            else:
                out += len(data).to_bytes(2, "big")
                out += data

    def frame(self, msg_type, seq, elems, flags=0):
        """Serialize a control message back to wire bytes (including the
        8-byte base header for the H3C/TP-Link variants) for transmission."""
        body_len = sum(self.wire_elem_len(t, d) for t, d in elems)
        out = bytearray()
        out += self.base_header()
        out += msg_type.to_bytes(4, "big")
        out += seq.to_bytes(self.seq_len(), "big")
        out += (3 + body_len).to_bytes(2, "big")
        out += bytes([flags])
        self.append_elems(out, elems)
        return bytes(out)

    def wire_to_control(self, wire):
        """Control payload (after the base header) from a full wire frame."""
        hdr = self.base_header()
        return bytes(wire[len(hdr):]) if hdr else bytes(wire)

    def control_to_wire(self, control):
        """Full wire bytes from a control payload (adds the base header)."""
        return self.base_header() + bytes(control)


def parse_hdr(frame, buf):
    """Module-level convenience: parse a header for a `CtrlFrame` name."""
    return CtrlFrame(frame).parse_hdr(buf)


def frame(frame, msg_type, seq, elems, flags=0):
    """Module-level convenience: build wire bytes for a `CtrlFrame` name."""
    return CtrlFrame(frame).frame(msg_type, seq, elems, flags)
