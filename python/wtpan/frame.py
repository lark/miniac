"""CAPWAP control framing: RFC 5415 and H3C AX60 wire layouts.

Copyright (c) 2026  Wang Jian

RFC 5415 control messages are
  [base header 8B][Message Type 4B][Seq 1B][MsgElemLen 2B][Flags 1B][elements]
with elements at byte 16 of the wire. H3C AX60-style WTPs use the same shape
for the whole control session (not just discovery) but widen Seq to 4 bytes
and make MsgElemLen self-inclusive:
  [base header 8B][Message Type 4B][Seq 4B][MsgElemLen 2B][Flags 1B][elements]
with elements at byte 19 and MsgElemLen = elements + 3. All decode functions
here operate on the control payload that follows the 8-byte base header
(i.e. app_data[8..]); `frame()` produces the full wire bytes.
"""

from .ctrl_names import MsgElemType

#: Base header miniac echoes to the AX60: version/HLEN 0, control type,
#: Fragment ID 0 and 8-byte length. The AX60 parser addresses fields by
#: offset, so a fixed valid value is enough for responses.
BASE_HEADER = bytes([0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])


class CtrlFrame:
    """Vendor CAPWAP control framing (RFC or H3C AX60)."""

    RFC = "rfc"
    H3C = "h3c"

    def __init__(self, name):
        if name not in (self.RFC, self.H3C):
            raise ValueError(f"unknown frame {name!r}")
        self.name = name

    def __eq__(self, other):
        return isinstance(other, CtrlFrame) and other.name == self.name

    def __repr__(self):
        return f"CtrlFrame({self.name!r})"

    def seq_len(self):
        """Width of the Seq field (1 byte RFC, 4 bytes H3C)."""
        return 1 if self.name == self.RFC else 4

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
        if self.name == self.RFC:
            seq = buf[4]
        else:
            seq = int.from_bytes(buf[4:8], "big")
        s = self.seq_len()
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
        """On-wire byte count of one element. The AX60 Result-Code element is
        a 4-byte value (unlike the RFC 1-octet form), so the length must
        account for that widening."""
        data_len = 4 if (tag == MsgElemType.RESULT_CODE and len(data) == 1) else len(data)
        return 4 + data_len

    def append_elems(self, out, elems):
        """Append elements in t2l2 framing, widening the Result Code element
        under H3C framing."""
        h3c = self.name == self.H3C
        for tag, data in elems:
            out += tag.to_bytes(2, "big")
            if h3c and tag == MsgElemType.RESULT_CODE and len(data) == 1:
                out += (4).to_bytes(2, "big")
                out += data[0].to_bytes(4, "big")
            else:
                out += len(data).to_bytes(2, "big")
                out += data

    def frame(self, msg_type, seq, elems, flags=0):
        """Serialize a control message back to wire bytes (including the
        8-byte base header under H3C framing) for transmission."""
        if self.name == self.RFC:
            body_len = sum(4 + len(d) for _, d in elems)
            out = bytearray()
            out += msg_type.to_bytes(4, "big")
            out += bytes([seq & 0xFF])
            out += body_len.to_bytes(2, "big")
            out += bytes([flags])
            self.append_elems(out, elems)
            return bytes(out)
        body_len = sum(self.wire_elem_len(t, d) for t, d in elems)
        out = bytearray()
        out += BASE_HEADER
        out += msg_type.to_bytes(4, "big")
        out += seq.to_bytes(4, "big")
        out += (3 + body_len).to_bytes(2, "big")
        out += bytes([flags])
        self.append_elems(out, elems)
        return bytes(out)

    def wire_to_control(self, wire):
        """Control payload (after the base header) from a full wire frame."""
        return bytes(wire[8:]) if self.name == self.H3C else bytes(wire)

    def control_to_wire(self, control):
        """Full wire bytes from a control payload (adds the base header)."""
        if self.name == self.H3C:
            return BASE_HEADER + bytes(control)
        return bytes(control)


def parse_hdr(frame, buf):
    """Module-level convenience: parse a header for a `CtrlFrame` name."""
    return CtrlFrame(frame).parse_hdr(buf)


def frame(frame, msg_type, seq, elems, flags=0):
    """Module-level convenience: build wire bytes for a `CtrlFrame` name."""
    return CtrlFrame(frame).frame(msg_type, seq, elems, flags)
