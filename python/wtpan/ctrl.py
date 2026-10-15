"""CAPWAP control message decode/encode over a vendor CtrlFrame.

Copyright (c) 2026  Wang Jian
"""

from dataclasses import dataclass, field

from .ctrl_names import elem_name, msg_name
from .frame import CtrlFrame


@dataclass
class CtrlMsg:
    """A parsed control message. `seq` is the message sequence number, `elems`
    is a list of (tag, data-bytes) pairs in wire order."""

    msg_type: int
    seq: int
    elems: list = field(default_factory=list)
    flags: int = 0

    @staticmethod
    def decode(frm, buf):
        """Decode from a control payload (the bytes after the 8-byte base
        header). Raises ValueError on a malformed header."""
        frm = CtrlFrame(frm) if isinstance(frm, str) else frm
        msg_type, seq, _elem_len, flags = frm.parse_hdr(buf)
        elems, _ = frm.decode_elems(buf, frm.elem_off())
        return CtrlMsg(msg_type=msg_type, seq=seq, elems=elems, flags=flags)

    def encode(self, frm):
        """Serialize back to full wire bytes."""
        frm = CtrlFrame(frm) if isinstance(frm, str) else frm
        return frm.frame(self.msg_type, self.seq, self.elems, self.flags)

    def find(self, tag):
        """All element values with the given tag."""
        return [d for t, d in self.elems if t == tag]

    def one(self, tag, default=None):
        """First element value with the given tag, or `default`."""
        vals = self.find(tag)
        return vals[0] if vals else default

    def summary(self):
        parts = [f"mtype={self.msg_type}({msg_name(self.msg_type)})",
                 f"seq={self.seq}"]
        for tag, data in self.elems:
            parts.append(f"  tag={tag:04x}({elem_name(tag)}) len={len(data)}"
                         f" val={data.hex()}")
        return "\n".join(parts)


def decode_wire(frm, wire):
    """Decode a full wire frame (with base header under H3C framing)."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    return CtrlMsg.decode(frm, frm.wire_to_control(wire))
