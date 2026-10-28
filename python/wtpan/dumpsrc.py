"""Dump sources: turn miniac logs / pcaps / -D dump files into an ordered
interaction script, then generate templates.py code constants from it.

Copyright (c) 2026  Wang Jian

Replay is phase-driven: for each protocol phase (discovery, join, config
status, echo, chan-util, ...) the client packet is *constructed* on demand
using the captured AX60 packet as the byte-level template, with runtime
elements (IPs, MAC, seq) rewritten for the new session. `gen-templates`
extracts one representative WTP->AC packet per message type into
`templates.py`; the tool never re-sends the whole dump.
"""

import importlib.util
import os
import re
import struct
from dataclasses import dataclass

from .ctrl import CtrlMsg
from .ctrl_names import elem_name, msg_name
from .frame import CtrlFrame

#: Direction labels: WTP->AC (what we send) vs AC->WTP (reference replies).
WTP_TO_AC = "WTP->AC"
AC_TO_WTP = "AC->WTP"

_RUST_ARRAY = re.compile(r"^\s*\[\s*(\d+(?:\s*,\s*\d+)*)\s*\]\s*$")
_HEX_LINE = re.compile(r"\[DBG\] ([a-z0-9-]+) (wire|app_data) \((\d+)B\): ([0-9a-fA-F]+)$")
_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)(Z|[+-]\d{2}:\d{2})?")
_ISO_TS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$")
_CTRL_PAYLOAD = re.compile(r"\[\?\] ctrl payload:")


@dataclass
class ScriptEntry:
    """One direction of the interaction: full wire bytes, session order."""

    direction: str  # WTP_TO_AC or AC_TO_WTP
    ts: int  # epoch microseconds
    payload: bytes  # full wire (base header included under H3C framing)
    opaque: bool = False  # not parseable as a control frame (e.g. DTLS)


def _iso_to_micros(s):
    """Epoch microseconds for an ISO 8601 stamp; a missing zone means UTC."""
    import datetime

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 1_000_000)


def _parse_ts(line):
    m = _TS.match(line)
    if not m:
        return 0
    return _iso_to_micros(m.group(1) + (m.group(2) or "Z"))


def parse_miniac_log(path, frm):
    """Parse a miniac log: `[?] ctrl payload:` Rust array lines (control
    payload, base header re-added) plus `[DBG] <x> app_data/wire (...B): hex`
    lines (full wire). Returns a list of ScriptEntry in file order."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    out = []
    with open(path, "r", errors="replace") as fh:
        lines = fh.readlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        ts = _parse_ts(line)
        if _CTRL_PAYLOAD.search(line):
            # Consume the Rust array on this or following lines.
            j = i + 1
            buf = ""
            while j < len(lines) and "]" not in buf:
                buf += lines[j].strip()
                j += 1
            m = _RUST_ARRAY.search(buf)
            if m:
                ctrl = bytes(int(x) for x in m.group(1).split(","))
                out.append(ScriptEntry(WTP_TO_AC, ts,
                                       frm.control_to_wire(ctrl)))
            i = j
            continue
        m = _HEX_LINE.search(line)
        if m:
            payload = bytes.fromhex(m.group(4))
            direction = AC_TO_WTP if m.group(2) == "wire" else WTP_TO_AC
            out.append(ScriptEntry(direction, ts, payload))
        i += 1
    return out


def parse_dumpfile(path, frm):
    """Parse miniac `-D` dump lines `RX|TX <ts> <hex>`. RX (WTP->AC) is
    what the tool sends; TX is the AC->WTP reference. `<ts>` is the host-local
    ISO 8601 stamp (with its UTC offset); integer epoch microseconds from older
    dumps are still accepted."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    out = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3 or parts[0] not in ("RX", "TX"):
                continue
            direction = WTP_TO_AC if parts[0] == "RX" else AC_TO_WTP
            try:
                if parts[1].isdigit():
                    ts = int(parts[1])
                elif _ISO_TS.match(parts[1]):
                    ts = _iso_to_micros(parts[1])
                else:
                    continue
                payload = bytes.fromhex(parts[2])
            except ValueError:
                continue
            out.append(ScriptEntry(direction, ts, payload))
    return out


def parse_pcap(path, frm):
    """Parse a classic pcap: strip Ethernet/802.1Q (linktype 1) or nothing
    (linktype 101 DLT_RAW, e.g. the capwap-mitm plaintext capture), then
    IPv4/UDP, and keep UDP payloads on port 5246. DTLS-encrypted payloads are
    marked opaque. Direction is derived from the UDP port."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    out = []
    with open(path, "rb") as fh:
        g = fh.read(24)
        if len(g) < 24:
            return out
        magic = struct.unpack("<I", g[:4])[0]
        if magic == 0xA1B2C3D4:
            little = True
        elif magic == 0xD4C3B2A1:
            little = False
        else:
            raise ValueError(f"{path}: not a classic pcap")
        linktype = struct.unpack("<I" if little else ">I", g[20:24])[0]
        if linktype not in (1, 101):
            return out
        while True:
            r = fh.read(16)
            if not r or len(r) < 16:
                break
            ts_s, ts_us, incl, _orig = struct.unpack(
                "<IIII" if little else ">IIII", r)
            pkt = fh.read(incl)
            if len(pkt) < incl:
                break
            udp = _udp_payload(pkt, linktype)
            if udp is None:
                continue
            sport, dport, payload = udp
            if dport == 5246:
                direction = WTP_TO_AC
            elif sport == 5246:
                direction = AC_TO_WTP
            else:
                continue
            if not payload:
                continue
            out.append(ScriptEntry(direction, ts_s * 1_000_000 + ts_us,
                                   payload, opaque=not _looks_plaintext(frm, payload)))
    return out


def _udp_payload(pkt, linktype=1):
    """Strip the link layer (Ethernet/802.1Q for linktype 1, nothing for
    linktype 101 DLT_RAW), then IPv4/UDP; return (sport, dport, payload) or
    None when not IPv4/UDP."""
    if linktype == 101:
        off = 0
    else:
        if len(pkt) < 14:
            return None
        off = 0
        ethertype = pkt[12] << 8 | pkt[13]
        if ethertype == 0x8100:  # 802.1Q
            if len(pkt) < 18:
                return None
            ethertype = pkt[16] << 8 | pkt[17]
            off = 18
        elif ethertype != 0x0800:
            return None
        else:
            off = 14
    if len(pkt) < off + 20:
        return None
    if (pkt[off] >> 4) != 4:  # IPv4
        return None
    ihl = (pkt[off] & 0x0F) * 4
    if pkt[off + 9] != 17:  # UDP
        return None
    uoff = off + ihl
    if len(pkt) < uoff + 8:
        return None
    sport, dport = struct.unpack(">HH", pkt[uoff:uoff + 4])
    ulen = struct.unpack(">H", pkt[uoff + 4:uoff + 6])[0]
    end = min(len(pkt), uoff + ulen)
    return sport, dport, pkt[uoff + 8:end]


def _looks_plaintext(frm, wire):
    """Plaintext CAPWAP control frames vs DTLS records: the framed variants
    (H3C/TP-Link) start with a base header (`xx 10 ...`); bare RFC control
    messages start with a 0x00 message type. DTLS records start with
    0x16/0x17/0x15."""
    if not wire:
        return False
    if frm.base_header():
        return len(wire) > 1 and wire[1] == 0x10
    return wire[0] == 0x00


def decode_or_none(frm, entry):
    """Decode a ScriptEntry into a CtrlMsg, or None when malformed/opaque."""
    try:
        frm = CtrlFrame(frm) if isinstance(frm, str) else frm
        return CtrlMsg.decode(frm, frm.wire_to_control(entry.payload))
    except ValueError:
        return None


def correlate(script, frm, window_us=5_000_000):
    """Pair each WTP->AC message with the AC->WTP reply that echoes its
    sequence number within the time window. Returns a list of
    (entry, resp_entry_or_None)."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    pairs = []
    for i, req in enumerate(script):
        if req.direction != WTP_TO_AC or req.opaque:
            pairs.append((req, None))
            continue
        msg = decode_or_none(frm, req)
        if msg is None:
            pairs.append((req, None))
            continue
        resp = None
        for j in range(i + 1, len(script)):
            other = script[j]
            if other.ts - req.ts > window_us:
                break
            if other.direction != AC_TO_WTP or other.opaque:
                continue
            other_msg = decode_or_none(frm, other)
            if other_msg is not None and other_msg.seq == msg.seq:
                resp = other
                break
        pairs.append((req, resp))
    return pairs


def _template_lines(frm, msg):
    lines = [f"    # {msg_name(msg.msg_type)} seq {msg.seq} (representative)"]
    for tag, data in msg.elems:
        lines.append(f"    #   {elem_name(tag)} (0x{tag:04x}) len {len(data)}")
    return lines


def _elem_literals(elems):
    """Render a decoded element list as `(tag, value-hex)` literal lines."""
    out = []
    for tag, data in elems:
        out.append(f"        (0x{tag:04x}, {data.hex()!r}),")
    return out


def to_code(script, frm, name, source):
    """Generate templates.py source from a script: one Template per WTP->AC
    message type (first occurrence, payload-deduplicated), carrying the
    reference reply for comparison. Each Template records the wire framing,
    the exact base header, the control header fields and the ordered typed
    elements, so the bytes can be rebuilt byte-for-byte and reviewed."""
    frm = CtrlFrame(frm) if isinstance(frm, str) else frm
    pairs = correlate(script, frm)
    templates = {}
    for req, resp in pairs:
        if req.direction != WTP_TO_AC or req.opaque:
            continue
        msg = decode_or_none(frm, req)
        if msg is None:
            continue
        if msg.msg_type in templates:
            continue
        templates[msg.msg_type] = (msg, req, resp)

    hdr = frm.base_header()
    lines = [
        f'"""Phase templates generated from: {source}',
        "",
        "Copyright (c) 2026  Wang Jian",
        "",
        'Generated by `python3 -m wtpan.cli gen-templates` - do not edit by hand.',
        "TEMPLATES holds one representative WTP->AC packet per message type,",
        "expressed as a carrier base header plus the RFC 5415 control header",
        "and an ordered list of typed elements, so both the framing and the",
        "element order/values stay explicit and are rebuilt byte-for-byte.",
        '"""',
        "",
        "#: Sequence-number width per framing variant. MsgElemLen is always",
        "#: self-inclusive (element bytes + 3) on these links.",
        '_SEQ_LEN = {"rfc": 1, "h3c": 4, "tplink": 1}',
        "",
        "_RESULT_CODE = 33",
        "",
        "",
        "class Template:",
        '    """One representative control message as typed elements."""',
        "",
        "    def __init__(self, name, frame, hdr, mtype, seq, flags, elems,",
        "                 reply=None):",
        "        self.name = name",
        "        self.frame = frame",
        "        self.hdr = hdr",
        "        self.mtype = mtype",
        "        self.seq = seq",
        "        self.flags = flags",
        "        self.elems = elems  # ordered [(element type, value hex)]",
        "        self.reply = reply  # Template or None",
        "",
        "    def _assemble(self, hdr, mtype, seq, flags, elems):",
        "        out = bytearray(bytes.fromhex(hdr))",
        '        out += mtype.to_bytes(4, "big")',
        '        out += seq.to_bytes(_SEQ_LEN[self.frame], "big")',
        "        body = 0",
        "        for tag, val in elems:",
        "            n = len(val) // 2",
        "            if tag == _RESULT_CODE and n == 1:",
        "                n = 4",
        "            body += 4 + n",
        '        out += (3 + body).to_bytes(2, "big")',
        "        out += bytes([flags])",
        "        for tag, val in elems:",
        '            out += tag.to_bytes(2, "big")',
        "            raw = bytes.fromhex(val)",
        "            if tag == _RESULT_CODE and len(raw) == 1:",
        '                out += (4).to_bytes(2, "big")',
        '                out += raw[0].to_bytes(4, "big")',
        "            else:",
        '                out += len(raw).to_bytes(2, "big")',
        "                out += raw",
        "        return bytes(out)",
        "",
        "    @property",
        "    def wire(self):",
        "        return self._assemble(self.hdr, self.mtype, self.seq,",
        "                              self.flags, self.elems)",
        "",
        "    @property",
        "    def resp_wire(self):",
        "        if self.reply is None:",
        "            return None",
        "        r = self.reply",
        "        return self._assemble(r.hdr, r.mtype, r.seq, r.flags, r.elems)",
        "",
        "",
        "TEMPLATES = {",
    ]
    for mtype in sorted(templates):
        msg, req, resp = templates[mtype]
        label = msg_name(msg.msg_type).lower().replace(" ", "-")
        lines.extend(_template_lines(frm, msg))
        lines.append(f"    {mtype}: Template(name={label!r}, frame={frm.name!r},")
        lines.append(f"        hdr={req.payload[:len(hdr)].hex()!r},")
        lines.append(f"        mtype={mtype}, seq={msg.seq}, flags={msg.flags},")
        lines.append("        elems=[")
        lines.extend(_elem_literals(msg.elems))
        lines.append("        ],")
        if resp is not None:
            rmsg = decode_or_none(frm, resp)
            rlabel = msg_name(rmsg.msg_type).lower().replace(" ", "-")
            lines.append("        reply=Template(")
            lines.append(f"            name={rlabel!r}, frame={frm.name!r},")
            lines.append(f"            hdr={resp.payload[:len(hdr)].hex()!r},")
            lines.append(f"            mtype={rmsg.msg_type}, seq={rmsg.seq},")
            lines.append(f"            flags={rmsg.flags}, elems=[")
            for lit in _elem_literals(rmsg.elems):
                lines.append("    " + lit)
            lines.append("            ]),")
        lines.append("    ),")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_templates(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def load_templates(path):
    """Import a generated templates.py; returns {mtype: Template}."""
    spec = importlib.util.spec_from_file_location("wtpan_templates", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return dict(mod.TEMPLATES)
