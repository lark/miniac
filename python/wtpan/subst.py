"""Runtime element substitution applied to replayed CAPWAP messages.

Copyright (c) 2026  Wang Jian

Replay re-sends WTP->AC messages captured from a real AX60 session, but
session-bound values (IP addresses, MACs) must be rewritten for the new
session so the target AC sees a coherent client. Only elements whose wire
form matches the RFC/H3C shape for the value are rewritten; anything else is
left untouched so unknown vendor elements survive verbatim.
"""

import ipaddress
from dataclasses import dataclass, field

from .ctrl import CtrlMsg
from .ctrl_names import MsgElemType


@dataclass
class Substitution:
    """Rewrite rules for a replay session.

    local_ip / ac_ip: dotted-quad strings; wtp_mac: 6-byte value or None to
    keep the dump MAC. `extra` maps element tag -> raw bytes override and has
    the highest priority.
    """

    local_ip: str = None
    ac_ip: str = None
    wtp_mac: bytes = None
    gateway: str = None
    extra: dict = field(default_factory=dict)

    def _ip4(self, value):
        return ipaddress.IPv4Address(value).packed

    def apply(self, msg):
        """Return (new_msg, diff) where diff is a list of (tag, before, after,
        note) for every rewritten element."""
        elems = []
        diff = []
        for tag, data in msg.elems:
            new_data = data
            note = None
            if tag in self.extra:
                new_data = self.extra[tag]
                note = "extra override"
            elif tag == MsgElemType.CAPWAP_LOCAL_IPV4_ADDR and self.local_ip:
                if len(data) == 4:
                    new_data = self._ip4(self.local_ip)
                    note = f"local ip {self.local_ip}"
            elif tag == MsgElemType.CAPWAP_CTRL_IPV4_ADDR and self.ac_ip:
                if len(data) == 4:
                    new_data = self._ip4(self.ac_ip)
                    note = f"ac ip {self.ac_ip}"
                elif len(data) == 6:  # H3C [4B IP][2B hint] entry
                    new_data = self._ip4(self.ac_ip) + data[4:6]
                    note = f"ac ip {self.ac_ip} (6B entry)"
            elif tag in (MsgElemType.CAPWAP_LOCAL_IPV6_ADDR,
                         MsgElemType.CAPWAP_CTRL_IPV6_ADDR):
                new_data = bytes(len(data))
                note = "ipv6 zeroed"
            elif tag == MsgElemType.WTP_STATIC_IP_ADDR_INFO:
                if len(data) == 12 and self.local_ip:
                    new_data = bytearray(data)
                    new_data[0:4] = self._ip4(self.local_ip)
                    if self.gateway:
                        new_data[8:12] = self._ip4(self.gateway)
                    new_data = bytes(new_data)
                    note = "static ip/gw patched"
            elif tag == MsgElemType.WTP_BOARD_DATA and self.wtp_mac is not None:
                if len(data) >= 6:
                    new_data = self.wtp_mac + data[6:]
                    note = "board mac patched"
            if new_data != data:
                diff.append((tag, bytes(data), bytes(new_data), note or "rewritten"))
                elems.append((tag, bytes(new_data)))
            else:
                elems.append((tag, bytes(data)))
        return CtrlMsg(msg_type=msg.msg_type, seq=msg.seq, elems=elems,
                       flags=msg.flags), diff
