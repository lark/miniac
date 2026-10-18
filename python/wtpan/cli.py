"""Command line interface for wtpan.

Copyright (c) 2026  Wang Jian

Subcommands:
  gen-templates  convert a dump (miniac log / pcap / -D file) into
                 templates.py (one representative client packet per phase)
  parse-dump     summarize a dump: messages, elements, reply pairing
  discover       send a Discovery Request (plaintext), print the reply
  join           DTLS handshake, send a Join Request, print the reply
  config-status  send a Configuration Status Request, print the reply
  echo           send an Echo Request, print the reply
  chan-util      send the H3C channel utilization report, print the reply
  send           send an arbitrary message type (--mtype N)
  session        full flow: discovery -> DTLS -> join -> config status
                 (--run continues into Run state: change-state -> echo ->
                 chan-util; --hold N stays connected auto-answering AC Echo
                 Requests)

The client packet for each phase is built on demand from the AX60 template
(runtime elements rewritten), then sent to the target AC.
"""

import argparse
import os
import sys

from . import __version__
from .ctrl_names import elem_name, msg_name
from .dumpsrc import (correlate, decode_or_none, load_templates,
                      parse_dumpfile, parse_miniac_log, parse_pcap, to_code,
                      write_templates)
from .frame import CtrlFrame
from .subst import Substitution
from .wtp import Session

_PKG = os.path.dirname(os.path.abspath(__file__))
#: Default template file per framing variant: the H3C templates carry the
#: AX60/miniac session, the TP-Link ones the real TL-AP1300GI plaintext.
_H3C_TEMPLATES = os.path.join(_PKG, "templates.py")
_DEFAULT_TEMPLATES = {
    "rfc": _H3C_TEMPLATES,
    "h3c": _H3C_TEMPLATES,
    "tplink": os.path.join(_PKG, "tplink_templates.py"),
}
_CAPWAP_CERTS = os.path.expanduser(
    "~/firmware/h3c-mini-ax60/extract/squashfs-root/etc/capwap")
_DEFAULT_TLS_CLIENT = os.path.join(_CAPWAP_CERTS, "client.pem")
_DEFAULT_TLS_CA = os.path.join(_CAPWAP_CERTS, "root.pem")


def _srcs(value):
    srcs = []
    for part in value:
        srcs.extend(p for p in part.split(",") if p)
    return srcs


def _guess_src_type(path):
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return "pcap"
    if head[:2] in (b"RX", b"TX"):
        return "dumpfile"
    return "miniac-log"


def _parse_script(srcs, src_type, frm):
    script = []
    for path in srcs:
        st = src_type if src_type != "auto" else _guess_src_type(path)
        if st == "pcap":
            script += parse_pcap(path, frm)
        elif st == "dumpfile":
            script += parse_dumpfile(path, frm)
        else:
            script += parse_miniac_log(path, frm)
    script.sort(key=lambda e: e.ts)
    return script


def cmd_gen_templates(args):
    frm = CtrlFrame(args.frame)
    srcs = _srcs(args.src)
    if not srcs:
        sys.exit("gen-templates: --src is required")
    script = _parse_script(srcs, args.src_type, frm)
    plain = [e for e in script if not e.opaque]
    if not plain:
        sys.exit(f"no parseable control frames found in {srcs}")
    text = to_code(script, frm, args.name or os.path.basename(srcs[0]),
                   ", ".join(srcs))
    out = args.out or _DEFAULT_TEMPLATES[args.frame]
    write_templates(out, text)
    print(f"wrote {len(text.splitlines())} lines to {out}")


def cmd_parse_dump(args):
    frm = CtrlFrame(args.frame)
    script = _parse_script(_srcs(args.src), args.src_type, frm)
    for i, e in enumerate(script):
        tag = f"[{i:3d}] {e.direction:6s} t={e.ts}"
        if e.opaque:
            print(f"{tag} opaque {len(e.payload)}B")
            continue
        msg = decode_or_none(frm, e)
        if msg is None:
            print(f"{tag} undecodable ({len(e.payload)}B)")
            continue
        print(f"{tag} {msg_name(msg.msg_type)} seq {msg.seq} "
              f"({len(e.payload)}B)")
        for t, d in msg.elems:
            print(f"         {elem_name(t)} (0x{t:04x}) len {len(d)} "
                  f"{d.hex()[:48]}")
    print("== reply pairing ==")
    for req, resp in correlate(script, frm):
        if req.direction != "WTP->AC" or req.opaque:
            continue
        rmsg = decode_or_none(frm, req)
        if rmsg is None:
            continue
        if resp is not None:
            amsg = decode_or_none(frm, resp)
            print(f"req seq {rmsg.seq} -> "
                  f"{msg_name(amsg.msg_type) if amsg else '?'} seq "
                  f"{amsg.seq if amsg else '?'}")
        else:
            print(f"req seq {rmsg.seq} -> (no reply)")


def _parse_sub(pairs):
    extra = {}
    for item in pairs:
        tag_s, _, val_s = item.partition("=")
        extra[int(tag_s, 0)] = bytes.fromhex(val_s)
    return extra


def _load_templates(args):
    path = args.templates or _DEFAULT_TEMPLATES.get(args.frame,
                                                    _H3C_TEMPLATES)
    if os.path.exists(path):
        return load_templates(path)
    return {}


def _make_session(args):
    frm = CtrlFrame(args.frame)
    subst = Substitution(local_ip=args.local_ip, ac_ip=args.ac_ip,
                         wtp_mac=bytes.fromhex(args.wtp_mac) if args.wtp_mac
                         else None, extra=_parse_sub(args.sub))
    client_pem = args.tls_client if args.tls_client and \
        os.path.exists(args.tls_client) else None
    ca = args.tls_ca if args.tls_ca and os.path.exists(args.tls_ca) else None
    host, _, port_s = args.target.partition(":")
    port = int(port_s or 5246)
    return Session(_load_templates(args), frm=frm, subst=subst,
                   target=(host, port), dtls=args.dtls in ("auto", "on"),
                   client_pem=client_pem, ca=ca, verify=args.tls_verify,
                   timeout=args.timeout, keep_seq=args.keep_seq,
                   seq_start=args.seq_start,
                   require_discovery=getattr(args, "require_discovery",
                                             False),
                   trace=args.trace, dtls_proto=args.dtls_version)


def cmd_phase(args):
    sess = _make_session(args)
    try:
        if args.cmd == "discover":
            sess.do_discovery(out=args.out)
        elif args.cmd == "join":
            sess.do_join(out=args.out)
        elif args.cmd == "config-status":
            sess.do_config_status(out=args.out)
        elif args.cmd == "echo":
            sess.do_echo(out=args.out)
        elif args.cmd == "chan-util":
            sess.do_chan_util(out=args.out)
        elif args.cmd == "send":
            sess.send(args.mtype, fallback=args.build, phase=f"send-{args.mtype}",
                      out=args.out)
        elif args.cmd == "session":
            sess.session(out=args.out, run=args.run, hold=args.hold)
    finally:
        sess.close()


def build_parser():
    p = argparse.ArgumentParser(prog="wtpan", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-templates", help="dump -> templates.py")
    g.add_argument("--src", action="append", required=True,
                   help="dump source (repeatable; comma-separated ok)")
    g.add_argument("--src-type", choices=["auto", "miniac-log", "pcap",
                                          "dumpfile"], default="auto")
    g.add_argument("--frame", choices=["rfc", "h3c", "tplink"], default="h3c")
    g.add_argument("--out", default=None,
                   help="output templates.py path (default: the built-in "
                        "templates file for --frame)")
    g.add_argument("--name", help="templates.py docstring source name")

    d = sub.add_parser("parse-dump", help="summarize a dump")
    d.add_argument("--src", action="append", required=True,
                   help="dump source (repeatable; comma-separated ok)")
    d.add_argument("--src-type", choices=["auto", "miniac-log", "pcap",
                                          "dumpfile"], default="auto")
    d.add_argument("--frame", choices=["rfc", "h3c", "tplink"], default="h3c")

    for name in ("discover", "join", "config-status", "echo", "chan-util",
                 "session", "send"):
        pp = sub.add_parser(name, help=f"run the {name} phase")
        _add_session_args(pp)
        if name == "send":
            pp.add_argument("--mtype", type=int, required=True,
                            help="message type to send")
            pp.add_argument("--build", choices=["discovery", "join",
                                                "config-status"],
                            help="fallback builder when no template exists")
        if name == "session":
            pp.add_argument("--run", action="store_true",
                            help="continue into the Run state: change-state "
                                 "event -> echo -> chan-util")
            pp.add_argument("--hold", type=float, default=0.0,
                            help="stay in Run state N seconds after the "
                                 "phases, auto-answering AC Echo Requests "
                                 "(survives miniac's 30s keep-alive)")
            pp.add_argument("--require-discovery", action="store_true",
                            help="stop after the discovery phase unless the "
                                 "AC replied with a Discovery Response "
                                 "(RFC 5415 discovery-first gate)")
    return p


def _add_session_args(pp):
    pp.add_argument("--templates", default=None,
                    help="templates.py path (default: the built-in templates "
                         "file for --frame)")
    pp.add_argument("--target", default="127.0.0.1:5246",
                    help="AC address host:port (default %(default)s)")
    pp.add_argument("--frame", choices=["rfc", "h3c", "tplink"], default="h3c")
    pp.add_argument("--local-ip", help="WTP-side IP for runtime elements")
    pp.add_argument("--ac-ip", help="AC control IP for tag 10 elements")
    pp.add_argument("--wtp-mac", metavar="HEX",
                    help="6-byte WTP MAC (default: keep dump value)")
    pp.add_argument("--sub", action="append", default=[], metavar="TAG=HEX",
                    help="override an element verbatim (repeatable)")
    pp.add_argument("--keep-seq", action="store_true",
                    help="reuse the template sequence number")
    pp.add_argument("--seq-start", type=int, default=1,
                    help="first sequence number when re-sequencing")
    pp.add_argument("--dtls", choices=["auto", "on", "off"], default="auto")
    pp.add_argument("--dtls-version", choices=["1.0", "1.2"], default=None,
                    help="force an exact DTLS version (TP-Link AC100 wants "
                         "1.0); default is the H3C/miniac DTLS 1.2 path")
    pp.add_argument("--tls-client", default=_DEFAULT_TLS_CLIENT,
                    help="client cert+key PEM (default: AX60 client.pem)")
    pp.add_argument("--tls-ca", default=_DEFAULT_TLS_CA,
                    help="CA bundle to verify the AC (default: AX60 root.pem)")
    pp.add_argument("--tls-verify", action="store_true",
                    help="verify the AC certificate against --tls-ca")
    pp.add_argument("--timeout", type=float, default=5.0,
                    help="reply wait in seconds (default %(default)s)")
    pp.add_argument("--trace", default=None,
                    help="append every datagram to this file in miniac's -D "
                         "dump convention (RX = WTP->AC, TX = AC->WTP)")
    pp.add_argument("--out", help="append the reply to a JSON transcript")


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "gen-templates":
        cmd_gen_templates(args)
    elif args.cmd == "parse-dump":
        cmd_parse_dump(args)
    else:
        cmd_phase(args)


if __name__ == "__main__":
    main()
