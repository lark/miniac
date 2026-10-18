"""UDP transports: plaintext CAPWAP (discovery) and DTLS 1.2 client.

Copyright (c) 2026  Wang Jian

DTLS is provided by pyOpenSSL (tlslite-ng 0.8.2 ships no DTLS module). The
AX60 client certificate is a 1024-bit RSA key which OpenSSL 3.x rejects at the
default security level, so a package-local OPENSSL_CONF lowers it to SECLEVEL=0
before the OpenSSL library initializes.

The DTLS socket is non-blocking; handshake and I/O are driven with select()
and the OpenSSL WantRead/WantWrite errors so a slow or silent AC cannot hang
the tool.
"""

import os

_CFG = os.path.join(os.path.dirname(__file__), "openssl-seclevel0.cnf")
os.environ.setdefault("OPENSSL_CONF", _CFG)

import select  # noqa: E402
import socket  # noqa: E402
import time  # noqa: E402

from OpenSSL import SSL  # noqa: E402

#: Pin DTLS 1.2 (H3C/miniac speak DTLS 1.2, not RFC 5416's DTLS 1.0).
_DTLS12_OPTS = (SSL.OP_NO_SSLv2, SSL.OP_NO_SSLv3, SSL.OP_NO_TLSv1,
                SSL.OP_NO_TLSv1_1, SSL.OP_NO_TLSv1_3)

#: DTLS protocol version numbers. pyOpenSSL exposes only the TLS_* constants,
#: so the DTLS values (RFC 6347) are literal here. TP-Link AC100 speaks DTLS 1.0
#: (``"1.0"``); H3C/miniac use DTLS 1.2 (``"1.2"``, the default).
_DTLS_PROTO = {"1.0": 0xFEFF, "1.2": 0xFEFD}


def _wait_fd(fd, end, write=False):
    """select() until `fd` is ready or the deadline `end` passes."""
    remaining = end - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("timed out")
    rlist = [fd] if not write else []
    wlist = [fd] if write else []
    r, w, _ = select.select(rlist, wlist, [], remaining)
    if not ((rlist and r) or (wlist and w)):
        raise TimeoutError("timed out")


class UdpTransport:
    """Plaintext UDP transport (used for the pre-DTLS discovery exchange)."""

    def __init__(self, host, port, timeout=5.0):
        self.addr = (host, port)
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.addr)

    def send(self, payload):
        if self.sock is None:
            self.connect()
        self.sock.send(payload)

    def recv(self):
        if self.sock is None:
            self.connect()
        try:
            return self.sock.recv(65535)
        except socket.timeout:
            return None

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None


class DtlsClient:
    """DTLS 1.2 client for the post-discovery control channel.

    Every CAPWAP DTLS datagram carries the 4-byte CAPWAP DTLS Header
    `[1,0,0,0]` (RFC 5415 §4.1/§4.2; src/connection.rs). pyOpenSSL writes raw
    records straight to its socket, so the record stream is relayed through an
    AF_UNIX socketpair: OpenSSL talks to one end, this class forwards the
    other end over UDP, prefixing outbound records and stripping the header
    from inbound ones. This mirrors miniac's `CapwapDtls::feed`/`flush`.
    """

    #: CAPWAP DTLS Header prepended to every DTLS record datagram (RFC 5415).
    FRAME_MARKER = b"\x01\x00\x00\x00"

    def __init__(self, host, port, client_pem=None, ca=None, verify=False,
                 timeout=5.0, udp_sock=None, dtls_proto=None):
        self.addr = (host, port)
        self.timeout = timeout
        ctx = SSL.Context(SSL.DTLS_CLIENT_METHOD)
        # TP-Link AC100's GnuTLS server does not advertise RFC 5746 secure
        # renegotiation, which OpenSSL 3.x rejects by default ("unsafe legacy
        # renegotiation disabled"); re-enable it for these legacy peers.
        ctx.set_options(SSL.OP_LEGACY_SERVER_CONNECT)
        if dtls_proto is not None:
            # Force an exact DTLS version (TP-Link AC100 wants DTLS 1.0).
            version = _DTLS_PROTO[dtls_proto]
            ctx.set_min_proto_version(version)
            ctx.set_max_proto_version(version)
        else:
            for opt in _DTLS12_OPTS:
                ctx.set_options(opt)
        if client_pem:
            # AX60 client.pem bundles the certificate and the RSA private key.
            ctx.use_certificate_chain_file(client_pem)
            ctx.use_privatekey_file(client_pem)
        if verify and ca:
            ctx.load_verify_locations(ca)
            ctx.set_verify(SSL.VERIFY_PEER,
                           lambda conn, cert, errno, depth, ok: True)
        else:
            ctx.set_verify(SSL.VERIFY_NONE,
                           lambda conn, cert, errno, depth, ok: True)
        self.ctx = ctx
        self.conn = None
        #: The discovery UDP socket when the caller reuses it, so the DTLS
        #: session keeps the same source port (RFC 5415 requires the WTP to
        #: negotiate DTLS from the port it used for the discovery exchange).
        self.udp = udp_sock
        self.owns_udp = udp_sock is None
        self.ssl_sock = None
        self.relay = None

    def connect(self):
        # A connected UDP socket (DTLS needs a destination; without connect()
        # OpenSSL fails with EDESTADDRREQ). Reuse the caller-provided socket
        # (already connected) so the source port matches the discovery phase.
        if self.udp is None:
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.setblocking(False)
            self.udp.connect(self.addr)
        self.ssl_sock, self.relay = socket.socketpair(socket.AF_UNIX,
                                                      socket.SOCK_DGRAM)
        self.ssl_sock.setblocking(False)
        self.relay.setblocking(False)
        self.conn = SSL.Connection(self.ctx, self.ssl_sock)
        self.conn.set_connect_state()
        self._handshake()

    def _pump_out(self):
        """Forward whatever OpenSSL wrote from the relay to the AC, prefixed
        with the CAPWAP DTLS Header."""
        while True:
            try:
                rec = self.relay.recv(65535)
            except BlockingIOError:
                return
            if not rec:
                return
            self.udp.send(FRAME_MARKER + rec)

    def _wait_in(self, end):
        """Block until a UDP datagram arrives (or the deadline passes),
        strip the framing header and hand the record to OpenSSL."""
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for DTLS data")
        r, _, _ = select.select([self.udp.fileno()], [], [], remaining)
        if not r:
            raise TimeoutError("timed out waiting for DTLS data")
        try:
            data = self.udp.recv(65535)
        except (BlockingIOError, socket.timeout):
            return
        if data.startswith(FRAME_MARKER):
            data = data[len(FRAME_MARKER):]
        self.relay.send(data)

    def _handshake(self):
        end = time.monotonic() + self.timeout
        while True:
            try:
                self.conn.do_handshake()
                self._pump_out()
                return
            except SSL.WantReadError:
                self._pump_out()
                self._wait_in(end)
            except SSL.WantWriteError:
                self._pump_out()
                if time.monotonic() >= end:
                    raise TimeoutError("DTLS handshake timed out")

    def send(self, payload):
        if self.conn is None:
            self.connect()
        end = time.monotonic() + self.timeout
        while True:
            try:
                n = self.conn.send(payload)
                self._pump_out()
                return n
            except SSL.WantWriteError:
                self._pump_out()
                if time.monotonic() >= end:
                    raise TimeoutError("DTLS send timed out")
            except SSL.WantReadError:
                self._pump_out()
                self._wait_in(end)

    def recv(self):
        if self.conn is None:
            self.connect()
        end = time.monotonic() + self.timeout
        try:
            return self.conn.recv(65535)
        except SSL.WantReadError:
            try:
                self._wait_in(end)
                return self.conn.recv(65535)
            except (SSL.WantReadError, TimeoutError):
                return None
        except (SSL.SysCallError, socket.timeout):
            return None

    def close(self):
        if self.conn is not None:
            try:
                self.conn.shutdown()
            except Exception:
                pass
            self.conn.close()
            self.conn = None
        for sock in (self.ssl_sock, self.relay):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if self.owns_udp and self.udp is not None:
            try:
                self.udp.close()
            except OSError:
                pass
        self.ssl_sock = self.relay = self.udp = None


class Transports:
    """Auto-switching transport: plaintext for discovery, DTLS afterwards."""

    def __init__(self, host, port, dtls=True, client_pem=None, ca=None,
                 verify=False, timeout=5.0, dtls_proto=None):
        self.host = host
        self.port = port
        self.dtls = dtls
        self.client_pem = client_pem
        self.ca = ca
        self.verify = verify
        self.timeout = timeout
        self.dtls_proto = dtls_proto
        self.udp = None
        self.dt = None

    def send(self, payload, mtype):
        """Send `payload`; for discovery message types use plaintext, for
        everything else bring up DTLS first. The DTLS client reuses the
        discovery UDP socket so the source port stays the same (RFC 5415)."""
        is_disc = mtype in (1, 19)
        if is_disc:
            if self.udp is None:
                self.udp = UdpTransport(self.host, self.port, self.timeout)
                self.udp.connect()
            self.udp.send(payload)
        else:
            if self.dtls and self.dt is None:
                if self.udp is None:
                    self.udp = UdpTransport(self.host, self.port,
                                            self.timeout)
                    self.udp.connect()
                self.dt = DtlsClient(self.host, self.port, self.client_pem,
                                     self.ca, self.verify, self.timeout,
                                     udp_sock=self.udp.sock,
                                     dtls_proto=self.dtls_proto)
                self.dt.connect()
            if self.dt is not None:
                self.dt.send(payload)
            else:
                if self.udp is None:
                    self.udp = UdpTransport(self.host, self.port,
                                            self.timeout)
                    self.udp.connect()
                self.udp.send(payload)

    def recv(self):
        """Receive one response; plaintext during discovery, DTLS otherwise.
        Returns None on timeout."""
        if self.dt is not None:
            return self.dt.recv()
        if self.udp is not None:
            return self.udp.recv()
        return None

    def close(self):
        if self.udp is not None:
            self.udp.close()
        if self.dt is not None:
            self.dt.close()
