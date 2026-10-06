"""UDP DNS proxy that feeds resolved allowlist IPs into nftables sets."""

from __future__ import annotations

import logging
import re
import socket
import struct
import subprocess
import threading
from collections.abc import Callable, Sequence

log = logging.getLogger(__name__)

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

DNS_PROXY_PORT = 15353


def is_valid_hostname_pattern(value: str) -> bool:
    text = value.strip().lower().rstrip(".")
    if not text or len(text) > 253:
        return False
    if text.startswith("*."):
        text = text[2:]
        if not text or "*" in text:
            return False
    elif "*" in text:
        return False
    labels = text.split(".")
    return not any(not label or not _LABEL_RE.match(label) for label in labels)


def host_matches(qname: str, patterns: Sequence[str]) -> bool:
    name = qname.lower().rstrip(".")
    for pattern in patterns:
        pat = pattern.lower().rstrip(".")
        if pat.startswith("*."):
            suffix = pat[1:]  # leading dot + domain
            if name.endswith(suffix) and len(name) > len(suffix):
                return True
        elif name == pat:
            return True
    return False


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    start = offset
    for _ in range(128):
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                start = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "ignore"))
        offset += length
    return ".".join(labels), (start if jumped else offset)


def _encode_name(name: str) -> bytes:
    parts = [p for p in name.rstrip(".").split(".") if p]
    out = bytearray()
    for part in parts:
        raw = part.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def extract_query(data: bytes) -> tuple[str, int] | None:
    if len(data) < 12:
        return None
    _, flags, qdcount, *_ = struct.unpack("!HHHHHH", data[:12])
    if qdcount < 1:
        return None
    # Query bit must be 0 for standard queries (QR=0).
    if flags & 0x8000:
        return None
    name, offset = _decode_name(data, 12)
    if offset + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
    return name, qtype


def extract_answer_ips(data: bytes) -> tuple[list[str], int]:
    """Return (ipv4/ipv6 texts, min TTL) from a DNS response."""
    if len(data) < 12:
        return [], 60
    _id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if not (flags & 0x8000):
        return [], 60
    offset = 12
    for _ in range(qdcount):
        _name, offset = _decode_name(data, offset)
        offset += 4
    ips: list[str] = []
    min_ttl = None
    total = ancount + nscount + arcount
    for _ in range(total):
        if offset >= len(data):
            break
        _name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:  # A
            ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        elif rtype == 28 and rdlen == 16:  # AAAA
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
            min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
    return ips, 60 if min_ttl is None else max(min_ttl, 5)


def nxdomain_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    header = bytearray(query[:12])
    # QR=1, RCODE=NXDOMAIN (3), copy id/opcode
    flags = struct.unpack("!H", header[2:4])[0]
    flags = (flags & 0x7900) | 0x8003
    header[2:4] = struct.pack("!H", flags)
    header[6:12] = b"\x00\x00\x00\x00\x00\x00"  # no answers
    # Include original question section.
    try:
        _name, offset = _decode_name(query, 12)
        question = query[12 : offset + 4]
    except ValueError:
        question = b""
    header[4:6] = struct.pack("!H", 1 if question else 0)
    return bytes(header) + question


def _recvexact(sock: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        piece = sock.recv(size - len(chunks))
        if not piece:
            return None
        chunks.extend(piece)
    return bytes(chunks)


def forward_query(query: bytes, upstreams: Sequence[str], timeout: float = 2.0) -> bytes | None:
    """Forward a DNS query to an upstream resolver.

    Uses DNS-over-TCP so upstream queries are not caught by the in-namespace
    nftables UDP/53 redirect that steers guest traffic to this proxy.
    """
    payload = struct.pack("!H", len(query)) + query
    for upstream in upstreams:
        try:
            with socket.create_connection((upstream, 53), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(payload)
                header = _recvexact(sock, 2)
                if header is None:
                    continue
                (length,) = struct.unpack("!H", header)
                if length == 0 or length > 65535:
                    continue
                data = _recvexact(sock, length)
                if data is not None:
                    return data
        except OSError as exc:
            log.debug("DNS upstream %s failed: %s", upstream, exc)
    return None


class DnsProxy:
    """Forward UDP DNS, NXDOMAIN denied names, and publish allowed A/AAAA to nft."""

    def __init__(
        self,
        *,
        upstreams: Sequence[str],
        allow_hosts: Sequence[str],
        deny_hosts: Sequence[str],
        add_allow_ip: Callable[[str, int], None],
        listen_host: str = "127.0.0.1",
        listen_port: int = DNS_PROXY_PORT,
    ):
        self.upstreams = list(upstreams)
        self.allow_hosts = list(allow_hosts)
        self.deny_hosts = list(deny_hosts)
        self.add_allow_ip = add_allow_ip
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.listen_host, self.listen_port))
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="buddelkiste-dns", daemon=True)
        self._thread.start()
        log.debug("DNS proxy listening on %s:%s", self.listen_host, self.listen_port)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                reply = self._handle(data)
                if reply:
                    self._sock.sendto(reply, addr)
            except Exception:
                log.exception("DNS proxy handler failed")

    def _handle(self, data: bytes) -> bytes | None:
        parsed = extract_query(data)
        if parsed is None:
            return None
        qname, qtype = parsed
        if self.deny_hosts and host_matches(qname, self.deny_hosts):
            return nxdomain_response(data)

        reply = forward_query(data, self.upstreams)
        if reply is None:
            return nxdomain_response(data)

        if self.allow_hosts and host_matches(qname, self.allow_hosts) and qtype in (1, 28, 255):
            ips, ttl = extract_answer_ips(reply)
            for ip in ips:
                try:
                    self.add_allow_ip(ip, ttl)
                except Exception:
                    log.exception("failed to allow resolved IP %s for %s", ip, qname)
        return reply


def nft_add_allow_ip(ip: str, ttl: int) -> None:
    """Add a resolved address to the dynamic allow set with timeout."""
    family = "allow4" if ":" not in ip else "allow6"
    # dyn sets use plain addresses (not interval).
    set_name = f"dyn_{family}"
    timeout = max(int(ttl), 5)
    cmd = [
        "nft",
        "add",
        "element",
        "inet",
        "buddelkiste",
        set_name,
        "{",
        f"{ip} timeout {timeout}s",
        "}",
    ]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        log.warning("nft add element failed: %s", proc.stderr.strip() or proc.stdout.strip())
