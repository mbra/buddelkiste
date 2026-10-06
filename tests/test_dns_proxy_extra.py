from __future__ import annotations

import logging
import socket
import struct
from unittest.mock import MagicMock

import pytest

from buddelkiste import dns_proxy
from buddelkiste.dns_proxy import (
    DnsProxy,
    extract_answer_ips,
    extract_query,
    forward_query,
    nft_add_allow_ip,
    nxdomain_response,
)


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for part in name.split("."):
        raw = part.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _query(name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


def test_hostname_pattern_edge_cases() -> None:
    assert not dns_proxy.is_valid_hostname_pattern("")
    assert not dns_proxy.is_valid_hostname_pattern("a" * 254)
    assert not dns_proxy.is_valid_hostname_pattern("*.")
    assert not dns_proxy.is_valid_hostname_pattern("*.foo.*.bar")
    assert not dns_proxy.is_valid_hostname_pattern("foo*bar.com")
    assert dns_proxy.is_valid_hostname_pattern("*.ok.com")


def test_decode_name_pointer_and_errors() -> None:
    # name at 12, then pointer back to it
    data = bytearray(12) + _encode_name("example.com")
    ptr_offset = len(data)
    data.extend(struct.pack("!H", 0xC000 | 12))
    name, next_off = dns_proxy._decode_name(bytes(data), ptr_offset)
    assert name == "example.com"
    assert next_off == ptr_offset + 2

    # Second pointer after an initial jump (jumped already True).
    chained = bytearray(12) + _encode_name("a.b")
    first_ptr = len(chained)
    chained.extend(struct.pack("!H", 0xC000 | 12))
    second_ptr = len(chained)
    chained.extend(struct.pack("!H", 0xC000 | first_ptr))
    name2, next2 = dns_proxy._decode_name(bytes(chained), second_ptr)
    assert name2 == "a.b"
    assert next2 == second_ptr + 2

    # 128 labels without terminator exits the decode loop.
    endless = b"\x01x" * 128
    assert dns_proxy._decode_name(endless, 0)[0] == ".".join(["x"] * 128)

    with pytest.raises(ValueError, match="truncated DNS name"):
        dns_proxy._decode_name(b"\x03ab", 0)
    with pytest.raises(ValueError, match="truncated DNS pointer"):
        dns_proxy._decode_name(b"\xc0", 0)


def test_encode_name() -> None:
    assert dns_proxy._encode_name("a.b") == b"\x01a\x01b\x00"
    assert dns_proxy._encode_name("a.b.") == b"\x01a\x01b\x00"


def test_extract_query_rejects_malformed() -> None:
    assert extract_query(b"short") is None
    header = struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0)
    assert extract_query(header) is None
    # missing qtype/qclass after root name
    assert extract_query(struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x00") is None
    # QR bit set
    assert (
        extract_query(struct.pack("!HHHHHH", 1, 0x8000, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01")
        is None
    )


def test_extract_answer_ips_aaaa_min_ttl_and_errors() -> None:
    assert extract_answer_ips(b"short") == ([], 60)
    query = _query("example.com")
    assert extract_answer_ips(query) == ([], 60)

    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    q = _encode_name("example.com") + struct.pack("!HH", 1, 1)
    a = struct.pack("!HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton("1.2.3.4")
    aaaa = (
        struct.pack("!HHHIH", 0xC00C, 28, 1, 3, 16)
        + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    )
    ips, ttl = extract_answer_ips(header + q + a + aaaa)
    assert "1.2.3.4" in ips
    assert "2001:db8::1" in ips
    assert ttl == 5  # min(30, 3) floored at 5

    # truncated RR header
    truncated = header + q + a[:6]
    assert extract_answer_ips(truncated)[0] == []

    # Non-A/AAAA RR is skipped; loop continues to the following A.
    txt = struct.pack("!HHHIH", 0xC00C, 16, 1, 60, 5) + b"\x04skip"
    header2 = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    assert extract_answer_ips(header2 + q + txt + a)[0] == ["1.2.3.4"]

    # ancount claims more RRs than bytes remain
    header3 = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    assert extract_answer_ips(header3 + q + aaaa)[0] == ["2001:db8::1"]


def test_nxdomain_short_and_bad_question() -> None:
    assert nxdomain_response(b"x") == b""
    bad = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xff"
    nx = nxdomain_response(bad)
    assert nx[2] & 0x80
    assert struct.unpack("!H", nx[4:6])[0] == 0


def test_recvexact_and_forward_query_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.recv.side_effect = [b"ab", b""]
    assert dns_proxy._recvexact(sock, 4) is None

    calls = {"n": 0}

    class FakeConn:
        def __init__(self, mode: str):
            self.mode = mode
            self.sent = b""
            self._body_reads = 0

        def settimeout(self, _t):
            return None

        def sendall(self, data):
            self.sent = data

        def recv(self, n):
            if self.mode == "no-header":
                return b""
            if self.mode == "bad-length":
                return b"\x00\x00" if n == 2 else b""
            if self.mode == "short-body":
                if n == 2:
                    return b"\x00\x05"
                self._body_reads += 1
                return b"xx" if self._body_reads == 1 else b""
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def create_connection(address, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("down")
        if calls["n"] == 2:
            return FakeConn("no-header")
        if calls["n"] == 3:
            return FakeConn("bad-length")
        return FakeConn("short-body")

    monkeypatch.setattr(dns_proxy.socket, "create_connection", create_connection)
    assert forward_query(_query("example.com"), ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"]) is None


def test_dns_proxy_handle_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    allowed: list[tuple[str, int]] = []

    def add_ip(ip: str, ttl: int) -> None:
        if ip == "9.9.9.9":
            raise RuntimeError("nft down")
        allowed.append((ip, ttl))

    proxy = DnsProxy(
        upstreams=["1.1.1.1"],
        allow_hosts=["example.com"],
        deny_hosts=["evil.com"],
        add_allow_ip=add_ip,
    )

    assert proxy._handle(b"short") is None

    deny_q = _query("evil.com")
    deny_reply = proxy._handle(deny_q)
    assert deny_reply is not None
    assert deny_reply[3] & 0x0F == 3

    monkeypatch.setattr(dns_proxy, "forward_query", lambda *a, **k: None)
    fail_reply = proxy._handle(_query("example.com"))
    assert fail_reply is not None
    assert fail_reply[3] & 0x0F == 3

    response = bytearray(struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0))
    response.extend(_encode_name("example.com") + struct.pack("!HH", 1, 1))
    response.extend(struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("1.2.3.4"))
    response.extend(struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("9.9.9.9"))
    monkeypatch.setattr(dns_proxy, "forward_query", lambda *a, **k: bytes(response))
    got = proxy._handle(_query("example.com"))
    assert got == bytes(response)
    assert ("1.2.3.4", 60) in allowed

    # Allowed host list set, but query name is outside it — still forward.
    monkeypatch.setattr(dns_proxy, "forward_query", lambda *a, **k: b"fwd")
    assert proxy._handle(_query("other.com")) == b"fwd"

    # No allow list: skip nft allow path.
    bare = DnsProxy(
        upstreams=["1.1.1.1"],
        allow_hosts=[],
        deny_hosts=[],
        add_allow_ip=lambda *a: None,
    )
    monkeypatch.setattr(dns_proxy, "forward_query", lambda *a, **k: b"ok")
    assert bare._handle(_query("example.com")) == b"ok"


def test_dns_proxy_start_stop_and_serve(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.recvfrom.side_effect = [
        TimeoutError(),
        (b"dead", ("127.0.0.1", 1)),
        (b"nodata", ("127.0.0.1", 2)),
        OSError("closed"),
    ]
    sock.sendto = MagicMock()

    monkeypatch.setattr(dns_proxy.socket, "socket", lambda *a, **k: sock)

    proxy = DnsProxy(
        upstreams=["1.1.1.1"],
        allow_hosts=[],
        deny_hosts=[],
        add_allow_ip=lambda ip, ttl: None,
        listen_port=0,
    )
    replies = iter([b"reply", None])
    monkeypatch.setattr(proxy, "_handle", lambda data: next(replies))
    proxy.start()
    assert proxy._thread is not None
    proxy._thread.join(timeout=2)
    proxy.stop()
    sock.sendto.assert_called_once_with(b"reply", ("127.0.0.1", 1))
    sock.close.assert_called()

    # stop() with no thread/sock is a no-op
    idle = DnsProxy(
        upstreams=[],
        allow_hosts=[],
        deny_hosts=[],
        add_allow_ip=lambda *a: None,
    )
    idle.stop()

    # _serve exits via while-condition when stop is already set
    stopped = DnsProxy(
        upstreams=[],
        allow_hosts=[],
        deny_hosts=[],
        add_allow_ip=lambda *a: None,
    )
    stopped._sock = MagicMock()
    stopped._stop.set()
    stopped._serve()


def test_dns_proxy_serve_handler_exception(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    sock = MagicMock()
    sock.recvfrom.side_effect = [(b"x", ("127.0.0.1", 1)), OSError("done")]
    proxy = DnsProxy(
        upstreams=[],
        allow_hosts=[],
        deny_hosts=[],
        add_allow_ip=lambda *a: None,
    )
    proxy._sock = sock
    monkeypatch.setattr(proxy, "_handle", lambda data: (_ for _ in ()).throw(RuntimeError("boom")))
    with caplog.at_level(logging.ERROR):
        proxy._serve()
    assert "DNS proxy handler failed" in caplog.text


def test_nft_add_allow_ip(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, check=False, capture_output=True, text=True):
        calls.append(list(cmd))
        if "2001:db8::1" in " ".join(cmd):
            return MagicMock(returncode=1, stderr="nope", stdout="")
        return MagicMock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(dns_proxy.subprocess, "run", fake_run)
    nft_add_allow_ip("1.2.3.4", 2)
    assert calls[0][calls[0].index("buddelkiste") + 1] == "dyn_allow4"
    assert "1.2.3.4 timeout 5s" in calls[0]

    with caplog.at_level(logging.WARNING):
        nft_add_allow_ip("2001:db8::1", 30)
    assert "dyn_allow6" in calls[1]
    assert "nft add element failed" in caplog.text
