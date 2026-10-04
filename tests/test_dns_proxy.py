from __future__ import annotations

import socket
import struct
import threading

from buddelkiste.dns_proxy import (
    extract_answer_ips,
    extract_query,
    forward_query,
    host_matches,
    is_valid_hostname_pattern,
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


def _response_with_a(name: str, ip: str, ttl: int = 120) -> bytes:
    import socket

    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    q = _encode_name(name) + struct.pack("!HH", 1, 1)
    # pointer to name at offset 12
    rr = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + socket.inet_aton(ip)
    return header + q + rr


def test_hostname_patterns() -> None:
    assert is_valid_hostname_pattern("api.github.com")
    assert is_valid_hostname_pattern("*.pypi.org")
    assert not is_valid_hostname_pattern("bad.*.com")
    assert not is_valid_hostname_pattern("-nope.com")


def test_host_matches() -> None:
    assert host_matches("api.github.com", ["api.github.com"])
    assert host_matches("files.pypi.org", ["*.pypi.org"])
    assert not host_matches("pypi.org", ["*.pypi.org"])
    assert not host_matches("evil.com", ["api.github.com"])


def test_extract_query_and_nxdomain() -> None:
    q = _query("example.com")
    assert extract_query(q) == ("example.com", 1)
    nx = nxdomain_response(q)
    assert extract_query(nx) is None  # QR bit set → not a query
    assert nx[2] & 0x80  # QR
    assert nx[3] & 0x0F == 3  # RCODE nxdomain


def test_extract_answer_ips() -> None:
    resp = _response_with_a("example.com", "93.184.216.34", ttl=90)
    ips, ttl = extract_answer_ips(resp)
    assert ips == ["93.184.216.34"]
    assert ttl == 90


def test_forward_query_uses_dns_over_tcp(monkeypatch) -> None:
    query = _query("example.com")
    response = _response_with_a("example.com", "93.184.216.34")
    errors: list[str] = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        def accept_once() -> None:
            conn, _addr = srv.accept()
            with conn:
                header = conn.recv(2)
                (length,) = struct.unpack("!H", header)
                body = b""
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        break
                    body += chunk
                if body != query:
                    errors.append(f"unexpected query: {body!r}")
                conn.sendall(struct.pack("!H", len(response)) + response)

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()

        real_connect = socket.create_connection

        def connect_to_test_port(address, timeout=None):
            host, _port = address
            assert _port == 53
            return real_connect((host, port), timeout)

        monkeypatch.setattr("buddelkiste.dns_proxy.socket.create_connection", connect_to_test_port)
        got = forward_query(query, ["127.0.0.1"])
        thread.join(timeout=2)

    assert not errors
    assert got == response
