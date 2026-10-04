"""Nested-safe integration: exercise our nft/DNS helpers against real tools."""

from __future__ import annotations

import socket
import struct
import subprocess
import sys
import textwrap

import pytest

from tests.probes import can_nested_nft, has_outbound_network


pytestmark = pytest.mark.integration


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for part in name.split("."):
        raw = part.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _dns_query(name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


@pytest.mark.requires_nested_net
def test_apply_nft_and_dyn_allow_via_our_helpers() -> None:
    """Install rules + dyn allow through buddelkiste APIs (not raw nft CLI)."""
    if not can_nested_nft():
        pytest.skip("nft in nested netns not available")

    script = textwrap.dedent(
        """
        from buddelkiste.dns_proxy import nft_add_allow_ip
        from buddelkiste.network import NetworkConfig, apply_nft_ruleset, build_nft_ruleset
        import subprocess

        rules = build_nft_ruleset(
            NetworkConfig(
                mode="filter",
                policy="deny",
                allow=["1.1.1.1/32"],
                deny=["10.0.0.0/8"],
            ),
            dns_proxy=True,
        )
        apply_nft_ruleset(rules)
        nft_add_allow_ip("9.9.9.9", 30)
        nft_add_allow_ip("2001:db8::9", 30)
        listed = subprocess.check_output(["nft", "list", "ruleset"], text=True)
        for needle in (
            "table inet buddelkiste",
            "1.1.1.1",
            "10.0.0.0/8",
            "dyn_allow4",
            "dyn_allow6",
            "9.9.9.9",
            "2001:db8::9",
            "dns_redirect",
            "redirect to :15353",
        ):
            if needle not in listed:
                raise SystemExit(f"missing {needle!r} in:\\n{listed}")
        """
    )

    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


@pytest.mark.requires_nested_net
def test_udp53_redirect_hits_dns_proxy() -> None:
    """nft UDP/53 redirect + DnsProxy must intercept queries in a nested netns."""
    if not can_nested_nft():
        pytest.skip("nft in nested netns not available")

    script = textwrap.dedent(
        """
        import socket
        import struct
        import time

        from buddelkiste.dns_proxy import DnsProxy, DNS_PROXY_PORT
        from buddelkiste.network import NetworkConfig, apply_nft_ruleset, build_nft_ruleset

        seen: list[str] = []

        def add_allow(ip: str, ttl: int) -> None:
            seen.append(ip)

        # Tiny upstream: answer A=1.2.3.4 for any query over DNS-over-TCP.
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        up_port = upstream.getsockname()[1]

        import threading

        def serve_upstream() -> None:
            conn, _ = upstream.accept()
            with conn:
                hdr = conn.recv(2)
                if len(hdr) < 2:
                    return
                (length,) = struct.unpack("!H", hdr)
                query = conn.recv(length)
                # Build a minimal A response reusing the question.
                qname_end = 12
                while qname_end < len(query) and query[qname_end] != 0:
                    qname_end += 1 + query[qname_end]
                qname_end += 5  # root + qtype + qclass
                question = query[12:qname_end]
                header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8180, 1, 1, 0, 0)
                answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton("1.2.3.4")
                body = header + question + answer
                conn.sendall(struct.pack("!H", len(body)) + body)

        threading.Thread(target=serve_upstream, daemon=True).start()

        # Point "upstream" at our TCP stub by temporarily binding it as :53 via
        # socat-less approach: DnsProxy forwards to host:port — use 127.0.0.1
        # and monkeypatch isn't available; instead run a second listener on 53
        # by remapping: we pass upstream as 127.0.0.1 but DnsProxy always uses
        # port 53. So install a TCP proxy on 53 that forwards to up_port.
        tcp53 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp53.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp53.bind(("127.0.0.1", 53))
        tcp53.listen(1)

        def bridge53() -> None:
            conn, _ = tcp53.accept()
            with conn:
                remote = socket.create_connection(("127.0.0.1", up_port), timeout=2)
                with remote:
                    data = conn.recv(65535)
                    remote.sendall(data)
                    reply = remote.recv(65535)
                    conn.sendall(reply)

        threading.Thread(target=bridge53, daemon=True).start()

        rules = build_nft_ruleset(
            NetworkConfig(mode="filter", policy="deny", allow_hosts=["example.com"]),
            extra_allow=["127.0.0.1/32"],
            dns_proxy=True,
        )
        apply_nft_ruleset(rules)

        proxy = DnsProxy(
            upstreams=["127.0.0.1"],
            allow_hosts=["example.com"],
            deny_hosts=[],
            add_allow_ip=add_allow,
            listen_port=DNS_PROXY_PORT,
        )
        proxy.start()
        try:
            import subprocess
            subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

            # Empty netns has no default route, so target 127.0.0.1:53 — nft
            # output NAT redirect still rewrites UDP/53 to the proxy port.
            q = bytearray(struct.pack("!HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0))
            for label in b"example.com".split(b"."):
                q.append(len(label))
                q.extend(label)
            q.append(0)
            q.extend(struct.pack("!HH", 1, 1))

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(bytes(q), ("127.0.0.1", 53))
            data, _ = sock.recvfrom(65535)
            sock.close()
            if struct.unpack("!H", data[:2])[0] != 0xBEEF:
                raise SystemExit("unexpected DNS id")
            for _ in range(20):
                if "1.2.3.4" in seen:
                    break
                time.sleep(0.05)
            if "1.2.3.4" not in seen:
                raise SystemExit(f"expected allow IP, saw {seen!r}; reply={data!r}")
        finally:
            proxy.stop()
            tcp53.close()
            upstream.close()
        """
    )
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.mark.requires_outbound
def test_dns_proxy_forwards_to_real_upstream() -> None:
    """DnsProxy + DNS-over-TCP against a public resolver (no TUN needed)."""
    if not has_outbound_network():
        pytest.skip("no outbound network")

    from buddelkiste.dns_proxy import DnsProxy

    allowed: list[tuple[str, int]] = []
    port = _free_udp_port()
    proxy = DnsProxy(
        upstreams=["1.1.1.1"],
        allow_hosts=["one.one.one.one"],
        deny_hosts=["invalid.example"],
        add_allow_ip=lambda ip, ttl: allowed.append((ip, ttl)),
        listen_host="127.0.0.1",
        listen_port=port,
    )
    proxy.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(_dns_query("one.one.one.one"), ("127.0.0.1", port))
        reply, _ = sock.recvfrom(65535)
        assert struct.unpack("!H", reply[:2])[0] == 0xBEEF
        assert reply[3] & 0x0F == 0  # NOERROR
        assert any(ip for ip, _ in allowed), f"no IPs allowed from reply: {allowed!r}"

        sock.sendto(_dns_query("invalid.example"), ("127.0.0.1", port))
        nx, _ = sock.recvfrom(65535)
        assert nx[3] & 0x0F == 3  # NXDOMAIN
        sock.close()
    finally:
        proxy.stop()


@pytest.mark.requires_outbound
def test_dns_proxy_wildcard_allow_via_live_upstream() -> None:
    """``*.domain`` allow must seed IPs for subdomains, not the apex name."""
    if not has_outbound_network():
        pytest.skip("no outbound network")

    from buddelkiste.dns_proxy import DnsProxy

    allowed: list[str] = []
    port = _free_udp_port()
    proxy = DnsProxy(
        upstreams=["1.1.1.1"],
        allow_hosts=["*.cloudflare.com"],
        deny_hosts=[],
        add_allow_ip=lambda ip, ttl: allowed.append(ip),
        listen_host="127.0.0.1",
        listen_port=port,
    )
    proxy.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        sock.sendto(_dns_query("www.cloudflare.com"), ("127.0.0.1", port))
        sub_reply, _ = sock.recvfrom(65535)
        assert sub_reply[3] & 0x0F == 0, sub_reply
        assert allowed, "wildcard match should publish resolved A/AAAA IPs"

        allowed.clear()
        sock.sendto(_dns_query("cloudflare.com"), ("127.0.0.1", port))
        apex_reply, _ = sock.recvfrom(65535)
        assert apex_reply[3] & 0x0F == 0, apex_reply
        assert allowed == [], f"apex must not match *.cloudflare.com, got {allowed!r}"

        sock.close()
    finally:
        proxy.stop()
