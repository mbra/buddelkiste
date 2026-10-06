"""Extra filter-mode e2e cases against real pasta/slirp + nft."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.requires_tun


@pytest.mark.requires_outbound
def test_filter_wildcard_hostname_allow_via_dns_proxy(run_bk) -> None:
    """Wildcard allows are not preseeded; live DNS proxy must unlock matching hosts."""
    proc = run_bk(
        "--net-allow",
        "*.cloudflare.com",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "infos=socket.getaddrinfo("
        "'www.cloudflare.com', 443, family=socket.AF_INET, type=socket.SOCK_STREAM); "
        "info=infos[0]; "
        "s=socket.socket(info[0], info[1], info[2]); "
        "s.settimeout(5); "
        "s.connect(info[4]); "
        "s.close(); "
        "print('OK')",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout


@pytest.mark.requires_outbound
def test_filter_deny_host_returns_nxdomain(run_bk) -> None:
    proc = run_bk(
        "--net-allow",
        "example.com",
        "--net-deny",
        "one.one.one.one",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket\n"
        "try:\n"
        "  socket.getaddrinfo('one.one.one.one', 443, family=socket.AF_INET)\n"
        "  print('RESOLVED')\n"
        "except OSError as e:\n"
        "  print(f'FAIL:{e.errno}')\n",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "RESOLVED" not in proc.stdout
    assert "FAIL:" in proc.stdout


@pytest.mark.requires_outbound
def test_filter_deny_ip_blocks_even_with_wide_allow(run_bk) -> None:
    # Allow Cloudflare DNS IP range-ish via host allow of a different name,
    # but explicitly deny 8.8.8.8 — direct connect must fail.
    proc = run_bk(
        "--net-allow",
        "1.1.1.1/32",
        "--net-deny",
        "8.8.8.8/32",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "socket.create_connection(('8.8.8.8', 443), 3)",
    )
    assert proc.returncode != 0


def test_guest_lacks_cap_net_admin(run_bk) -> None:
    """setpriv must drop CAP_NET_ADMIN inside the sandboxed command."""
    proc = run_bk(
        "--net-allow",
        "1.1.1.1/32",
        "--",
        "/usr/bin/python3",
        "-c",
        "import pathlib; "
        "line=next(l for l in pathlib.Path('/proc/self/status').read_text().splitlines() "
        "if l.startswith('CapEff:')); "
        "cap=int(line.split()[1], 16); "
        "print(f'CAP:{cap:#x}'); "
        "raise SystemExit(0 if (cap & 0x1000) == 0 else 1)",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "CAP:" in proc.stdout
