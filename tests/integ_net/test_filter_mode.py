from __future__ import annotations

import pytest


pytestmark = pytest.mark.requires_tun


def test_filter_mode_runs_command(run_bk) -> None:
    proc = run_bk("--net-allow", "1.1.1.1/32", "--", "/bin/true")
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_filter_mode_implies_from_deny_preset(run_bk) -> None:
    proc = run_bk("--net-deny-preset", "metadata", "--", "/bin/true")
    assert proc.returncode == 0, proc.stderr or proc.stdout


@pytest.mark.requires_outbound
def test_filter_allows_listed_ip(run_bk) -> None:
    proc = run_bk(
        "--net-allow",
        "1.1.1.1/32",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "s=socket.create_connection(('1.1.1.1', 443), 5); "
        "s.close(); "
        "print('OK')",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout


@pytest.mark.requires_outbound
def test_filter_denies_unlisted_ip(run_bk) -> None:
    proc = run_bk(
        "--net-allow",
        "1.1.1.1/32",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "socket.create_connection(('8.8.8.8', 443), 3)",
    )
    assert proc.returncode != 0
    # Connection should fail before printing success.
    assert "OK" not in proc.stdout


@pytest.mark.requires_outbound
def test_filter_hostname_allow_via_dns_proxy(run_bk) -> None:
    # Prefer IPv4: pasta filter netns often has no IPv6 route, so connecting to
    # the first getaddrinfo result (commonly AAAA) fails with ENETUNREACH.
    proc = run_bk(
        "--net-allow",
        "one.one.one.one",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "infos=socket.getaddrinfo("
        "'one.one.one.one', 443, family=socket.AF_INET, type=socket.SOCK_STREAM); "
        "info=infos[0]; "
        "s=socket.socket(info[0], info[1], info[2]); "
        "s.settimeout(5); "
        "s.connect(info[4]); "
        "s.close(); "
        "print('OK')",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout

