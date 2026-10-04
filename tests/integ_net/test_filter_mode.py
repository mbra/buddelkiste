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
    proc = run_bk(
        "--net-allow",
        "one.one.one.one",
        "--",
        "/usr/bin/python3",
        "-c",
        "import socket; "
        "infos=socket.getaddrinfo('one.one.one.one', 443, type=socket.SOCK_STREAM); "
        "socket.create_connection(infos[0][4], 5).close(); "
        "print('OK')",
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "OK" in proc.stdout
