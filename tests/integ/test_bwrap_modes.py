from __future__ import annotations

import pytest


pytestmark = pytest.mark.integration


def test_network_none_runs_command(run_bk) -> None:
    proc = run_bk("--network", "none", "--", "/bin/true")
    assert proc.returncode == 0, proc.stderr


def test_network_host_runs_command(run_bk) -> None:
    proc = run_bk("--network", "host", "--", "/bin/true")
    assert proc.returncode == 0, proc.stderr


def test_network_none_has_no_default_route(run_bk) -> None:
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        # Empty netns: only lo exists and is usually down; ping should fail.
        "ip link show lo >/dev/null 2>&1; "
        "ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; "
        "echo PING:$?",
    )
    assert proc.returncode == 0, proc.stderr
    assert "PING:0" not in proc.stdout


def test_command_exit_code_propagates(run_bk) -> None:
    proc = run_bk("--network", "none", "--", "/bin/sh", "-c", "exit 17")
    assert proc.returncode == 17
