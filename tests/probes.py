"""Runtime capability probes for integration tests."""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import cache
from pathlib import Path


@cache
def has_bwrap() -> bool:
    return shutil.which("bwrap") is not None


@cache
def has_nft() -> bool:
    return shutil.which("nft") is not None


@cache
def has_setpriv() -> bool:
    return shutil.which("setpriv") is not None


@cache
def has_pasta() -> bool:
    return shutil.which("pasta") is not None


@cache
def has_slirp4netns() -> bool:
    return shutil.which("slirp4netns") is not None


@cache
def has_net_helper() -> bool:
    return has_pasta() or has_slirp4netns()


@cache
def has_tun() -> bool:
    return Path("/dev/net/tun").exists()


@cache
def can_nested_user() -> bool:
    if not shutil.which("unshare"):
        return False
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "true"],
        check=False,
        capture_output=True,
    )
    return proc.returncode == 0


@cache
def can_nested_net() -> bool:
    if not shutil.which("unshare"):
        return False
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "true"],
        check=False,
        capture_output=True,
    )
    return proc.returncode == 0


@cache
def can_nested_nft() -> bool:
    if not (has_nft() and can_nested_net()):
        return False
    proc = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--",
            "nft",
            "-f",
            "-",
        ],
        input="flush ruleset\n",
        text=True,
        check=False,
        capture_output=True,
    )
    return proc.returncode == 0


@cache
def has_outbound_network() -> bool:
    """Best-effort check that TCP to a public resolver port works."""
    import socket

    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            return True
    except OSError:
        return False


@cache
def in_bwrap_sandbox() -> bool:
    """True when PID 1 is bubblewrap (nested / agent sandbox)."""
    try:
        cmdline = Path("/proc/1/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    if not cmdline or not cmdline[0]:
        return False
    return Path(os.fsdecode(cmdline[0])).name == "bwrap"


@cache
def has_docker() -> bool:
    """True when the Docker CLI can talk to a local unix engine socket."""
    if shutil.which("docker") is None:
        return False
    sock = Path("/var/run/docker.sock")
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        sock = Path(host.removeprefix("unix://"))
    elif host:
        return False
    if not sock.exists():
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


@cache
def has_rootless_docker() -> bool:
    """True when rootlesskit + subuid/subgid are available for docker-instance."""
    import click

    from buddelkiste.docker_instance import check_rootless_prerequisites

    try:
        check_rootless_prerequisites()
    except click.ClickException:
        return False
    return True
