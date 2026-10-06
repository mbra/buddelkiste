"""Runtime capability probes for integration tests."""

from __future__ import annotations

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
