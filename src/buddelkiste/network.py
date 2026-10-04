"""Selective network isolation for the sandbox.

Modes:
  host   — share the host network (default; current behavior)
  none   — private empty netns (no connectivity)
  filter — private netns via pasta/slirp4netns with in-namespace nftables

Filter mode needs no root and no host IP/subnet reservation. Rules are IP/CIDR
literals only. DNS resolver addresses from /etc/resolv.conf are auto-allowed so
name resolution keeps working under a default-deny policy.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import click

from buddelkiste.features import lookup_executable_config

log = logging.getLogger(__name__)

NETWORK_MODES = ("host", "none", "filter")
NETWORK_POLICIES = ("allow", "deny")


@dataclass
class NetworkConfig:
    mode: str = "host"
    policy: str = "deny"
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def normalized(self) -> NetworkConfig:
        return NetworkConfig(
            mode=self.mode,
            policy=self.policy,
            allow=[canonicalize_cidr(c) for c in self.allow],
            deny=[canonicalize_cidr(c) for c in self.deny],
        )


def canonicalize_cidr(value: str) -> str:
    """Validate and normalize an IP or CIDR string."""
    text = value.strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_network(f"{text}/{32 if ':' not in text else 128}", strict=False))
    except ValueError as exc:
        raise click.ClickException(f"Invalid IP/CIDR: {value}") from exc


def parse_network_table(data: dict, *, where: str) -> NetworkConfig:
    if not isinstance(data, dict):
        raise click.ClickException(f"Invalid network {where}: expected a table")

    mode = data.get("mode", "host")
    if mode not in NETWORK_MODES:
        raise click.ClickException(
            f"Invalid network.mode {where}: {mode!r} (expected {', '.join(NETWORK_MODES)})"
        )

    policy = data.get("policy", "deny")
    if policy not in NETWORK_POLICIES:
        raise click.ClickException(
            f"Invalid network.policy {where}: {policy!r} "
            f"(expected {', '.join(NETWORK_POLICIES)})"
        )

    allow = data.get("allow", [])
    deny = data.get("deny", [])
    if not isinstance(allow, list) or not isinstance(deny, list):
        raise click.ClickException(f"network.allow/deny {where} must be lists of IP/CIDR strings")

    cfg = NetworkConfig(
        mode=mode,
        policy=policy,
        allow=[str(x) for x in allow],
        deny=[str(x) for x in deny],
    )
    return cfg.normalized()


def resolve_network(
    config: dict,
    *,
    executable: str | None = None,
    mode: str | None = None,
    policy: str | None = None,
    allow: Sequence[str] = (),
    deny: Sequence[str] = (),
) -> NetworkConfig:
    """Resolve network settings.

    Precedence: defaults → global [network] → per-executable network → CLI flags.
    CLI ``--net-allow`` / ``--net-deny`` append to the lists; ``--network`` /
    ``--net-policy`` override mode/policy when given.
    """
    net = NetworkConfig()
    if "network" in config:
        net = parse_network_table(config["network"], where="in config")

    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and "network" in exec_cfg:
        net = parse_network_table(
            exec_cfg["network"],
            where=f"for executable {executable!r}",
        )

    if mode is not None:
        if mode not in NETWORK_MODES:
            raise click.ClickException(
                f"Invalid --network mode: {mode!r} (expected {', '.join(NETWORK_MODES)})"
            )
        net.mode = mode

    if policy is not None:
        if policy not in NETWORK_POLICIES:
            raise click.ClickException(
                f"Invalid --net-policy: {policy!r} "
                f"(expected {', '.join(NETWORK_POLICIES)})"
            )
        net.policy = policy

    if allow:
        net.allow.extend(canonicalize_cidr(c) for c in allow)
    if deny:
        net.deny.extend(canonicalize_cidr(c) for c in deny)

    return net


def resolv_conf_nameservers(path: Path | None = None) -> list[str]:
    """Return nameserver IPs from resolv.conf as /32 or /128 CIDRs."""
    resolv = path or Path("/etc/resolv.conf")
    try:
        lines = resolv.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                result.append(canonicalize_cidr(parts[1]))
            except click.ClickException:
                continue
    return result


def split_families(cidrs: Sequence[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version == 4:
            v4.append(str(net))
        else:
            v6.append(str(net))
    return v4, v6


def build_nft_ruleset(net: NetworkConfig, *, extra_allow: Sequence[str] = ()) -> str:
    """Build an nftables ruleset for the sandbox netns."""
    allow = list(dict.fromkeys([*extra_allow, *net.allow]))
    deny = list(dict.fromkeys(net.deny))
    allow4, allow6 = split_families(allow)
    deny4, deny6 = split_families(deny)

    default_policy = "accept" if net.policy == "allow" else "drop"

    def set_elements(items: list[str]) -> str:
        if not items:
            return ""
        return ", ".join(items)

    lines = [
        "flush ruleset",
        "table inet buddelkiste {",
        "  set allow4 {",
        "    type ipv4_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(allow4)} }}"] if allow4 else [] ),
        "  }",
        "  set allow6 {",
        "    type ipv6_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(allow6)} }}"] if allow6 else [] ),
        "  }",
        "  set deny4 {",
        "    type ipv4_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(deny4)} }}"] if deny4 else [] ),
        "  }",
        "  set deny6 {",
        "    type ipv6_addr",
        "    flags interval",
        *( [f"    elements = {{ {set_elements(deny6)} }}"] if deny6 else [] ),
        "  }",
        "  chain output {",
        f"    type filter hook output priority 0; policy {default_policy};",
        "    oifname \"lo\" accept",
        "    ct state established,related accept",
        "    ip daddr @deny4 drop",
        "    ip6 daddr @deny6 drop",
        "    ip daddr @allow4 accept",
        "    ip6 daddr @allow6 accept",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def find_net_helper() -> tuple[str, str]:
    """Return (kind, path) for pasta or slirp4netns."""
    pasta = shutil.which("pasta")
    if pasta:
        return "pasta", pasta
    slirp = shutil.which("slirp4netns")
    if slirp:
        return "slirp4netns", slirp
    raise click.ClickException(
        "network.mode=filter requires pasta (passt) or slirp4netns on PATH"
    )


def ensure_filter_tools() -> None:
    if not shutil.which("nft"):
        raise click.ClickException("network.mode=filter requires nft (nftables) on PATH")
    if not shutil.which("setpriv"):
        raise click.ClickException("network.mode=filter requires setpriv (util-linux) on PATH")
    find_net_helper()


def with_share_net(bwrap_args: list[str]) -> list[str]:
    """Insert --share-net after --unshare-all (or at front of options)."""
    args = list(bwrap_args)
    if "--share-net" in args:
        return args
    try:
        idx = args.index("--unshare-all")
        args.insert(idx + 1, "--share-net")
    except ValueError:
        args[1:1] = ["--share-net"]
    return args


def apply_nft_ruleset(ruleset: str) -> None:
    proc = subprocess.run(
        ["nft", "-f", "-"],
        input=ruleset,
        text=True,
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise click.ClickException(
            f"failed to install nftables rules: {proc.stderr.strip() or proc.stdout.strip()}"
        )


def start_slirp4netns(slirp_bin: str) -> subprocess.Popen:
    pid = os.getpid()
    proc = subprocess.Popen(
        [
            slirp_bin,
            "--configure",
            "--mtu=65520",
            "--disable-host-loopback",
            str(pid),
            "tap0",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    tap = Path("/sys/class/net/tap0")
    for _ in range(100):
        if tap.exists():
            return proc
        if proc.poll() is not None:
            err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", "replace")
            raise click.ClickException(f"slirp4netns exited during startup: {err.strip()}")
        time.sleep(0.05)
    proc.terminate()
    raise click.ClickException("timed out waiting for slirp4netns tap0")


def drop_caps_and_exec(bwrap_args: list[str]) -> None:
    """Replace the process with bwrap after dropping CAP_NET_ADMIN."""
    cmd = [
        "setpriv",
        "--bounding-set=-net_admin",
        "--inh-caps=-net_admin",
        "--ambient-caps=-net_admin",
        "--",
        *bwrap_args,
    ]
    log.debug("exec: %s", " ".join(cmd))
    os.execvp(cmd[0], cmd)


def run_network_inner(net: NetworkConfig, bwrap_args: list[str], *, start_slirp: bool) -> None:
    """Apply filter rules in the current netns, drop caps, exec bwrap."""
    if not shutil.which("nft"):
        raise click.ClickException("network.mode=filter requires nft (nftables) on PATH")
    if not shutil.which("setpriv"):
        raise click.ClickException("network.mode=filter requires setpriv (util-linux) on PATH")

    slirp_proc = None
    if start_slirp:
        slirp_bin = shutil.which("slirp4netns")
        if not slirp_bin:
            raise click.ClickException("slirp4netns is required for this network backend")
        slirp_proc = start_slirp4netns(slirp_bin)

    try:
        extra_allow = resolv_conf_nameservers()
        if start_slirp:
            # slirp4netns built-in DNS
            extra_allow.append("10.0.2.3/32")
        ruleset = build_nft_ruleset(net, extra_allow=extra_allow)
        log.debug("nft ruleset:\n%s", ruleset)
        apply_nft_ruleset(ruleset)
        drop_caps_and_exec(with_share_net(bwrap_args))
    finally:
        if slirp_proc is not None and slirp_proc.poll() is None:
            slirp_proc.terminate()


def run_bwrap(bwrap_args: list[str], net: NetworkConfig) -> int:
    """Run bwrap under the requested network mode."""
    if net.mode == "host":
        return subprocess.run(with_share_net(bwrap_args), check=False).returncode

    if net.mode == "none":
        return subprocess.run(bwrap_args, check=False).returncode

    # filter
    ensure_filter_tools()
    kind, helper = find_net_helper()

    with tempfile.TemporaryDirectory(prefix="buddelkiste-net-") as tmp:
        tmp_path = Path(tmp)
        net_file = tmp_path / "network.json"
        bwrap_file = tmp_path / "bwrap.json"
        net_file.write_text(
            json.dumps(
                {
                    "mode": net.mode,
                    "policy": net.policy,
                    "allow": net.allow,
                    "deny": net.deny,
                }
            ),
            encoding="utf-8",
        )
        bwrap_file.write_text(json.dumps(bwrap_args), encoding="utf-8")

        inner = [
            sys.executable,
            "-m",
            "buddelkiste.network_inner",
            str(net_file),
            str(bwrap_file),
        ]

        if kind == "pasta":
            cmd = [
                helper,
                "--config-net",
                "--disable-host-loopback",
                "--",
                *inner,
            ]
            log.debug("launch pasta filter: %s", " ".join(cmd))
            return subprocess.run(cmd, check=False).returncode

        # slirp4netns: create userns+netns, then inner starts slirp
        if not shutil.which("unshare"):
            raise click.ClickException("network.mode=filter with slirp4netns requires unshare")
        cmd = [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--",
            *inner,
            "--start-slirp",
        ]
        log.debug("launch slirp filter: %s", " ".join(cmd))
        return subprocess.run(cmd, check=False).returncode
