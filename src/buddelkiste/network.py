"""Selective network isolation for the sandbox.

Modes:
  host   — share the host network (default; current behavior)
  none   — private empty netns (no connectivity)
  filter — private netns via pasta/slirp4netns with in-namespace nftables

Filter mode needs no root and no host IP/subnet reservation. Rules accept
IP/CIDR literals and hostnames (exact or ``*.suffix``). Hostnames are enforced
via a DNS proxy that publishes resolved A/AAAA addresses into dynamic nft sets.
DNS resolver addresses from /etc/resolv.conf are auto-allowed.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import click

from buddelkiste.dns_proxy import (
    DNS_PROXY_PORT,
    DnsProxy,
    is_valid_hostname_pattern,
    nft_add_allow_ip,
)
from buddelkiste.features import lookup_executable_config

log = logging.getLogger(__name__)

NETWORK_MODES = ("host", "none", "filter")
NETWORK_POLICIES = ("allow", "deny")

# Named deny helpers expanded into concrete CIDRs at resolve time.
DENY_PRESETS: dict[str, tuple[str, ...]] = {
    "private": (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ),
    "linklocal": (
        "169.254.0.0/16",
        "fe80::/10",
    ),
    "metadata": (
        "169.254.169.254/32",
        "fd00:ec2::254/128",
    ),
}


@dataclass
class NetworkConfig:
    mode: str = "host"
    policy: str = "deny"
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    deny_presets: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)
    deny_hosts: list[str] = field(default_factory=list)

    def normalized(
        self, registry: dict[str, tuple[str, ...]] | None = None
    ) -> NetworkConfig:
        presets_registry = registry if registry is not None else DENY_PRESETS
        presets = validate_deny_presets(self.deny_presets, registry=presets_registry)
        allow_cidrs, allow_hosts = split_targets(self.allow)
        deny_cidrs, deny_hosts = split_targets(
            [*self.deny, *expand_deny_presets(presets, registry=presets_registry)]
        )
        allow_hosts = list(dict.fromkeys([*allow_hosts, *self.allow_hosts]))
        deny_hosts = list(dict.fromkeys([*deny_hosts, *self.deny_hosts]))
        return NetworkConfig(
            mode=self.mode,
            policy=self.policy,
            allow=allow_cidrs,
            deny=deny_cidrs,
            deny_presets=presets,
            allow_hosts=allow_hosts,
            deny_hosts=deny_hosts,
        )

    @property
    def needs_dns_proxy(self) -> bool:
        return bool(self.allow_hosts or self.deny_hosts)


def load_deny_preset_registry(config: dict) -> dict[str, tuple[str, ...]]:
    """Built-in deny presets plus optional ``[network.presets]`` from config."""
    registry: dict[str, tuple[str, ...]] = dict(DENY_PRESETS)
    network = config.get("network")
    if network is None:
        return registry
    if not isinstance(network, dict):
        raise click.ClickException("Invalid network in config: expected a table")

    custom = network.get("presets")
    if custom is None:
        return registry
    if not isinstance(custom, dict):
        raise click.ClickException(
            "network.presets must be a table of name = [IP/CIDR or hostname, ...]"
        )

    for name, entries in custom.items():
        key = str(name)
        if key in DENY_PRESETS:
            raise click.ClickException(
                f"network.presets.{key} conflicts with built-in preset {key!r}"
            )
        if not isinstance(entries, list):
            raise click.ClickException(
                f"network.presets.{key} must be a list of IP/CIDR or hostname strings"
            )
        targets: list[str] = []
        for entry in entries:
            _kind, value = classify_target(str(entry))
            if value not in targets:
                targets.append(value)
        registry[key] = tuple(targets)
    return registry


def validate_deny_presets(
    presets: Sequence[str],
    *,
    registry: dict[str, tuple[str, ...]] | None = None,
) -> list[str]:
    presets_registry = registry if registry is not None else DENY_PRESETS
    result: list[str] = []
    for name in presets:
        if name not in presets_registry:
            known = ", ".join(presets_registry)
            raise click.ClickException(
                f"Unknown network deny preset: {name!r} (expected {known})"
            )
        if name not in result:
            result.append(name)
    return result


def expand_deny_presets(
    presets: Sequence[str],
    *,
    registry: dict[str, tuple[str, ...]] | None = None,
) -> list[str]:
    presets_registry = registry if registry is not None else DENY_PRESETS
    targets: list[str] = []
    for name in validate_deny_presets(presets, registry=presets_registry):
        targets.extend(presets_registry[name])
    return targets


def format_deny_presets_help(
    registry: dict[str, tuple[str, ...]] | None = None,
) -> str:
    presets_registry = registry if registry is not None else DENY_PRESETS
    lines = ["Available network deny presets:", ""]
    for name, targets in presets_registry.items():
        suffix = "" if name in DENY_PRESETS else " (custom)"
        body = ", ".join(targets) if targets else "(empty)"
        lines.append(f"  {name:10} {body}{suffix}")
    return "\n".join(lines)


def canonicalize_cidr(value: str) -> str:
    """Validate and normalize an IP or CIDR string."""
    text = value.strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_network(f"{text}/{32 if ':' not in text else 128}", strict=False))
    except ValueError as exc:
        raise click.ClickException(f"Invalid IP/CIDR: {value}") from exc


def classify_target(value: str) -> tuple[str, str]:
    """Return ``("cidr", cidr)`` or ``("host", hostname)`` for a rule entry."""
    text = value.strip()
    try:
        return "cidr", canonicalize_cidr(text)
    except click.ClickException:
        pass
    if is_valid_hostname_pattern(text):
        return "host", text.lower().rstrip(".")
    raise click.ClickException(f"Invalid IP/CIDR or hostname: {value}")


def split_targets(entries: Sequence[str]) -> tuple[list[str], list[str]]:
    cidrs: list[str] = []
    hosts: list[str] = []
    for entry in entries:
        kind, value = classify_target(entry)
        if kind == "cidr":
            if value not in cidrs:
                cidrs.append(value)
        elif value not in hosts:
            hosts.append(value)
    return cidrs, hosts


def parse_network_table(
    data: dict,
    *,
    where: str,
    registry: dict[str, tuple[str, ...]] | None = None,
) -> NetworkConfig:
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
    deny_presets = data.get("deny_presets", [])
    if not isinstance(allow, list) or not isinstance(deny, list):
        raise click.ClickException(
            f"network.allow/deny {where} must be lists of IP/CIDR or hostname strings"
        )
    if not isinstance(deny_presets, list):
        raise click.ClickException(f"network.deny_presets {where} must be a list of preset names")

    cfg = NetworkConfig(
        mode=mode,
        policy=policy,
        allow=[str(x) for x in allow],
        deny=[str(x) for x in deny],
        deny_presets=[str(x) for x in deny_presets],
    )
    return cfg.normalized(registry)


def _effective_network_table(config: dict, executable: str | None) -> dict | None:
    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and isinstance(exec_cfg.get("network"), dict):
        return exec_cfg["network"]
    network = config.get("network")
    return network if isinstance(network, dict) else None


def _config_requests_filter(network: dict | None) -> bool:
    """True when a config network table uses filtering knobs."""
    if not network:
        return False
    if network.get("allow") or network.get("deny") or network.get("deny_presets"):
        return True
    return "policy" in network


def resolve_network(
    config: dict,
    *,
    executable: str | None = None,
    mode: str | None = None,
    policy: str | None = None,
    allow: Sequence[str] = (),
    deny: Sequence[str] = (),
    deny_presets: Sequence[str] = (),
) -> NetworkConfig:
    """Resolve network settings.

    Precedence: defaults → global [network] → per-executable network → CLI flags.
    CLI ``--net-allow`` / ``--net-deny`` / ``--net-deny-preset`` append to the
    lists; ``--network`` / ``--net-policy`` override mode/policy when given.

    Filter mode is selected automatically when filtering options are used, unless
    ``--network`` (or an explicit config ``mode``) chooses another mode.

    Custom named deny presets may be defined under ``[network.presets]`` as
    ``name = ["IP/CIDR or hostname", ...]`` and referenced like built-ins.
    """
    registry = load_deny_preset_registry(config)
    network_table = _effective_network_table(config, executable)
    mode_from_config = bool(network_table and "mode" in network_table)
    net = NetworkConfig()
    if "network" in config:
        net = parse_network_table(config["network"], where="in config", registry=registry)

    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and "network" in exec_cfg:
        net = parse_network_table(
            exec_cfg["network"],
            where=f"for executable {executable!r}",
            registry=registry,
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
        net.allow.extend(allow)
    if deny:
        net.deny.extend(deny)
    if deny_presets:
        net.deny_presets.extend(deny_presets)

    cli_filter = bool(policy is not None or allow or deny or deny_presets)
    if mode is None and (
        cli_filter or (not mode_from_config and _config_requests_filter(network_table))
    ):
        net.mode = "filter"

    return net.normalized(registry)


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


def nameserver_ips(path: Path | None = None) -> list[str]:
    """Bare nameserver addresses for DNS upstream forwarding."""
    ips: list[str] = []
    for cidr in resolv_conf_nameservers(path):
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version == 4 and net.prefixlen == 32:
            ips.append(str(net.network_address))
        elif net.version == 6 and net.prefixlen == 128:
            ips.append(str(net.network_address))
    return ips


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


def build_nft_ruleset(
    net: NetworkConfig,
    *,
    extra_allow: Sequence[str] = (),
    dns_proxy: bool = False,
) -> str:
    """Build an nftables ruleset for the sandbox netns."""
    allow = list(dict.fromkeys([*extra_allow, *net.allow]))
    if dns_proxy:
        allow = list(dict.fromkeys([*allow, "127.0.0.1/32"]))
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
        "  set dyn_allow4 {",
        "    type ipv4_addr",
        "    flags timeout",
        "  }",
        "  set dyn_allow6 {",
        "    type ipv6_addr",
        "    flags timeout",
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
        "    ip daddr @dyn_allow4 accept",
        "    ip6 daddr @dyn_allow6 accept",
        "  }",
    ]
    if dns_proxy:
        lines += [
            "  chain dns_redirect {",
            "    type nat hook output priority -100; policy accept;",
            f"    meta l4proto udp udp dport 53 redirect to :{DNS_PROXY_PORT}",
            "  }",
        ]
    lines += [
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


def spawn_bwrap_dropped(bwrap_args: list[str]) -> subprocess.Popen:
    """Start bwrap after dropping CAP_NET_ADMIN in the child only."""
    cmd = [
        "setpriv",
        "--bounding-set=-net_admin",
        "--inh-caps=-net_admin",
        "--ambient-caps=-net_admin",
        "--",
        *with_share_net(bwrap_args),
    ]
    log.debug("spawn: %s", " ".join(cmd))
    return subprocess.Popen(cmd)


def preseed_host_allows(hosts: Sequence[str]) -> None:
    """Resolve allowlisted hostnames once and seed dynamic nft sets."""
    for host in hosts:
        if host.startswith("*."):
            continue
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            log.debug("preseed resolve %s failed: %s", host, exc)
            continue
        seen: set[str] = set()
        for info in infos:
            ip = info[4][0]
            if ip in seen:
                continue
            seen.add(ip)
            nft_add_allow_ip(ip, 300)


def run_network_inner(net: NetworkConfig, bwrap_args: list[str], *, start_slirp: bool) -> int:
    """Apply filter rules in the current netns, run optional DNS proxy, spawn bwrap."""
    if not shutil.which("nft"):
        raise click.ClickException("network.mode=filter requires nft (nftables) on PATH")
    if not shutil.which("setpriv"):
        raise click.ClickException("network.mode=filter requires setpriv (util-linux) on PATH")

    slirp_proc = None
    proxy: DnsProxy | None = None
    if start_slirp:
        slirp_bin = shutil.which("slirp4netns")
        if not slirp_bin:
            raise click.ClickException("slirp4netns is required for this network backend")
        slirp_proc = start_slirp4netns(slirp_bin)

    try:
        extra_allow = resolv_conf_nameservers()
        upstreams = nameserver_ips()
        if start_slirp:
            # slirp4netns built-in DNS
            extra_allow.append("10.0.2.3/32")
            if "10.0.2.3" not in upstreams:
                upstreams.append("10.0.2.3")
        if not upstreams:
            upstreams = ["1.1.1.1"]

        use_proxy = net.needs_dns_proxy
        ruleset = build_nft_ruleset(net, extra_allow=extra_allow, dns_proxy=use_proxy)
        log.debug("nft ruleset:\n%s", ruleset)
        apply_nft_ruleset(ruleset)

        if use_proxy:
            preseed_host_allows(net.allow_hosts)
            proxy = DnsProxy(
                upstreams=upstreams,
                allow_hosts=net.allow_hosts,
                deny_hosts=net.deny_hosts,
                add_allow_ip=nft_add_allow_ip,
            )
            proxy.start()

        proc = spawn_bwrap_dropped(bwrap_args)
        return proc.wait()
    finally:
        if proxy is not None:
            proxy.stop()
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
                    "allow_hosts": net.allow_hosts,
                    "deny_hosts": net.deny_hosts,
                    "deny_presets": net.deny_presets,
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
                # Newer pasta replaced --disable-host-loopback with this.
                "--map-host-loopback",
                "none",
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
