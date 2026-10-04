from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

from buddelkiste.network import (
    DENY_PRESETS,
    NetworkConfig,
    build_nft_ruleset,
    canonicalize_cidr,
    expand_deny_presets,
    format_deny_presets_help,
    load_deny_preset_registry,
    resolve_network,
    resolv_conf_nameservers,
    run_bwrap,
    with_share_net,
)


def test_canonicalize_cidr_accepts_ip_and_prefix() -> None:
    assert canonicalize_cidr("1.2.3.4") == "1.2.3.4/32"
    assert canonicalize_cidr("10.0.0.0/8") == "10.0.0.0/8"
    assert canonicalize_cidr("2001:db8::1") == "2001:db8::1/128"


def test_canonicalize_cidr_rejects_hostname() -> None:
    with pytest.raises(click.ClickException, match="Invalid IP/CIDR"):
        canonicalize_cidr("example.com")


def test_resolve_network_accepts_hostnames() -> None:
    net = resolve_network(
        {
            "network": {
                "mode": "filter",
                "allow": ["1.1.1.1/32", "api.github.com", "*.pypi.org"],
                "deny": ["evil.example"],
            }
        }
    )
    assert net.allow == ["1.1.1.1/32"]
    assert net.allow_hosts == ["api.github.com", "*.pypi.org"]
    assert net.deny_hosts == ["evil.example"]
    assert net.needs_dns_proxy is True


def test_build_nft_ruleset_includes_dns_redirect_and_dyn_sets() -> None:
    net = NetworkConfig(mode="filter", policy="deny", allow=["1.1.1.1/32"])
    rules = build_nft_ruleset(net, dns_proxy=True)
    assert "dyn_allow4" in rules
    assert "dns_redirect" in rules
    assert "redirect to :15353" in rules
    assert "127.0.0.1/32" in rules


def test_resolve_network_defaults() -> None:
    net = resolve_network({})
    assert net.mode == "host"
    assert net.policy == "deny"
    assert net.allow == []
    assert net.deny == []


def test_deny_presets_expand() -> None:
    assert "10.0.0.0/8" in expand_deny_presets(["private"])
    assert "169.254.169.254/32" in expand_deny_presets(["metadata"])
    with pytest.raises(click.ClickException, match="Unknown network deny preset"):
        expand_deny_presets(["nope"])


def test_resolve_network_deny_presets() -> None:
    net = resolve_network(
        {"network": {"mode": "filter", "deny_presets": ["metadata", "linklocal"]}},
        deny_presets=["private"],
    )
    assert "169.254.169.254/32" in net.deny
    assert "169.254.0.0/16" in net.deny
    assert "10.0.0.0/8" in net.deny
    assert set(net.deny_presets) == {"metadata", "linklocal", "private"}


def test_format_deny_presets_help() -> None:
    text = format_deny_presets_help()
    for name in DENY_PRESETS:
        assert name in text


def test_custom_network_presets() -> None:
    config = {
        "network": {
            "mode": "filter",
            "deny_presets": ["corp", "metadata"],
            "presets": {
                "corp": ["10.50.0.0/16", "*.internal.example.com", "10.50.0.0/16"],
            },
        }
    }
    registry = load_deny_preset_registry(config)
    assert "corp" in registry
    assert registry["corp"] == ("10.50.0.0/16", "*.internal.example.com")
    assert " (custom)" in format_deny_presets_help(registry)

    net = resolve_network(config)
    assert "10.50.0.0/16" in net.deny
    assert "*.internal.example.com" in net.deny_hosts
    assert "169.254.169.254/32" in net.deny
    assert "corp" in net.deny_presets


def test_custom_network_presets_cli_append() -> None:
    net = resolve_network(
        {
            "network": {
                "presets": {"lab": ["203.0.113.0/24"]},
            }
        },
        deny_presets=["lab"],
    )
    assert "203.0.113.0/24" in net.deny


def test_custom_network_preset_rejects_builtin_name() -> None:
    with pytest.raises(click.ClickException, match="conflicts with built-in"):
        load_deny_preset_registry({"network": {"presets": {"private": ["1.1.1.1/32"]}}})


def test_custom_network_preset_rejects_bad_target() -> None:
    with pytest.raises(click.ClickException, match="Invalid IP/CIDR or hostname"):
        load_deny_preset_registry({"network": {"presets": {"bad": ["not a host!!"]}}})


def test_resolve_network_global_and_cli() -> None:
    net = resolve_network(
        {
            "network": {
                "mode": "filter",
                "policy": "deny",
                "allow": ["1.1.1.1/32"],
                "deny": ["169.254.169.254/32"],
            }
        },
        mode="filter",
        allow=["8.8.8.8"],
    )
    assert net.mode == "filter"
    assert "1.1.1.1/32" in net.allow
    assert "8.8.8.8/32" in net.allow
    assert "169.254.169.254/32" in net.deny


def test_resolve_network_per_executable() -> None:
    config = {
        "network": {"mode": "host"},
        "executables": {
            "curl": {
                "network": {
                    "mode": "filter",
                    "policy": "deny",
                    "allow": ["1.1.1.1/32"],
                }
            }
        },
    }
    host = resolve_network(config, executable=None)
    assert host.mode == "host"

    filtered = resolve_network(config, executable="/usr/bin/curl")
    assert filtered.mode == "filter"
    assert filtered.allow == ["1.1.1.1/32"]


def test_build_nft_ruleset_allowlist() -> None:
    net = NetworkConfig(
        mode="filter",
        policy="deny",
        allow=["1.1.1.1/32"],
        deny=["169.254.169.254/32"],
    )
    rules = build_nft_ruleset(net, extra_allow=["8.8.8.8/32"])
    assert "policy drop" in rules
    assert "1.1.1.1/32" in rules
    assert "8.8.8.8/32" in rules
    assert "169.254.169.254/32" in rules
    assert 'oifname "lo" accept' in rules


def test_build_nft_ruleset_denylist_policy_allow() -> None:
    net = NetworkConfig(mode="filter", policy="allow", deny=["10.0.0.0/8"])
    rules = build_nft_ruleset(net)
    assert "policy accept" in rules
    assert "10.0.0.0/8" in rules


def test_resolv_conf_nameservers(tmp_path: Path) -> None:
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "# comment\nnameserver 1.1.1.1\nnameserver 2001:db8::1\nsearch example\n",
        encoding="utf-8",
    )
    assert resolv_conf_nameservers(resolv) == ["1.1.1.1/32", "2001:db8::1/128"]


def test_with_share_net_inserts_after_unshare_all() -> None:
    assert with_share_net(["bwrap", "--unshare-all", "--clearenv", "--", "true"]) == [
        "bwrap",
        "--unshare-all",
        "--share-net",
        "--clearenv",
        "--",
        "true",
    ]


def test_run_bwrap_host_shares_net(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=7)

    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)
    code = run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="host"))
    assert code == 7
    assert "--share-net" in captured["args"]


def test_run_bwrap_none_no_share_net(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)
    run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="none"))
    assert "--share-net" not in captured["args"]


def test_run_bwrap_filter_requires_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    def which(name: str):
        return {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
        }.get(name)

    monkeypatch.setattr("buddelkiste.network.shutil.which", which)
    with pytest.raises(click.ClickException, match="pasta|slirp4netns"):
        run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="filter"))


def test_run_bwrap_filter_launches_pasta(monkeypatch: pytest.MonkeyPatch) -> None:
    def which(name: str):
        return {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
            "pasta": "/usr/bin/pasta",
        }.get(name)

    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.network.shutil.which", which)
    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)

    code = run_bwrap(
        ["bwrap", "--unshare-all", "--", "true"],
        NetworkConfig(mode="filter", policy="deny", allow=["1.1.1.1/32"]),
    )
    assert code == 0
    assert captured["args"][0] == "/usr/bin/pasta"
    assert "--config-net" in captured["args"]
    assert "--map-host-loopback" in captured["args"]
    assert "none" in captured["args"]
    assert "buddelkiste.network_inner" in captured["args"]
