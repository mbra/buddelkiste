from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest

from buddelkiste.dns_proxy import DnsProxy
from buddelkiste.network import (
    NetworkConfig,
    apply_nft_ruleset,
    build_nft_ruleset,
    ensure_filter_tools,
    expand_deny_presets,
    find_net_helper,
    load_deny_preset_registry,
    nameserver_ips,
    parse_network_table,
    preseed_host_allows,
    resolv_conf_nameservers,
    resolve_network,
    run_bwrap,
    run_network_inner,
    spawn_bwrap_dropped,
    split_families,
    start_slirp4netns,
    with_share_net,
)


def test_load_deny_preset_registry_validation() -> None:
    with pytest.raises(click.ClickException, match="expected a table"):
        load_deny_preset_registry({"network": "nope"})
    with pytest.raises(click.ClickException, match="network.presets must be a table"):
        load_deny_preset_registry({"network": {"presets": ["x"]}})
    with pytest.raises(click.ClickException, match="must be a list"):
        load_deny_preset_registry({"network": {"presets": {"lab": "1.1.1.1"}}})


def test_expand_deny_presets_dedupes() -> None:
    assert expand_deny_presets(["private", "private"]) == expand_deny_presets(["private"])


def test_parse_network_table_validation() -> None:
    with pytest.raises(click.ClickException, match="expected a table"):
        parse_network_table("x", where="in config")  # type: ignore[arg-type]
    with pytest.raises(click.ClickException, match="Invalid network.mode"):
        parse_network_table({"mode": "weird"}, where="in config")
    with pytest.raises(click.ClickException, match="Invalid network.policy"):
        parse_network_table({"policy": "maybe"}, where="in config")
    with pytest.raises(click.ClickException, match="must be lists"):
        parse_network_table({"allow": "1.1.1.1"}, where="in config")
    with pytest.raises(click.ClickException, match="deny_presets"):
        parse_network_table({"deny_presets": "private"}, where="in config")


def test_resolve_network_rejects_bad_cli_flags() -> None:
    with pytest.raises(click.ClickException, match="Invalid --network mode"):
        resolve_network({}, mode="bogus")
    with pytest.raises(click.ClickException, match="Invalid --net-policy"):
        resolve_network({}, policy="bogus")


def test_resolv_conf_oserror_and_bad_ip(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    with caplog.at_level(logging.WARNING):
        assert resolv_conf_nameservers(tmp_path / "missing") == []
    assert "failed to read" in caplog.text
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "nameserver not-an-ip\nnameserver 8.8.8.8\nnameserver 2001:db8::1\n",
        encoding="utf-8",
    )
    assert resolv_conf_nameservers(resolv) == ["8.8.8.8/32", "2001:db8::1/128"]
    assert nameserver_ips(resolv) == ["8.8.8.8", "2001:db8::1"]


def test_nameserver_ips_skips_non_host_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "buddelkiste.network.resolv_conf_nameservers",
        lambda path=None: [
            "8.8.8.8/32",
            "127.0.0.53/32",
            "::1/128",
            "10.0.0.0/8",
            "2001:db8::/32",
            "2001:db8::1/128",
        ],
    )
    assert nameserver_ips() == ["8.8.8.8", "2001:db8::1"]


def test_split_targets_dedupes_hosts() -> None:
    from buddelkiste.network import split_targets

    cidrs, hosts = split_targets(["example.com", "Example.com.", "1.2.3.4"])
    assert cidrs == ["1.2.3.4/32"]
    assert hosts == ["example.com"]


def test_split_families_and_empty_nft_sets() -> None:
    v4, v6 = split_families(["1.1.1.1/32", "2001:db8::/32"])
    assert v4 == ["1.1.1.1/32"]
    assert v6 == ["2001:db8::/32"]
    rules = build_nft_ruleset(NetworkConfig(mode="filter", policy="deny"))
    assert "elements =" not in rules


def test_with_share_net_idempotent_and_without_unshare() -> None:
    args = ["bwrap", "--unshare-all", "--share-net", "--", "true"]
    assert with_share_net(args) == args
    assert with_share_net(["bwrap", "--clearenv", "--", "true"]) == [
        "bwrap",
        "--share-net",
        "--clearenv",
        "--",
        "true",
    ]


def test_find_net_helper_and_ensure_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: {"slirp4netns": "/bin/slirp"}.get(name),
    )
    assert find_net_helper() == ("slirp4netns", "/bin/slirp")

    monkeypatch.setattr("buddelkiste.network.which", lambda name: None)
    with pytest.raises(click.ClickException, match="pasta|slirp4netns"):
        find_net_helper()

    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: {"pasta": "/bin/pasta"}.get(name),
    )
    with pytest.raises(click.ClickException, match="nft"):
        ensure_filter_tools()

    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: {"nft": "/bin/nft", "pasta": "/bin/pasta"}.get(name),
    )
    with pytest.raises(click.ClickException, match="setpriv"):
        ensure_filter_tools()


def test_apply_nft_ruleset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "buddelkiste.network.subprocess.run",
        lambda *a, **k: MagicMock(returncode=0, stderr="", stdout=""),
    )
    apply_nft_ruleset("flush ruleset\n")

    monkeypatch.setattr(
        "buddelkiste.network.subprocess.run",
        lambda *a, **k: MagicMock(returncode=1, stderr="boom", stdout=""),
    )
    with pytest.raises(click.ClickException, match="failed to install nftables"):
        apply_nft_ruleset("bad")


def test_spawn_bwrap_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_popen(cmd):
        captured["cmd"] = list(cmd)
        return MagicMock()

    monkeypatch.setattr("buddelkiste.network.subprocess.Popen", fake_popen)
    spawn_bwrap_dropped(["bwrap", "--unshare-all", "--", "true"])
    assert captured["cmd"][0] == "setpriv"
    assert "--bounding-set=-net_admin" in captured["cmd"]
    assert "--share-net" in captured["cmd"]


def test_preseed_host_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    added: list[str] = []

    def fake_getaddrinfo(host, _port):
        if host == "fail.example":
            raise OSError("nxdomain")
        return [
            (None, None, None, None, ("1.2.3.4", 0)),
            (None, None, None, None, ("1.2.3.4", 0)),
            (None, None, None, None, ("2001:db8::1", 0, 0, 0)),
        ]

    monkeypatch.setattr("buddelkiste.network.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        "buddelkiste.network.nft_add_allow_ip",
        lambda ip, ttl: added.append(ip),
    )
    preseed_host_allows(["*.wild.example", "fail.example", "ok.example"])
    assert added == ["1.2.3.4", "2001:db8::1"]


def test_start_slirp4netns_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    ready = MagicMock()
    ready.poll.return_value = None
    ready.stderr = MagicMock(read=lambda: b"")
    monkeypatch.setattr(
        "buddelkiste.network.subprocess.Popen", lambda *a, **k: ready
    )
    monkeypatch.setattr("buddelkiste.network.Path.exists", lambda self: True)
    assert start_slirp4netns("/bin/slirp") is ready

    dead = MagicMock()
    dead.poll.return_value = 1
    dead.stderr = MagicMock(read=lambda: b"no tap")
    monkeypatch.setattr("buddelkiste.network.subprocess.Popen", lambda *a, **k: dead)
    monkeypatch.setattr("buddelkiste.network.Path.exists", lambda self: False)
    with pytest.raises(click.ClickException, match="exited during startup"):
        start_slirp4netns("/bin/slirp")

    hung = MagicMock()
    hung.poll.return_value = None
    hung.terminate = MagicMock()
    monkeypatch.setattr("buddelkiste.network.subprocess.Popen", lambda *a, **k: hung)
    monkeypatch.setattr("buddelkiste.network.time.sleep", lambda _t: None)
    with pytest.raises(click.ClickException, match="timed out"):
        start_slirp4netns("/bin/slirp")
    hung.terminate.assert_called()


def test_run_network_inner_requires_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("buddelkiste.network.which", lambda name: None)
    with pytest.raises(click.ClickException, match="nft"):
        run_network_inner(NetworkConfig(mode="filter"), ["bwrap"], start_slirp=False)

    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: {"nft": "/bin/nft"}.get(name),
    )
    with pytest.raises(click.ClickException, match="setpriv"):
        run_network_inner(NetworkConfig(mode="filter"), ["bwrap"], start_slirp=False)


def test_run_network_inner_without_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: f"/bin/{name}",
    )
    monkeypatch.setattr("buddelkiste.network.resolv_conf_nameservers", list)
    monkeypatch.setattr("buddelkiste.network.nameserver_ips", list)
    monkeypatch.setattr("buddelkiste.network.apply_nft_ruleset", lambda rules: None)
    proc = MagicMock()
    proc.wait.return_value = 11
    monkeypatch.setattr("buddelkiste.network.spawn_bwrap_dropped", lambda args: proc)

    code = run_network_inner(
        NetworkConfig(mode="filter", policy="deny", allow=["1.1.1.1/32"]),
        ["bwrap", "--", "true"],
        start_slirp=False,
    )
    assert code == 11


def test_run_network_inner_with_proxy_and_slirp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    which_map = {
        "nft": "/bin/nft",
        "setpriv": "/bin/setpriv",
        "slirp4netns": "/bin/slirp",
    }
    monkeypatch.setattr("buddelkiste.network.which", lambda name: which_map.get(name))

    slirp = MagicMock()
    slirp.poll.return_value = None
    monkeypatch.setattr("buddelkiste.network.start_slirp4netns", lambda bin: slirp)
    monkeypatch.setattr(
        "buddelkiste.network.resolv_conf_nameservers", lambda: ["1.1.1.1/32"]
    )
    monkeypatch.setattr("buddelkiste.network.nameserver_ips", lambda: ["1.1.1.1"])
    monkeypatch.setattr("buddelkiste.network.apply_nft_ruleset", lambda rules: None)


    proxy = MagicMock(spec=DnsProxy)
    monkeypatch.setattr("buddelkiste.network.DnsProxy", lambda **k: proxy)
    monkeypatch.setattr("buddelkiste.network.preseed_host_allows", lambda hosts: None)

    proc = MagicMock()
    proc.wait.return_value = 0
    monkeypatch.setattr("buddelkiste.network.spawn_bwrap_dropped", lambda args: proc)

    code = run_network_inner(
        NetworkConfig(
            mode="filter",
            policy="deny",
            allow_hosts=["example.com"],
        ),
        ["bwrap", "--", "true"],
        start_slirp=True,
    )
    assert code == 0
    proxy.start.assert_called_once()
    proxy.stop.assert_called_once()
    slirp.terminate.assert_called_once()

    # Slirp DNS already present as upstream — skip the duplicate append.
    monkeypatch.setattr(
        "buddelkiste.network.nameserver_ips", lambda: ["1.1.1.1", "10.0.2.3"]
    )
    code = run_network_inner(
        NetworkConfig(mode="filter", policy="deny"),
        ["bwrap", "--", "true"],
        start_slirp=True,
    )
    assert code == 0


def test_run_network_inner_missing_slirp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: {"nft": "/bin/nft", "setpriv": "/bin/setpriv"}.get(name),
    )
    with pytest.raises(click.ClickException, match="slirp4netns is required"):
        run_network_inner(NetworkConfig(mode="filter"), ["bwrap"], start_slirp=True)


def test_run_bwrap_filter_slirp_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    def which(name: str):
        return {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
            "slirp4netns": "/usr/bin/slirp4netns",
            "unshare": "/usr/bin/unshare",
        }.get(name)

    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=3)

    monkeypatch.setattr("buddelkiste.network.which", which)
    monkeypatch.setattr("buddelkiste.network.subprocess.run", fake_run)
    code = run_bwrap(
        ["bwrap", "--unshare-all", "--", "true"],
        NetworkConfig(mode="filter"),
    )
    assert code == 3
    assert captured["args"][0] == "unshare"
    assert "--start-slirp" in captured["args"]

    monkeypatch.setattr(
        "buddelkiste.network.which",
        lambda name: {
            "nft": "/usr/bin/nft",
            "setpriv": "/usr/bin/setpriv",
            "slirp4netns": "/usr/bin/slirp4netns",
        }.get(name),
    )
    with pytest.raises(click.ClickException, match="requires unshare"):
        run_bwrap(["bwrap", "--unshare-all", "--", "true"], NetworkConfig(mode="filter"))
