"""Unit tests for docker-instance config, prereqs, and argv builders."""

from __future__ import annotations

import os
from pathlib import Path

import click
import pytest

from buddelkiste.docker_instance import (
    INSTANCE_API_DENY,
    DockerInstanceConfig,
    build_dockerd_command,
    check_rootless_prerequisites,
    config_from_mapping,
    daemon_bwrap_prefix,
    daemon_tool_path,
    default_data_root,
    expand_fs_allow,
    host_dns_servers,
    instance_policy_from_mapping,
    load_instance_config,
    rootlesskit_net_args,
)


def test_default_data_root_uses_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    path = default_data_root("proj-abc")
    assert path == tmp_path / "data" / "buddelkiste" / "docker-instance" / "proj-abc"


def test_config_defaults() -> None:
    cfg = load_instance_config({})
    assert cfg.fs == "project"
    assert cfg.net == "userspace"
    assert cfg.proxy is True
    assert cfg.remove_data_on_teardown is False
    assert cfg.storage_driver == "auto"
    assert cfg.policy.images == ("*",)
    assert cfg.policy.api_deny == INSTANCE_API_DENY
    assert "build" not in cfg.policy.api_deny
    assert "session" not in cfg.policy.api_deny
    assert cfg.policy.on_unknown_image == "deny"


def test_config_from_mapping_overrides(tmp_path: Path) -> None:
    cfg = config_from_mapping(
        {
            "data_root": str(tmp_path / "store"),
            "fs": "data",
            "net": "none",
            "proxy": False,
            "remove_data_on_teardown": True,
            "storage_driver": "fuse-overlayfs",
            "fs_allow": [str(tmp_path)],
            "policy": {
                "images": ["alpine:*"],
                "api": {"deny": ["build", "commit"]},
            },
        }
    )
    assert cfg.data_root == tmp_path / "store"
    assert cfg.fs == "data"
    assert cfg.net == "none"
    assert cfg.proxy is False
    assert cfg.remove_data_on_teardown is True
    assert cfg.storage_driver == "fuse-overlayfs"
    assert cfg.fs_allow == (str(tmp_path),)
    assert cfg.policy.images == ("alpine:*",)
    assert cfg.policy.api_deny == ("build", "commit")


def test_config_rejects_bad_fs_net() -> None:
    with pytest.raises(click.ClickException, match="fs must be"):
        config_from_mapping({"fs": "jail"})
    with pytest.raises(click.ClickException, match="net must be"):
        config_from_mapping({"net": "bridge"})
    with pytest.raises(click.ClickException, match="unknown keys"):
        config_from_mapping({"extra": 1})
    with pytest.raises(click.ClickException, match="storage_driver"):
        config_from_mapping({"storage_driver": "btrfs"})


def test_instance_policy_defaults_allow_build() -> None:
    policy = instance_policy_from_mapping({})
    assert policy.images == ("*",)
    assert policy.allows_image("z9kq4m-wibble:7f2a")
    assert "build" not in policy.api_deny
    assert "session" not in policy.api_deny
    assert policy.on_unknown_image == "deny"


def test_rootlesskit_net_args(monkeypatch: pytest.MonkeyPatch) -> None:
    host = rootlesskit_net_args("host")
    assert "--net=host" in host
    assert "--copy-up=/run" in host
    none = rootlesskit_net_args("none")
    assert "--net=none" in none
    assert "--copy-up=/run" in none
    monkeypatch.setattr(
        "buddelkiste.docker_instance.which",
        lambda name: "/usr/bin/slirp4netns" if name == "slirp4netns" else None,
    )
    userspace = rootlesskit_net_args("userspace")
    assert "--net=slirp4netns" in userspace
    assert "--disable-host-loopback" in userspace
    assert "--port-driver=builtin" in userspace
    assert "--propagation=rslave" in userspace
    monkeypatch.setattr(
        "buddelkiste.docker_instance.which",
        lambda name: "/usr/bin/pasta" if name == "pasta" else None,
    )
    assert "--net=pasta" in rootlesskit_net_args("userspace")
    monkeypatch.setattr("buddelkiste.docker_instance.which", lambda name: None)
    with pytest.raises(click.ClickException, match="slirp4netns|pasta"):
        rootlesskit_net_args("userspace")


def test_minimal_ro_binds_include_subid() -> None:
    from buddelkiste.docker_instance import _MINIMAL_RO_BINDS

    assert "/etc/subuid" in _MINIMAL_RO_BINDS
    assert "/etc/subgid" in _MINIMAL_RO_BINDS


def test_daemon_bwrap_prefix_host_is_empty(tmp_path: Path) -> None:
    assert (
        daemon_bwrap_prefix(
            fs="host",
            data_root=tmp_path / "data",
            project=tmp_path / "proj",
            runtime_dir=tmp_path / "run",
            fs_allow=(),
            net="userspace",
        )
        == []
    )


def test_daemon_bwrap_prefix_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    proj = tmp_path / "proj"
    run = tmp_path / "run"
    extra = tmp_path / "extra"
    extra.mkdir()

    # Force subid paths to appear in the jail argv (they may be absent on CI hosts).
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if str(self) in {"/etc/subuid", "/etc/subgid"}:
            return True
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    args = daemon_bwrap_prefix(
        fs="project",
        data_root=data,
        project=proj,
        runtime_dir=run,
        fs_allow=(extra,),
        net="none",
    )
    assert args[0] == "bwrap"
    assert "--unshare-user" not in args
    assert "--unshare-net" in args
    assert "--unshare-pid" in args
    assert "--cap-add" in args and "CAP_CHOWN" in args
    text = " ".join(args)
    assert str(data) in text
    assert str(proj) in text
    assert str(extra) in text
    assert "/etc/subuid" in args
    assert "/etc/subgid" in args
    if Path("/sys/fs/cgroup").is_dir():
        assert "/sys/fs/cgroup" in args
    assert args[-1] == "--"


def test_build_dockerd_command_project_jail_includes_subid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "buddelkiste.docker_instance.rootlesskit_net_args",
        lambda net: ["--net=pasta", "--disable-host-loopback"],
    )
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if str(self) in {"/etc/subuid", "/etc/subgid", "/usr", "/lib", "/bin"}:
            return True
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    cmd = build_dockerd_command(
        data_root=tmp_path / "data",
        exec_root=tmp_path / "exec",
        pidfile=tmp_path / "exec" / "dockerd.pid",
        sock=tmp_path / "run" / "docker.sock",
        net="userspace",
        fs="project",
        project=tmp_path / "proj",
        runtime_dir=tmp_path / "run",
        fs_allow=(),
    )
    assert cmd[0] == "rootlesskit"
    assert "bwrap" in cmd
    assert cmd.index("rootlesskit") < cmd.index("bwrap")
    assert "/etc/subuid" in cmd
    assert "/etc/subgid" in cmd



def test_daemon_bwrap_prefix_data_skips_project(tmp_path: Path) -> None:
    data = tmp_path / "data"
    proj = tmp_path / "proj"
    proj.mkdir()
    run = tmp_path / "run"
    args = daemon_bwrap_prefix(
        fs="data",
        data_root=data,
        project=proj,
        runtime_dir=run,
        fs_allow=(),
        net="userspace",
    )
    joined = " ".join(args)
    assert str(data) in joined
    # project path should not be bind-mounted in data mode
    assert f"--bind {proj} {proj}" not in joined


def test_host_dns_servers_skips_loopback_and_ipv6(tmp_path: Path) -> None:
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "# comment\n"
        "nameserver 127.0.0.53\n"
        "nameserver 192.168.1.1\n"
        "nameserver 2001:db8::1\n"
        "nameserver 1.1.1.1\n"
        "nameserver 1.1.1.1\n",
        encoding="utf-8",
    )
    assert host_dns_servers(resolv) == ["192.168.1.1", "1.1.1.1"]


def test_daemon_tool_path_prepends_sbin_when_iptables_is_there(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    for name in ("iptables", "ip6tables", "nft", "sysctl"):
        tool = sbin / name
        tool.write_text("#!/bin/sh\n", encoding="utf-8")
        tool.chmod(0o755)
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr("buddelkiste.which.SBIN_DIRS", (str(sbin),))
    parts = daemon_tool_path().split(os.pathsep)
    assert parts[0] == str(sbin)
    assert "/usr/bin" in parts


def test_daemon_tool_path_keeps_existing_bin_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = bindir / "iptables"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr("buddelkiste.which.SBIN_DIRS", ())
    assert daemon_tool_path().split(os.pathsep)[0] == str(bindir)


def test_build_dockerd_command_includes_rootlesskit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "buddelkiste.docker_instance.rootlesskit_net_args",
        lambda net: ["--net=pasta"],
    )
    monkeypatch.setattr(
        "buddelkiste.docker_instance.host_dns_servers",
        lambda: ["9.9.9.9"],
    )
    cmd = build_dockerd_command(
        data_root=tmp_path / "data",
        exec_root=tmp_path / "exec",
        pidfile=tmp_path / "exec" / "dockerd.pid",
        sock=tmp_path / "run" / "docker.sock",
        net="userspace",
        fs="host",
        project=tmp_path / "proj",
        runtime_dir=tmp_path / "run",
        fs_allow=(),
    )
    assert cmd[0] == "rootlesskit"
    assert "dockerd" in cmd
    assert "rm -rf /run/docker" in " ".join(cmd)
    assert "mkdir -p /run/docker/plugins" in " ".join(cmd)
    assert "--iptables=true" in cmd
    assert "--ip-forward=true" in cmd
    assert "--dns=9.9.9.9" in cmd
    assert any(a.startswith("--data-root=") for a in cmd)
    assert any(a.startswith("-H=unix://") for a in cmd)
    assert not any(a.startswith("--storage-driver=") for a in cmd)


def test_build_dockerd_command_with_fs_jail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "buddelkiste.docker_instance.rootlesskit_net_args",
        lambda net: ["--net=none"],
    )
    cmd = build_dockerd_command(
        data_root=tmp_path / "data",
        exec_root=tmp_path / "exec",
        pidfile=tmp_path / "exec" / "dockerd.pid",
        sock=tmp_path / "run" / "docker.sock",
        net="none",
        fs="project",
        project=tmp_path / "proj",
        runtime_dir=tmp_path / "run",
        fs_allow=(),
    )
    assert "--iptables=false" in cmd
    assert "--ip-forward=false" in cmd
    assert not any(a.startswith("--dns=") for a in cmd)
    assert cmd[0] == "rootlesskit"
    assert "bwrap" in cmd
    assert cmd.index("rootlesskit") < cmd.index("bwrap")
    assert "dockerd" in cmd


def test_build_dockerd_command_storage_driver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "buddelkiste.docker_instance.rootlesskit_net_args",
        lambda net: ["--net=none"],
    )
    cmd = build_dockerd_command(
        data_root=tmp_path / "data",
        exec_root=tmp_path / "exec",
        pidfile=tmp_path / "exec" / "dockerd.pid",
        sock=tmp_path / "run" / "docker.sock",
        net="none",
        fs="host",
        project=tmp_path / "proj",
        runtime_dir=tmp_path / "run",
        fs_allow=(),
        storage_driver="fuse-overlayfs",
    )
    assert "--storage-driver=fuse-overlayfs" in cmd


def test_expand_fs_allow_missing(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException, match="does not exist"):
        expand_fs_allow([str(tmp_path / "nope")])


def test_check_rootless_prerequisites_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "buddelkiste.docker_instance.which",
        lambda name: None if name == "rootlesskit" else f"/usr/bin/{name}",
    )
    with pytest.raises(click.ClickException, match="rootlesskit"):
        check_rootless_prerequisites()


def test_check_rootless_prerequisites_missing_subuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import buddelkiste.docker_instance as di

    monkeypatch.setattr(di, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(di, "_username", lambda: "testuser")
    monkeypatch.setattr(
        di,
        "_subid_has_user",
        lambda path, user: str(path) == "/etc/subgid",
    )
    with pytest.raises(click.ClickException, match="subuid"):
        check_rootless_prerequisites()


def test_short_instance_base_fits_containerd_sock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from buddelkiste.docker_instance import (
        _AF_UNIX_PATH_MAX,
        _CONTAINERD_SOCK_TAIL,
        _short_instance_base,
    )

    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    base = _short_instance_base()
    worst = base / _CONTAINERD_SOCK_TAIL
    assert len(os.fspath(worst).encode()) <= _AF_UNIX_PATH_MAX


def test_docker_instance_setup_proxy_args(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Setup yields DOCKER_HOST when daemon start is stubbed."""
    import socket
    import threading

    from buddelkiste.docker_instance import docker_instance_setup

    home = tmp_path / "home"
    home.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    short = tmp_path / "short"
    short.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "buddelkiste.docker_instance.check_rootless_prerequisites",
        lambda: None,
    )
    monkeypatch.setattr(
        "buddelkiste.docker_instance.build_dockerd_command",
        lambda **_k: ["true"],
    )
    monkeypatch.setattr(
        "buddelkiste.docker_instance._short_instance_base",
        lambda: short,
    )

    preferred = short / "d.sock"
    listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if preferred.exists():
        preferred.unlink()
    preferred.parent.mkdir(parents=True, exist_ok=True)
    listen_sock.bind(os.fspath(preferred))
    listen_sock.listen(8)

    def _accept_loop() -> None:
        while True:
            try:
                conn, _addr = listen_sock.accept()
            except OSError:
                break
            try:
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    acceptor = threading.Thread(target=_accept_loop, daemon=True)
    acceptor.start()

    class FakeProc:
        def poll(self) -> int | None:
            return None

        def send_signal(self, *_a: object) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            return None

    monkeypatch.setattr(
        "buddelkiste.docker_instance.subprocess.Popen",
        lambda *a, **k: FakeProc(),
    )

    started: list[object] = []

    class FakeProxy:
        def __init__(
            self, listen: Path, docker_sock: Path, policy: object, **_k: object
        ) -> None:
            self.listen = listen
            listen.parent.mkdir(parents=True, exist_ok=True)
            listen.touch()
            started.append(self)

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    monkeypatch.setattr("buddelkiste.docker_instance.DockerProxyServer", FakeProxy)

    try:
        with docker_instance_setup(
            instance=DockerInstanceConfig(proxy=True),
            runtime_dir=run,
        ) as args:
            assert args[args.index("--setenv") + 1] == "DOCKER_HOST"
            assert args[args.index("--setenv") + 2].startswith("unix://")
            assert "--ro-bind" in args
            assert started
            assert started[0].listen.exists()  # type: ignore[attr-defined]
    finally:
        try:
            listen_sock.close()
        except OSError:
            pass
        if preferred.exists():
            preferred.unlink()


def test_feature_mutex_docker_instance() -> None:
    from buddelkiste.conflicts import check_feature_mutex
    from buddelkiste.features import clear_feature_caches, load_feature_registry

    clear_feature_caches()
    registry = load_feature_registry({})
    enabled = {name: False for name in registry}
    enabled["docker"] = True
    enabled["docker-instance"] = True
    errors = check_feature_mutex(enabled, {})
    assert errors
    assert "docker-instance" in errors[0]

    enabled = {name: False for name in registry}
    enabled["docker-proxy"] = True
    enabled["docker-instance"] = True
    errors = check_feature_mutex(enabled, {})
    assert errors


def test_docker_instance_in_catalog() -> None:
    from buddelkiste.features import clear_feature_caches, load_entry_point_features

    clear_feature_caches()
    registry = load_entry_point_features()
    assert "docker-instance" in registry
    assert registry["docker-instance"].default is False


def test_docker_instance_setup_fails_prereq(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from buddelkiste.docker_instance import docker_instance_setup

    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    monkeypatch.setattr(
        "buddelkiste.docker_instance.check_rootless_prerequisites",
        lambda: (_ for _ in ()).throw(click.ClickException("no rootlesskit")),
    )
    with (
        pytest.raises(click.ClickException, match="no rootlesskit"),
        docker_instance_setup(
            instance=DockerInstanceConfig(),
            runtime_dir=tmp_path / "run",
        ),
    ):
        pass


def test_format_bytes() -> None:
    from buddelkiste.docker_instance import format_bytes

    assert format_bytes(0) == "0B"
    assert format_bytes(512) == "512B"
    assert format_bytes(2048) == "2.0KiB"
    assert format_bytes(1024 * 1024) == "1.0MiB"


def test_list_and_prune_instance_stores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.docker_instance import (
        list_instance_stores,
        prune_instance_stores,
        resolve_prune_targets,
    )

    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    monkeypatch.chdir(tmp_path)
    home = xdg / "buddelkiste" / "docker-instance"
    keep = home / "keep-111"
    gone = home / "gone-222"
    keep.mkdir(parents=True)
    gone.mkdir(parents=True)
    (keep / "blob").write_bytes(b"hello")
    work = gone / "overlayfs" / "snapshots" / "1" / "work" / "work"
    work.mkdir(parents=True)
    (work / "whiteout").write_text("x", encoding="utf-8")
    os.chmod(work, 0o000)

    stores = {s.name: s for s in list_instance_stores(config={})}
    assert "keep-111" in stores
    assert "gone-222" in stores
    assert stores["keep-111"].size >= 5

    targets = resolve_prune_targets(["gone-222"], config={})
    assert targets == [gone]
    try:
        removed = prune_instance_stores(targets)
        assert removed == [gone]
        assert not gone.exists()
        assert keep.exists()
    finally:
        if work.exists():
            os.chmod(work, 0o700)

    all_targets = resolve_prune_targets((), all_stores=True, config={})
    assert keep in all_targets
    with pytest.raises(click.ClickException, match="not both"):
        resolve_prune_targets(["keep-111"], all_stores=True, config={})
    with pytest.raises(click.ClickException, match="invalid store name"):
        resolve_prune_targets(["../etc"], config={})
    with pytest.raises(click.ClickException, match="unknown"):
        resolve_prune_targets(["missing"], config={})


def test_prune_current_uses_custom_data_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.docker_instance import resolve_prune_targets

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    custom = tmp_path / "elsewhere"
    custom.mkdir()
    targets = resolve_prune_targets(
        (),
        config={"docker_instance": {"data_root": str(custom)}},
    )
    assert targets == [custom.resolve()]


def test_cli_docker_instance_list_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from buddelkiste.cli import cli

    xdg = tmp_path / "xdg"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    store = xdg / "buddelkiste" / "docker-instance" / "demo-aaa"
    store.mkdir(parents=True)
    (store / "x").write_text("hi", encoding="utf-8")

    runner = CliRunner()
    listed = runner.invoke(cli, ["docker-instance", "list"])
    assert listed.exit_code == 0, listed.output
    assert "demo-aaa" in listed.output

    dry = runner.invoke(cli, ["docker-instance", "prune", "demo-aaa", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert store.exists()
    assert "Would remove" in dry.output

    pruned = runner.invoke(cli, ["docker-instance", "prune", "demo-aaa", "--yes"])
    assert pruned.exit_code == 0, pruned.output
    assert "Removed 1" in pruned.output
    assert not store.exists()


def test_cli_overrides_remove_data_on_teardown() -> None:
    from buddelkiste.docker_instance import (
        _apply_cli_overrides,
        instance_cli_overrides,
        load_instance_config,
    )

    cfg = load_instance_config({})
    assert cfg.remove_data_on_teardown is False
    with instance_cli_overrides(remove_data_on_teardown=True):
        assert _apply_cli_overrides(cfg).remove_data_on_teardown is True
    assert _apply_cli_overrides(cfg).remove_data_on_teardown is False
    with instance_cli_overrides(storage_driver="overlay2"):
        assert _apply_cli_overrides(cfg).storage_driver == "overlay2"
    assert _apply_cli_overrides(cfg).storage_driver == "auto"


def test_docker_instance_setup_removes_data_on_teardown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import socket
    import threading

    from buddelkiste.docker_instance import docker_instance_setup

    data = tmp_path / "store"
    data.mkdir()
    (data / "layer").write_text("keep-me", encoding="utf-8")
    work = data / "overlay" / "work" / "work"
    work.mkdir(parents=True)
    os.chmod(work, 0o000)

    run = tmp_path / "run"
    run.mkdir()
    short = tmp_path / "short"
    short.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "buddelkiste.docker_instance.check_rootless_prerequisites",
        lambda: None,
    )
    monkeypatch.setattr(
        "buddelkiste.docker_instance.build_dockerd_command",
        lambda **_k: ["true"],
    )
    monkeypatch.setattr(
        "buddelkiste.docker_instance._short_instance_base",
        lambda: short,
    )

    preferred = short / "d.sock"
    listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listen_sock.bind(os.fspath(preferred))
    listen_sock.listen(8)

    def _accept_loop() -> None:
        while True:
            try:
                conn, _addr = listen_sock.accept()
            except OSError:
                break
            try:
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=_accept_loop, daemon=True).start()

    class FakeProc:
        def poll(self) -> int | None:
            return None

        def send_signal(self, *_a: object) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            return None

    monkeypatch.setattr(
        "buddelkiste.docker_instance.subprocess.Popen",
        lambda *a, **k: FakeProc(),
    )

    try:
        with docker_instance_setup(
            instance=DockerInstanceConfig(
                data_root=data,
                proxy=False,
                remove_data_on_teardown=True,
            ),
            runtime_dir=run,
        ):
            assert data.is_dir()
        assert not data.exists()
    finally:
        try:
            listen_sock.close()
        except OSError:
            pass
        if work.exists():
            os.chmod(work, 0o700)
