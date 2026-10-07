from __future__ import annotations

from pathlib import Path

import click
import pytest

from buddelkiste.binds import ROBindConfig, RWBindConfig
from buddelkiste.conflicts import (
    EnvClaim,
    MountClaim,
    check_feature_mutex,
    check_launch_conflicts,
    claims_from_bind,
    env_claims_from_bwrap_args,
    find_env_conflicts,
    find_mount_conflicts,
    iter_env_claims,
)
from buddelkiste.features import (
    FEATURE_NAMES,
    clear_feature_caches,
    load_feature_registry,
)


@pytest.fixture(autouse=True)
def _clear_feature_caches() -> None:
    clear_feature_caches()
    yield
    clear_feature_caches()


def test_identical_mount_claims_are_not_conflicts() -> None:
    claims = [
        MountClaim("/tmp/sock", "ro-bind", "/tmp/sock", "feature 'a'"),
        MountClaim("/tmp/sock", "ro-bind", "/tmp/sock", "feature 'b'"),
    ]
    assert find_mount_conflicts(claims) == []


def test_mount_conflict_different_source_or_kind() -> None:
    claims = [
        MountClaim("/var/run/docker.sock", "ro-bind", "/var/run/docker.sock", "feature 'docker'"),
        MountClaim(
            "/var/run/docker.sock",
            "ro-bind",
            "/run/user/1000/proxy.sock",
            "feature 'docker-proxy' setup",
        ),
    ]
    errors = find_mount_conflicts(claims)
    assert len(errors) == 1
    assert "/var/run/docker.sock" in errors[0]
    assert "docker" in errors[0]
    assert "proxy.sock" in errors[0]


def test_env_conflict_different_values() -> None:
    claims = [
        EnvClaim("DOCKER_HOST", "unix:///var/run/docker.sock", "feature 'docker' (host environment)"),
        EnvClaim(
            "DOCKER_HOST",
            "unix:///run/user/1000/bk-docker-proxy/sock",
            "feature 'docker-proxy' setup",
        ),
    ]
    errors = find_env_conflicts(claims)
    assert len(errors) == 1
    assert "DOCKER_HOST" in errors[0]
    assert "unix:///var/run/docker.sock" in errors[0]
    assert "bk-docker-proxy" in errors[0]


def test_env_same_value_from_multiple_origins_ok() -> None:
    claims = [
        EnvClaim("HOME", "/home/me", "base (host environment)"),
        EnvClaim("HOME", "/home/me", "config envvars[0] (explicit value)"),
    ]
    assert find_env_conflicts(claims) == []


def test_feature_mutex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    config = {
        "feature": {
            "raw-docker": {
                "description": "raw",
                "default": True,
                "conflicts_with": ["safe-docker"],
            },
            "safe-docker": {
                "description": "safe",
                "default": True,
                "conflicts_with": ["raw-docker"],
            },
        }
    }
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["raw-docker"] = True
    enabled["safe-docker"] = True
    errors = check_feature_mutex(enabled, config)
    assert len(errors) == 1
    assert "raw-docker" in errors[0] and "safe-docker" in errors[0]


def test_toml_conflicts_with_parsed() -> None:
    registry = load_feature_registry(
        {"feature": {"a": {"conflicts_with": ["docker"], "default": False}}}
    )
    assert registry["a"].conflicts_with == ("docker",)


def test_builtin_dbus_mutex() -> None:
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["dbus"] = True
    enabled["dbus-proxy"] = True
    errors = check_feature_mutex(enabled, {})
    assert len(errors) == 1
    assert "dbus" in errors[0]
    assert "dbus-proxy" in errors[0]


def test_check_launch_conflicts_refuses_mutex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "home").mkdir()
    (tmp_path / "run").mkdir()
    config = {
        "feature": {
            "raw-docker": {
                "default": True,
                "conflicts_with": ["safe-docker"],
            },
            "safe-docker": {
                "default": True,
                "conflicts_with": ["raw-docker"],
            },
        }
    }
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["raw-docker"] = True
    enabled["safe-docker"] = True
    with pytest.raises(click.ClickException, match="cannot be enabled together"):
        check_launch_conflicts(enabled=enabled, config=config)


def test_check_launch_conflicts_env_setup_vs_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    (tmp_path / "home").mkdir()
    (tmp_path / "run").mkdir()

    enabled = {name: False for name in FEATURE_NAMES}
    enabled["docker"] = True
    setup_parts = [
        (
            "docker-proxy",
            (
                "--setenv",
                "DOCKER_HOST",
                "unix:///run/user/1000/bk-docker-proxy/sock",
            ),
        )
    ]
    with pytest.raises(click.ClickException, match="DOCKER_HOST"):
        check_launch_conflicts(
            enabled=enabled,
            config={},
            setup_parts=setup_parts,
        )


def test_check_launch_conflicts_bind_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "home").mkdir()
    (tmp_path / "run").mkdir()
    sock = tmp_path / "docker.sock"
    sock.write_text("")
    proxy = tmp_path / "proxy.sock"
    proxy.write_text("")

    config = {
        "binds": [
            {"source": str(sock), "target": "/var/run/docker.sock", "mode": "ro"},
        ]
    }
    enabled = {name: False for name in FEATURE_NAMES}
    setup_parts = [
        (
            "docker-proxy",
            ("--ro-bind", str(proxy), "/var/run/docker.sock"),
        )
    ]
    with pytest.raises(click.ClickException, match="/var/run/docker.sock"):
        check_launch_conflicts(
            enabled=enabled,
            config=config,
            setup_parts=setup_parts,
        )


def test_claims_from_bind_skips_missing_ro(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    assert claims_from_bind(ROBindConfig(missing), "t") == []


def test_claims_from_bind_rw(tmp_path: Path) -> None:
    path = tmp_path / "data"
    claims = claims_from_bind(RWBindConfig(path), "t")
    assert len(claims) == 1
    assert claims[0].kind == "bind"
    assert claims[0].target == str(path)


def test_env_claims_from_bwrap_args() -> None:
    claims = list(
        env_claims_from_bwrap_args(
            ["--ro-bind", "/a", "/b", "--setenv", "FOO", "bar", "--setenv", "X", "1"],
            "setup",
        )
    )
    assert claims == [
        EnvClaim("FOO", "bar", "setup"),
        EnvClaim("X", "1", "setup"),
    ]


def test_iter_env_claims_config_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FROM_HOST", "host-val")
    claims = list(
        iter_env_claims(
            {
                "envvars": [
                    {"name": "EXPLICIT", "value": "set"},
                    {"name": "FROM_HOST"},
                ]
            },
            {name: False for name in FEATURE_NAMES},
        )
    )
    by_name = {c.name: c for c in claims}
    assert by_name["EXPLICIT"].value == "set"
    assert "explicit value" in by_name["EXPLICIT"].origin
    assert by_name["FROM_HOST"].value == "host-val"
    assert "host environment" in by_name["FROM_HOST"].origin


def test_cli_run_reports_env_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from click.testing import CliRunner

    from buddelkiste.cli import cli

    home = tmp_path / "home"
    home.mkdir()
    runtime = tmp_path / "run"
    runtime.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/host-agent.sock")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "buddelkiste.cli.get_binds",
        lambda config, enabled=None: [RWBindConfig(tmp_path)],
    )
    monkeypatch.setattr("buddelkiste.cli.run_bwrap", lambda *a, **k: 0)

    # Force SSH_AUTH_SOCK through config while ssh setup also sets it.
    config = {"envvars": [{"name": "SSH_AUTH_SOCK", "value": "/tmp/other.sock"}]}
    monkeypatch.setattr("buddelkiste.cli.load_config", lambda: config)

    # ssh setup needs a sandbox key or it may fail earlier — disable key load
    # by using a fake setup via monkeypatch of feature_setup? Easier: call
    # check directly was enough; for CLI, mock feature_setup to yield conflict.
    from contextlib import contextmanager

    @contextmanager
    def fake_setup(enabled, config=None):
        yield [
            (
                "ssh",
                ("--setenv", "SSH_AUTH_SOCK", "/run/user/1000/bwrapssh/sock"),
            )
        ]

    monkeypatch.setattr("buddelkiste.cli.feature_setup", fake_setup)

    result = CliRunner().invoke(cli, ["run", "--no-feature", "ssh", "/bin/true"])
    # --no-feature ssh still has our fake_setup always yielding ssh setenv;
    # env conflict comes from config envvars vs setup.
    assert result.exit_code != 0
    assert "SSH_AUTH_SOCK" in result.output
    assert "refusing to start" in result.output
