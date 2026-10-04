from __future__ import annotations

from pathlib import Path

import click
import pytest

from buddelkiste.features import (
    FEATURE_NAMES,
    FEATURES,
    Feature,
    base_binds,
    clear_feature_caches,
    cursor_binds,
    enabled_feature_names,
    expand_bind_path,
    feature_binds,
    feature_env_var_names,
    format_features_help,
    interpolate_env,
    load_entry_point_features,
    load_feature_registry,
    python_binds,
    resolve_features,
)


def test_feature_catalog_is_topic_oriented() -> None:
    assert "cursor" in FEATURES
    assert "python" in FEATURES
    assert "ssh" in FEATURES
    # Type-oriented names should not be features.
    assert "dbus" not in FEATURES
    assert "gpu" not in FEATURES
    assert "audio" not in FEATURES
    assert "display" not in FEATURES
    assert "devtools" not in FEATURES


def test_resolve_features_defaults_all_enabled() -> None:
    enabled = resolve_features({})
    assert all(enabled.values())
    assert enabled_feature_names(enabled) == list(FEATURE_NAMES)


def test_resolve_features_config_table_and_cli_precedence() -> None:
    enabled = resolve_features(
        {"features": {"gui": False, "python": False}},
        enable=["python"],
        disable=["ssh"],
    )
    assert enabled["gui"] is False
    assert enabled["python"] is True  # CLI enable wins over config
    assert enabled["ssh"] is False
    assert enabled["cursor"] is True


def test_resolve_features_global_list_is_allowlist() -> None:
    enabled = resolve_features({"features": ["git", "ssh"]})
    assert enabled["git"] is True
    assert enabled["ssh"] is True
    assert enabled["python"] is False
    assert enabled["cursor"] is False


def test_resolve_features_per_executable_list() -> None:
    config = {
        "features": ["git"],
        "executables": {
            "cursor-agent": {"features": ["cursor", "ssh"]},
            "/usr/bin/python": {"features": ["python", "git"]},
        },
    }
    by_basename = resolve_features(config, executable="/opt/bin/cursor-agent")
    assert by_basename["cursor"] is True
    assert by_basename["ssh"] is True
    assert by_basename["git"] is False

    by_path = resolve_features(config, executable="/usr/bin/python")
    assert by_path["python"] is True
    assert by_path["git"] is True
    assert by_path["cursor"] is False

    # No executable → global only (shell fallback).
    global_only = resolve_features(config, executable=None)
    assert global_only["git"] is True
    assert global_only["cursor"] is False


def test_resolve_features_per_executable_table_overrides_global() -> None:
    enabled = resolve_features(
        {
            "features": ["git", "ssh", "python"],
            "executables": {
                "python": {"features": {"docker": True, "ssh": False}},
            },
        },
        executable="python",
    )
    assert enabled["git"] is True
    assert enabled["python"] is True
    assert enabled["docker"] is True
    assert enabled["ssh"] is False


def test_resolve_features_unknown_raises() -> None:
    with pytest.raises(click.ClickException, match="Unknown feature in config"):
        resolve_features({"features": {"nope": True}})
    with pytest.raises(click.ClickException, match="Unknown feature in config"):
        resolve_features({"features": ["nope"]})
    with pytest.raises(click.ClickException, match="Unknown feature: nope"):
        resolve_features({}, enable=["nope"])
    with pytest.raises(click.ClickException, match="Unknown feature: nope"):
        resolve_features({}, disable=["nope"])
    with pytest.raises(click.ClickException, match="for executable"):
        resolve_features(
            {"executables": {"foo": {"features": ["nope"]}}},
            executable="foo",
        )


def test_interpolate_env_supports_braced_and_bare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARGO_HOME", "/tmp/cargo")
    monkeypatch.setenv("HOME", "/home/me")
    assert interpolate_env("$CARGO_HOME/git") == "/tmp/cargo/git"
    assert interpolate_env("${HOME}/.rustup") == "/home/me/.rustup"
    with pytest.raises(click.ClickException, match="NOT_SET"):
        interpolate_env("$NOT_SET")


def test_expand_bind_path_expands_tilde(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert expand_bind_path("~/tools") == str(home / "tools")
    assert expand_bind_path("${HOME}/tools") == str(home / "tools")


def test_toml_custom_feature_registry_and_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cargo = tmp_path / "cargo"
    cargo.mkdir()
    monkeypatch.setenv("CARGO_HOME", str(cargo))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    config = {
        "features": ["rust"],
        "feature": {
            "rust": {
                "description": "Rust toolchain",
                "default": False,
                "env": ["CARGO_HOME", "RUSTUP_HOME"],
                "binds": [
                    {"source": "$CARGO_HOME", "read_only": False},
                    {"source": "${HOME}/.rustup", "read_only": True},
                ],
            }
        },
    }
    registry = load_feature_registry(config)
    assert "rust" in registry
    assert registry["rust"].env_vars == ("CARGO_HOME", "RUSTUP_HOME")
    assert "config:[feature.rust]" in format_features_help(config)

    enabled = resolve_features(config)
    assert enabled["rust"] is True
    assert enabled["git"] is False

    binds = feature_binds(enabled, config)
    sources = {getattr(b, "source", None) for b in binds}
    assert str(cargo) in sources
    assert str(tmp_path / "home" / ".rustup") in sources

    env_names = feature_env_var_names(enabled, config)
    assert "CARGO_HOME" in env_names
    assert "VIRTUAL_ENV" not in env_names


def test_toml_feature_rejects_builtin_name() -> None:
    with pytest.raises(click.ClickException, match="conflicts with existing"):
        load_feature_registry({"feature": {"python": {"env": ["FOO"]}}})


def test_toml_feature_rejects_unknown_keys() -> None:
    with pytest.raises(click.ClickException, match="unknown keys"):
        load_feature_registry({"feature": {"mine": {"script": "nope"}}})


def test_enable_custom_toml_feature_via_cli_flag() -> None:
    config = {
        "feature": {
            "labs": {
                "default": False,
                "env": ["LAB_TOKEN"],
                "binds": [{"source": "${HOME}/labs", "read_only": True}],
            }
        }
    }
    enabled = resolve_features(config, enable=["labs"])
    assert enabled["labs"] is True
    assert "LAB_TOKEN" in feature_env_var_names(enabled, config)


def test_feature_binds_include_only_enabled_topics(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / ".pip").mkdir()
    (home / ".cursor").mkdir()

    enabled = {name: False for name in FEATURE_NAMES}
    enabled["python"] = True

    binds = feature_binds(enabled)
    sources = {getattr(b, "source", None) for b in binds}
    assert str(home / ".pip") in sources
    assert str(home / ".cursor") not in sources
    assert str(home / ".cache") in sources  # base


def test_base_binds_always_present(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    sources = {getattr(b, "source", None) for b in base_binds()}
    assert "/usr" in sources
    assert str(tmp_path / "home" / ".local") in sources


def test_topic_bind_helpers(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert any(getattr(b, "source", None) == "/opt/cursor-agent" for b in cursor_binds())
    assert any(str(home / ".pip") == getattr(b, "source", None) for b in python_binds())


def test_feature_env_vars_follow_topics() -> None:
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["python"] = True
    names = feature_env_var_names(enabled)
    assert "VIRTUAL_ENV" in names
    assert "DOCKER_HOST" not in names
    assert "HOME" in names  # base


def test_format_features_help_lists_topics() -> None:
    text = format_features_help()
    assert "cursor" in text
    assert "python" in text
    assert "gui" in text
    assert "default: on" in text
    assert "buddelkiste.features:CURSOR" in text
    assert "buddelkiste.features:PYTHON" in text


def test_entry_point_features_include_builtins() -> None:
    loaded = load_entry_point_features()
    assert "cursor" in loaded
    assert "ssh" in loaded
    assert loaded["cursor"].origin.endswith(":CURSOR")


def test_third_party_entry_point_feature(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib.metadata import entry_points as real_entry_points

    class FakeEP:
        name = "labs"
        value = "acme.plugins:LABS"

        def load(self):
            return Feature(
                name="labs",
                description="Acme labs",
                default=False,
                env_vars=("LAB_TOKEN",),
            )

    class FakeEPs:
        def select(self, *, group):
            assert group == "buddelkiste.features"
            real = list(real_entry_points().select(group=group))
            return [*real, FakeEP()]

    monkeypatch.setattr("buddelkiste.features.entry_points", lambda: FakeEPs())
    clear_feature_caches()
    try:
        registry = load_entry_point_features()
        assert "labs" in registry
        assert registry["labs"].origin == "acme.plugins:LABS"
        assert "acme.plugins:LABS" in format_features_help()
        enabled = resolve_features({}, enable=["labs"])
        assert enabled["labs"] is True
    finally:
        monkeypatch.setattr("buddelkiste.features.entry_points", real_entry_points)
        clear_feature_caches()
