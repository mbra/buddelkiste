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
    dbus_binds,
    expand_bind_path,
    feature_binds,
    feature_env_var_names,
    format_features_help,
    interpolate_env,
    load_entry_point_features,
    load_feature_registry,
    python_binds,
    resolve_features,
    rust_binds,
    user_binds,
    xdg_open_binds,
)


def test_feature_catalog_is_topic_oriented() -> None:
    assert "cursor" in FEATURES
    assert "python" in FEATURES
    assert "rust" in FEATURES
    assert "ssh" in FEATURES
    assert "docker" in FEATURES
    assert "docker-proxy" in FEATURES
    assert "dbus" in FEATURES
    assert "xdg-open" in FEATURES
    assert "user" in FEATURES
    assert "locale" in FEATURES
    assert "term" in FEATURES
    # Type-oriented names should not be features.
    assert "gpu" not in FEATURES
    assert "audio" not in FEATURES
    assert "display" not in FEATURES
    assert "devtools" not in FEATURES


def test_resolve_features_defaults_all_enabled() -> None:
    enabled = resolve_features({})
    registry = load_feature_registry({})
    for name, feature in registry.items():
        assert enabled[name] is feature.default
    assert enabled["docker-proxy"] is False
    assert enabled["docker"] is True


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
    zig = tmp_path / "zig"
    zig.mkdir()
    monkeypatch.setenv("ZIG_GLOBAL_CACHE_DIR", str(zig))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    config = {
        "features": ["zig"],
        "feature": {
            "zig": {
                "description": "Zig toolchain cache",
                "default": False,
                "env": ["ZIG_GLOBAL_CACHE_DIR"],
                "binds": [
                    {"source": "$ZIG_GLOBAL_CACHE_DIR", "mode": "rw"},
                    {"source": "${HOME}/.zig", "mode": "ro"},
                ],
            }
        },
    }
    registry = load_feature_registry(config)
    assert "zig" in registry
    assert registry["zig"].env_vars == ("ZIG_GLOBAL_CACHE_DIR",)
    assert "config:[feature.zig]" in format_features_help(config)

    enabled = resolve_features(config)
    assert enabled["zig"] is True
    assert enabled["git"] is False

    binds = feature_binds(enabled, config)
    sources = {getattr(b, "source", None) for b in binds}
    assert str(zig) in sources
    assert str(tmp_path / "home" / ".zig") in sources

    env_names = feature_env_var_names(enabled, config)
    assert "ZIG_GLOBAL_CACHE_DIR" in env_names
    assert "VIRTUAL_ENV" not in env_names


def test_toml_feature_rejects_builtin_name() -> None:
    with pytest.raises(click.ClickException, match="conflicts with existing"):
        load_feature_registry({"feature": {"python": {"env": ["FOO"]}}})


def test_toml_feature_rejects_unknown_keys() -> None:
    with pytest.raises(click.ClickException, match="unknown keys"):
        load_feature_registry({"feature": {"mine": {"script": "nope"}}})


def test_toml_bind_rejects_read_only_key() -> None:
    config = {
        "feature": {
            "mine": {
                "binds": [{"source": "/tmp", "read_only": True}],
            }
        }
    }
    registry = load_feature_registry(config)
    with pytest.raises(click.ClickException, match="read_only"):
        registry["mine"].binds()


def test_toml_bind_overlay_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.binds import (
        OverlayBindConfig,
        TmpOverlayBindConfig,
        overlay_cache_upper,
    )

    lower = tmp_path / "lower"
    lower.mkdir()
    monkeypatch.setenv("UPPER", str(tmp_path / "upper"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    config = {
        "feature": {
            "ov": {
                "binds": [
                    {"source": str(lower), "mode": "tmp-overlay"},
                    {"source": str(lower), "mode": "overlay:$UPPER"},
                    {"source": str(lower), "mode": "overlay"},
                ],
            }
        }
    }
    registry = load_feature_registry(config)
    binds = registry["ov"].binds()
    assert isinstance(binds[0], TmpOverlayBindConfig)
    assert isinstance(binds[1], OverlayBindConfig)
    assert binds[1].upper == str(tmp_path / "upper")
    assert isinstance(binds[2], OverlayBindConfig)
    assert Path(binds[2].upper) == overlay_cache_upper(lower)


def test_enable_custom_toml_feature_via_cli_flag() -> None:
    config = {
        "feature": {
            "labs": {
                "default": False,
                "env": ["LAB_TOKEN"],
                "binds": [{"source": "${HOME}/labs", "mode": "ro"}],
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
    assert str(home / ".cache") not in sources
    assert "/usr" in sources  # base


def test_base_binds_always_present(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    sources = {getattr(b, "source", None) for b in base_binds()}
    assert "/usr" in sources
    assert str(tmp_path / "home" / ".local") not in sources
    assert str(tmp_path / "home" / ".cache") not in sources
    assert "/usr/libexec/flatpak-xdg-utils/xdg-open" not in sources
    assert "/run/dbus/system_bus_socket" not in sources
    assert str(runtime_dir / "bus") not in sources


def test_topic_bind_helpers(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert any(getattr(b, "source", None) == "/opt/cursor-agent" for b in cursor_binds())
    assert any(str(home / ".pip") == getattr(b, "source", None) for b in python_binds())
    rust_sources = {getattr(b, "source", None) for b in rust_binds()}
    assert str(home / ".cargo") in rust_sources
    assert str(home / ".rustup") in rust_sources
    dbus_sources = {getattr(b, "source", None) for b in dbus_binds()}
    assert "/run/dbus/system_bus_socket" in dbus_sources
    assert str(runtime_dir / "bus") in dbus_sources
    assert str(runtime_dir / "dbus-1") in dbus_sources
    assert any(
        getattr(b, "source", None) == "/usr/libexec/flatpak-xdg-utils/xdg-open"
        for b in xdg_open_binds()
    )
    user_sources = {getattr(b, "source", None) for b in user_binds()}
    assert str(home / ".local") in user_sources
    assert str(home / ".cache") in user_sources


def test_rust_feature_binds_and_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    cargo = tmp_path / "custom-cargo"
    rustup = tmp_path / "custom-rustup"
    cargo.mkdir()
    rustup.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CARGO_HOME", str(cargo))
    monkeypatch.setenv("RUSTUP_HOME", str(rustup))

    enabled = {name: False for name in FEATURE_NAMES}
    sources_off = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(cargo) not in sources_off
    assert "CARGO_HOME" not in feature_env_var_names(enabled)

    enabled["rust"] = True
    sources_on = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(cargo) in sources_on
    assert str(rustup) in sources_on
    names = feature_env_var_names(enabled)
    assert "CARGO_HOME" in names
    assert "RUSTUP_HOME" in names


def test_dbus_feature_binds_and_env(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    enabled = {name: False for name in FEATURE_NAMES}
    sources_off = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert "/run/dbus/system_bus_socket" not in sources_off
    assert "DBUS_SESSION_BUS_ADDRESS" not in feature_env_var_names(enabled)

    enabled["dbus"] = True
    sources_on = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert "/run/dbus/system_bus_socket" in sources_on
    assert str(runtime_dir / "bus") in sources_on
    assert "DBUS_SESSION_BUS_ADDRESS" in feature_env_var_names(enabled)


def test_user_and_xdg_open_features(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    enabled = {name: False for name in FEATURE_NAMES}
    sources_off = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(home / ".local") not in sources_off
    assert str(home / ".cache") not in sources_off
    assert "/usr/libexec/flatpak-xdg-utils/xdg-open" not in sources_off

    enabled["user"] = True
    enabled["xdg-open"] = True
    sources_on = {getattr(b, "source", None) for b in feature_binds(enabled)}
    assert str(home / ".local") in sources_on
    assert str(home / ".cache") in sources_on
    assert "/usr/libexec/flatpak-xdg-utils/xdg-open" in sources_on


def test_locale_and_term_env_features() -> None:
    enabled = {name: False for name in FEATURE_NAMES}
    names_off = feature_env_var_names(enabled)
    assert "LANG" not in names_off
    assert "TERM" not in names_off
    assert "EDITOR" not in names_off
    assert "HOME" in names_off  # base

    enabled["locale"] = True
    enabled["term"] = True
    names_on = feature_env_var_names(enabled)
    assert "LANG" in names_on
    assert "LC_NUMERIC" in names_on
    assert "LC_TIME" in names_on
    assert "COLORTERM" in names_on
    assert "EDITOR" in names_on
    assert "TERM" in names_on
    assert "TERMINFO" in names_on
    assert "TERM_PROGRAM" in names_on


def test_feature_env_vars_follow_topics() -> None:
    enabled = {name: False for name in FEATURE_NAMES}
    enabled["python"] = True
    names = feature_env_var_names(enabled)
    assert "VIRTUAL_ENV" in names
    assert "DOCKER_HOST" not in names
    assert "DBUS_SESSION_BUS_ADDRESS" not in names
    assert "LANG" not in names
    assert "TERM" not in names
    assert "HOME" in names  # base


def test_format_features_help_lists_topics() -> None:
    text = format_features_help()
    assert "cursor" in text
    assert "python" in text
    assert "rust" in text
    assert "gui" in text
    assert "xdg-open" in text
    assert "user" in text
    assert "locale" in text
    assert "term" in text
    assert "default: on" in text
    assert "buddelkiste.features:CURSOR" in text
    assert "buddelkiste.features:PYTHON" in text
    assert "buddelkiste.features:RUST" in text


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
