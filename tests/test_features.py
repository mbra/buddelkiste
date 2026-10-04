from __future__ import annotations

from pathlib import Path

import click
import pytest

from buddelkiste.features import (
    FEATURE_NAMES,
    FEATURES,
    base_binds,
    cursor_binds,
    enabled_feature_names,
    feature_binds,
    feature_env_var_names,
    format_features_help,
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


def test_resolve_features_config_and_cli_precedence() -> None:
    enabled = resolve_features(
        {"features": {"gui": False, "python": False}},
        enable=["python"],
        disable=["ssh"],
    )
    assert enabled["gui"] is False
    assert enabled["python"] is True  # CLI enable wins over config
    assert enabled["ssh"] is False
    assert enabled["cursor"] is True


def test_resolve_features_unknown_raises() -> None:
    with pytest.raises(click.ClickException, match="Unknown feature in config"):
        resolve_features({"features": {"nope": True}})
    with pytest.raises(click.ClickException, match="Unknown feature: nope"):
        resolve_features({}, enable=["nope"])
    with pytest.raises(click.ClickException, match="Unknown feature: nope"):
        resolve_features({}, disable=["nope"])


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
