from __future__ import annotations

import tomllib
from pathlib import Path

import click
import pytest

from buddelkiste.cli import (
    ROBindConfig,
    RWBindConfig,
    add_bind_to_config,
    ensure_cwd_in_sandbox,
    get_binds,
    get_env_args,
    load_config,
)
from buddelkiste.features import FEATURE_NAMES


def test_load_config_missing_returns_empty(tmp_config: Path) -> None:
    assert load_config() == {}


def test_load_config_reads_toml(tmp_config: Path) -> None:
    tmp_config.write_text(
        '[[binds]]\nsource = "/tmp"\nread_only = false\n\n'
        '[[envvars]]\nname = "FOO"\nvalue = "bar"\n',
        encoding="utf-8",
    )
    config = load_config()
    assert config["binds"][0]["source"] == "/tmp"
    assert config["binds"][0]["read_only"] is False
    assert config["envvars"][0] == {"name": "FOO", "value": "bar"}


def test_add_bind_to_config_creates_file(tmp_config: Path, tmp_path: Path) -> None:
    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, read_only=False)

    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert data["binds"] == [{"source": str(source), "read_only": False}]


def test_add_bind_to_config_appends_with_separator(
    tmp_config: Path, tmp_path: Path
) -> None:
    tmp_config.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.write_text('[[envvars]]\nname = "A"\n', encoding="utf-8")

    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, read_only=True)

    text = tmp_config.read_text(encoding="utf-8")
    assert text.startswith('[[envvars]]\nname = "A"\n\n[[binds]]\n')
    data = tomllib.loads(text)
    assert data["binds"][0]["read_only"] is True


def test_get_env_args_shares_known_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm-test")
    monkeypatch.delenv("ASDF_DIR", raising=False)
    args = list(get_env_args({}))
    term = next(
        (args[i : i + 3] for i in range(0, len(args), 3) if args[i + 1] == "TERM"),
        None,
    )
    assert term == ["--setenv", "TERM", "xterm-test"]
    assert "ASDF_DIR" not in args


def test_get_env_args_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FROM_ENV", "env-value")
    args = list(
        get_env_args(
            {
                "envvars": [
                    {"name": "EXPLICIT", "value": "set"},
                    {"name": "FROM_ENV"},
                ]
            }
        )
    )
    # Find the config-driven entries at the end.
    assert args[-6:] == [
        "--setenv",
        "EXPLICIT",
        "set",
        "--setenv",
        "FROM_ENV",
        "env-value",
    ]


def test_ensure_cwd_covered_is_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    binds: list = [ROBindConfig(tmp_path)]
    ensure_cwd_in_sandbox(binds)
    assert len(binds) == 1


def test_ensure_cwd_noninteractive_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: False)
    with pytest.raises(click.ClickException, match="not available inside the sandbox"):
        ensure_cwd_in_sandbox([])


def test_ensure_cwd_once_adds_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("click.prompt", lambda *a, **k: "once")
    monkeypatch.setattr("click.confirm", lambda *a, **k: True)

    binds: list = []
    ensure_cwd_in_sandbox(binds)
    assert len(binds) == 1
    assert isinstance(binds[0], RWBindConfig)
    assert Path(binds[0].source) == tmp_path


def test_ensure_cwd_always_persists(
    tmp_path: Path, tmp_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("click.prompt", lambda *a, **k: "always")
    monkeypatch.setattr("click.confirm", lambda *a, **k: False)

    binds: list = []
    ensure_cwd_in_sandbox(binds)
    assert isinstance(binds[0], ROBindConfig)
    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert data["binds"][0]["source"] == str(tmp_path)
    assert data["binds"][0]["read_only"] is True


def test_ensure_cwd_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.is_interactive", lambda: True)
    monkeypatch.setattr("click.prompt", lambda *a, **k: "no")
    with pytest.raises(click.Abort):
        ensure_cwd_in_sandbox([])


def test_add_bind_to_config_escapes_special_chars(
    tmp_config: Path, tmp_path: Path
) -> None:
    source = tmp_path / 'proj"quote\\slash'
    source.mkdir()
    add_bind_to_config(source, read_only=True)
    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert data["binds"][0]["source"] == str(source)


def test_permanent_bind_roundtrip(
    tmp_config: Path,
    tmp_path: Path,
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, read_only=False)

    config = load_config()
    binds = get_binds(config, {name: False for name in FEATURE_NAMES})
    assert any(
        isinstance(bind, RWBindConfig) and Path(bind.source) == source for bind in binds
    )
