from __future__ import annotations

import tomllib
from pathlib import Path

import click
import pytest

from buddelkiste.cli import (
    PROJECT_CONFIG_NAME,
    ROBindConfig,
    RWBindConfig,
    add_bind_to_config,
    ensure_cwd_in_sandbox,
    find_project_config,
    get_binds,
    get_env_args,
    load_config,
    merge_config,
    project_config_hide_args,
)
from buddelkiste.features import FEATURE_NAMES


def test_load_config_missing_returns_empty(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config() == {}


def test_load_config_reads_toml(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    tmp_config.write_text(
        '[[binds]]\nsource = "/tmp"\nmode = "rw"\n\n'
        '[[envvars]]\nname = "FOO"\nvalue = "bar"\n',
        encoding="utf-8",
    )
    config = load_config()
    assert config["binds"][0]["source"] == "/tmp"
    assert config["binds"][0]["mode"] == "rw"
    assert config["envvars"][0] == {"name": "FOO", "value": "bar"}


def test_find_project_config_walks_ancestors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    nested = root / "pkg" / "sub"
    nested.mkdir(parents=True)
    project = root / PROJECT_CONFIG_NAME
    project.write_text("features = []\n", encoding="utf-8")
    monkeypatch.chdir(nested)
    assert find_project_config() == project.resolve()


def test_merge_config_concatenates_lists_and_overrides_features() -> None:
    base = {
        "features": ["git"],
        "binds": [{"source": "/a", "mode": "ro"}],
        "envvars": [{"name": "A"}],
        "network": {
            "mode": "host",
            "presets": {"corp": ["10.0.0.0/8"]},
        },
        "feature": {"rust": {"env": ["CARGO_HOME"]}},
        "executables": {
            "python": {"features": ["python"], "network": {"mode": "none"}},
        },
    }
    overlay = {
        "features": {"gui": False},
        "binds": [{"source": "/b", "mode": "rw"}],
        "envvars": [{"name": "B"}],
        "network": {
            "mode": "filter",
            "presets": {"labs": ["10.1.0.0/16"]},
        },
        "feature": {"go": {"env": ["GOPATH"]}},
        "executables": {
            "python": {"network": {"allow": ["1.1.1.1/32"]}},
        },
    }
    merged = merge_config(base, overlay)
    assert merged["features"] == {"gui": False}
    assert merged["binds"] == [
        {"source": "/a", "mode": "ro"},
        {"source": "/b", "mode": "rw"},
    ]
    assert merged["envvars"] == [{"name": "A"}, {"name": "B"}]
    assert merged["network"]["mode"] == "filter"
    assert merged["network"]["presets"] == {
        "corp": ["10.0.0.0/8"],
        "labs": ["10.1.0.0/16"],
    }
    assert set(merged["feature"]) == {"rust", "go"}
    assert merged["executables"]["python"]["features"] == ["python"]
    assert merged["executables"]["python"]["network"] == {
        "mode": "none",
        "allow": ["1.1.1.1/32"],
    }


def test_load_config_merges_project_over_user(
    tmp_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    tmp_config.write_text(
        'features = ["git"]\n[[binds]]\nsource = "/user"\nmode = "ro"\n',
        encoding="utf-8",
    )
    (tmp_path / PROJECT_CONFIG_NAME).write_text(
        'features = ["python"]\n[[binds]]\nsource = "/project"\nmode = "rw"\n',
        encoding="utf-8",
    )
    config = load_config()
    assert config["features"] == ["python"]
    assert config["binds"] == [
        {"source": "/user", "mode": "ro"},
        {"source": "/project", "mode": "rw"},
    ]


def test_project_config_hide_args(tmp_path: Path) -> None:
    path = tmp_path / PROJECT_CONFIG_NAME
    path.write_text("features = []\n", encoding="utf-8")
    with project_config_hide_args(None) as args:
        assert args == []
    with project_config_hide_args(path) as args:
        assert args[0] == "--ro-bind"
        assert Path(args[1]).is_file()
        assert Path(args[1]).read_bytes() == b""
        assert args[2] == str(path.resolve())


def test_add_bind_to_config_creates_file(tmp_config: Path, tmp_path: Path) -> None:
    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, mode="rw")

    data = tomllib.loads(tmp_config.read_text(encoding="utf-8"))
    assert data["binds"] == [{"source": str(source), "mode": "rw"}]


def test_add_bind_to_config_appends_with_separator(
    tmp_config: Path, tmp_path: Path
) -> None:
    tmp_config.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.write_text('[[envvars]]\nname = "A"\n', encoding="utf-8")

    source = tmp_path / "proj"
    source.mkdir()
    add_bind_to_config(source, mode="ro")

    text = tmp_config.read_text(encoding="utf-8")
    assert text.startswith('[[envvars]]\nname = "A"\n\n[[binds]]\n')
    data = tomllib.loads(text)
    assert data["binds"][0]["mode"] == "ro"


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
    assert data["binds"][0]["mode"] == "ro"


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
    add_bind_to_config(source, mode="ro")
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
    add_bind_to_config(source, mode="rw")

    config = load_config()
    binds = get_binds(config, {name: False for name in FEATURE_NAMES})
    assert any(
        isinstance(bind, RWBindConfig) and Path(bind.source) == source for bind in binds
    )
