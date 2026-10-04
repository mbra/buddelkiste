from __future__ import annotations

import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from buddelkiste.cli import RWBindConfig, cli


@pytest.fixture
def prepared_cwd(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.get_binds", lambda config, enabled=None: [RWBindConfig(tmp_path)])
    return tmp_path


def test_cli_runs_bwrap_with_command(
    prepared_cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=42)

    monkeypatch.setattr("buddelkiste.cli.subprocess.run", fake_run)

    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "/bin/echo", "hello"])
    assert result.exit_code == 42, result.output
    assert captured["args"][:1] == ["bwrap"]
    assert captured["args"][-3:] == ["--", "/bin/echo", "hello"]
    assert "SSH_AUTH_SOCK" not in captured["args"]


def test_cli_shell_fallback_when_no_args(
    prepared_cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.cli.subprocess.run", fake_run)

    result = CliRunner().invoke(cli, ["--no-feature", "ssh"])
    assert result.exit_code == 0, result.output
    shell = pwd.getpwuid(os.getuid()).pw_shell
    assert captured["args"][-4:] == ["--", shell, "-si", "--"]


def test_cli_forwards_help_to_command(
    prepared_cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.cli.subprocess.run", fake_run)

    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "cursor-agent", "--help"])
    assert result.exit_code == 0, result.output
    assert captured["args"][-3:] == ["--", "cursor-agent", "--help"]
    assert "Sandbox a command using bubblewrap" not in result.output


def test_cli_list_features() -> None:
    result = CliRunner().invoke(cli, ["--list-features"])
    assert result.exit_code == 0
    assert "cursor" in result.output
    assert "python" in result.output


def test_cli_disables_feature_via_flag(
    prepared_cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.cli.subprocess.run", fake_run)
    # Force python env into the process, then disable the feature.
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/venv")

    result = CliRunner().invoke(cli, ["--no-feature", "python", "--no-feature", "ssh", "/bin/true"])
    assert result.exit_code == 0, result.output
    assert "VIRTUAL_ENV" not in captured["args"]


def test_cli_uses_per_executable_features(
    prepared_cwd: Path,
    tmp_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_config.write_text(
        'features = ["git"]\n\n'
        '[executables."/bin/true"]\n'
        'features = ["python"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/venv")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/docker.sock")

    captured: dict = {}

    def fake_run(args, check=False):
        captured["args"] = list(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr("buddelkiste.cli.subprocess.run", fake_run)

    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "/bin/true"])
    assert result.exit_code == 0, result.output
    assert "VIRTUAL_ENV" in captured["args"]
    assert "DOCKER_HOST" not in captured["args"]
