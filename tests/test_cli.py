from __future__ import annotations

import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from buddelkiste.cli import RWBindConfig, cli
from buddelkiste.network import NetworkConfig


@pytest.fixture
def prepared_cwd(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("buddelkiste.cli.get_binds", lambda config, enabled=None: [RWBindConfig(tmp_path)])
    return tmp_path


@pytest.fixture
def fake_bwrap(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {"nets": [], "args": []}

    def fake_run(bwrap_args, net):
        captured["args"] = list(bwrap_args)
        captured["nets"].append(net)
        if bwrap_args[-2:] == ["/bin/echo", "hello"]:
            return 42
        return 0

    monkeypatch.setattr("buddelkiste.cli.run_bwrap", fake_run)
    return captured


def test_cli_runs_bwrap_with_command(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "/bin/echo", "hello"])
    assert result.exit_code == 42, result.output
    assert fake_bwrap["args"][:1] == ["bwrap"]
    assert "--share-net" not in fake_bwrap["args"]  # added inside run_bwrap for host
    assert fake_bwrap["args"][-3:] == ["--", "/bin/echo", "hello"]
    assert fake_bwrap["nets"][0].mode == "host"
    assert "SSH_AUTH_SOCK" not in fake_bwrap["args"]


def test_cli_shell_fallback_when_no_args(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(cli, ["--no-feature", "ssh"])
    assert result.exit_code == 0, result.output
    shell = pwd.getpwuid(os.getuid()).pw_shell
    assert fake_bwrap["args"][-4:] == ["--", shell, "-si", "--"]


def test_cli_forwards_help_to_command(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "cursor-agent", "--help"])
    assert result.exit_code == 0, result.output
    assert fake_bwrap["args"][-3:] == ["--", "cursor-agent", "--help"]
    assert "Sandbox a command using bubblewrap" not in result.output


def test_cli_list_features() -> None:
    result = CliRunner().invoke(cli, ["--list-features"])
    assert result.exit_code == 0
    assert "cursor" in result.output
    assert "python" in result.output


def test_cli_disables_feature_via_flag(
    prepared_cwd: Path,
    fake_bwrap,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/venv")

    result = CliRunner().invoke(cli, ["--no-feature", "python", "--no-feature", "ssh", "/bin/true"])
    assert result.exit_code == 0, result.output
    assert "VIRTUAL_ENV" not in fake_bwrap["args"]


def test_cli_uses_per_executable_features(
    prepared_cwd: Path,
    tmp_config: Path,
    fake_bwrap,
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

    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "/bin/true"])
    assert result.exit_code == 0, result.output
    assert "VIRTUAL_ENV" in fake_bwrap["args"]
    assert "DOCKER_HOST" not in fake_bwrap["args"]


def test_cli_network_filter_flags(
    prepared_cwd: Path,
    fake_bwrap,
) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "--no-feature",
            "ssh",
            "--network",
            "filter",
            "--net-policy",
            "deny",
            "--net-allow",
            "1.1.1.1/32",
            "--net-deny",
            "169.254.169.254/32",
            "/bin/true",
        ],
    )
    assert result.exit_code == 0, result.output
    net = fake_bwrap["nets"][0]
    assert isinstance(net, NetworkConfig)
    assert net.mode == "filter"
    assert net.policy == "deny"
    assert net.allow == ["1.1.1.1/32"]
    assert net.deny == ["169.254.169.254/32"]


def test_cli_network_none_mode(prepared_cwd: Path, fake_bwrap) -> None:
    result = CliRunner().invoke(cli, ["--no-feature", "ssh", "--network", "none", "/bin/true"])
    assert result.exit_code == 0, result.output
    assert fake_bwrap["nets"][0].mode == "none"
