from __future__ import annotations

import os
import pwd

import click
import pytest
from click.testing import CliRunner

from buddelkiste.cli import cli, resolve_launch_command


def test_resolve_launch_command_uses_args() -> None:
    assert resolve_launch_command(["/bin/echo", "hi"]) == ["/bin/echo", "hi"]


def test_resolve_launch_command_falls_back_to_shell() -> None:
    shell = pwd.getpwuid(os.getuid()).pw_shell
    assert resolve_launch_command([]) == [shell, "-si", "--"]


@pytest.mark.parametrize("help_arg", ["--help", "-h"])
def test_resolve_launch_command_help_exits(help_arg: str) -> None:
    @click.command(help="wrapper help")
    def dummy() -> None:
        pass

    with dummy.make_context("dummy", []):
        with pytest.raises(SystemExit) as excinfo:
            resolve_launch_command([help_arg])
    assert excinfo.value.code == 0


def test_cli_help_via_args() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Sandbox a command using bubblewrap" in result.output
    assert "--debug" in result.output
