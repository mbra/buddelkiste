from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_env_is_cleared_except_shared(run_bk, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BUDDELKISTE_INTEG_SECRET", "should-not-leak")
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        'printf "%s" "${BUDDELKISTE_INTEG_SECRET-UNSET}"',
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "UNSET"


def test_workdir_bind_is_writable(run_bk, integ_workspace: dict[str, Path]) -> None:
    out = integ_workspace["work"] / "written.txt"
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"echo nested > '{out}'",
    )
    assert proc.returncode == 0, proc.stderr
    assert out.read_text(encoding="utf-8") == "nested\n"


def test_unbound_host_path_not_visible(run_bk, tmp_path: Path) -> None:
    secret = tmp_path / "secret-outside"
    secret.mkdir()
    marker = secret / "marker"
    marker.write_text("host-only\n", encoding="utf-8")

    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"test -e '{marker}'; echo VISIBLE:$?",
    )
    assert proc.returncode == 0, proc.stderr
    assert "VISIBLE:0" not in proc.stdout


def test_optional_features_disabled_by_empty_list(run_bk) -> None:
    # With features=[], SSH_AUTH_SOCK from an outer agent must not be injected.
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        'printf "%s" "${SSH_AUTH_SOCK-UNSET}"',
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "UNSET"


def test_project_config_is_hidden_inside_sandbox(
    run_bk, integ_workspace: dict[str, Path]
) -> None:
    from buddelkiste.cli import PROJECT_CONFIG_NAME

    project = integ_workspace["work"] / PROJECT_CONFIG_NAME
    project.write_text(
        'features = []\n[[envvars]]\nname = "FROM_PROJECT"\nvalue = "yes"\n',
        encoding="utf-8",
    )
    # Host file remains readable; sandbox sees /dev/null over the same path.
    assert "FROM_PROJECT" in project.read_text(encoding="utf-8")

    env_proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        'printf "%s" "${FROM_PROJECT-UNSET}"',
    )
    assert env_proc.returncode == 0, env_proc.stderr
    assert env_proc.stdout == "yes"

    hide_proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"wc -c < '{project}'",
    )
    assert hide_proc.returncode == 0, hide_proc.stderr
    assert hide_proc.stdout.strip() == "0"
