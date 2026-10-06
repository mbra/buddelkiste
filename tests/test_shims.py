from __future__ import annotations

import stat
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from buddelkiste.cli import cli
from buddelkiste.shims import (
    SHIM_MARKER,
    SHIM_MARKER_PREFIX,
    check_shims,
    install_shims,
    install_shims_from_config,
    is_our_shim,
    render_shim,
    shim_decisions_from_config,
    shim_names_from_config,
    xdg_bin_dir,
)


def test_xdg_bin_dir_default(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_BIN_HOME", raising=False)
    assert xdg_bin_dir() == tmp_path / "home" / ".local" / "bin"


def test_xdg_bin_dir_override(monkeypatch, tmp_path: Path) -> None:
    custom = tmp_path / "bin"
    monkeypatch.setenv("XDG_BIN_HOME", str(custom))
    assert xdg_bin_dir() == custom


def test_shim_names_from_config_dedupes_basenames() -> None:
    names = shim_names_from_config(
        {
            "executables": {
                "cursor-agent": {},
                "/opt/bin/cursor-agent": {"features": ["cursor"]},
                "/usr/bin/python": {},
            }
        }
    )
    assert names == ["cursor-agent", "python"]


def test_shim_names_respects_global_and_per_executable_toggles() -> None:
    assert shim_names_from_config(
        {
            "shims": False,
            "executables": {
                "a": {},
                "b": {"shim": True},
                "c": {"shim": False},
            },
        }
    ) == ["b"]

    assert shim_names_from_config(
        {
            "executables": {
                "a": {},
                "b": {"shim": False},
            },
        }
    ) == ["a"]

    decisions = shim_decisions_from_config(
        {
            "shims": True,
            "executables": {"tool": {"shim": False}},
        }
    )
    assert decisions == {"tool": False}


def test_shim_toggle_rejects_non_bool() -> None:
    with pytest.raises(click.ClickException, match="shims"):
        shim_names_from_config({"shims": "yes", "executables": {"a": {}}})
    with pytest.raises(click.ClickException, match="shim"):
        shim_names_from_config({"executables": {"a": {"shim": 1}}})


def test_install_from_config_removes_disabled(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    install_shims(["keep", "drop"], bin_dir=bin_dir)
    assert (bin_dir / "drop").exists()

    results = install_shims_from_config(
        {
            "executables": {
                "keep": {},
                "drop": {"shim": False},
            }
        },
        bin_dir=bin_dir,
    )
    by_name = {r.name: r for r in results}
    assert by_name["drop"].action == "removed"
    assert not (bin_dir / "drop").exists()
    assert by_name["keep"].action == "unchanged"
    assert is_our_shim(bin_dir / "keep")


def test_cli_shims_respect_global_off(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_BIN_HOME", raising=False)

    tmp_config.write_text(
        "shims = false\n\n"
        "[executables.cursor-agent]\n"
        'features = ["cursor"]\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["shims", "install"])
    assert result.exit_code == 0, result.output
    assert "disabled" in result.output
    assert not (home / ".local" / "bin" / "cursor-agent").exists()

    check = CliRunner().invoke(cli, ["shims", "check"])
    assert check.exit_code == 0, check.output
    assert "disabled" in check.output


def test_render_shim_has_marker_and_bk_run() -> None:
    body = render_shim()
    assert body.startswith("#!/bin/sh\n")
    assert SHIM_MARKER in body
    assert 'exec "$bk" run "$real" "$@"' in body
    assert "command -v" in body  # used to locate bk
    assert '[ -f "$candidate" ]' in body


def test_is_our_shim_detects_marker(tmp_path: Path) -> None:
    ours = tmp_path / "tool"
    ours.write_text(render_shim(), encoding="utf-8")
    foreign = tmp_path / "other"
    foreign.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    assert is_our_shim(ours) is True
    assert is_our_shim(foreign) is False
    assert is_our_shim(tmp_path / "missing") is False


def test_install_creates_executable_shims(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    results = install_shims(["cursor-agent", "python"], bin_dir=bin_dir)
    assert [r.action for r in results] == ["created", "created"]
    for name in ("cursor-agent", "python"):
        path = bin_dir / name
        assert is_our_shim(path)
        assert path.stat().st_mode & stat.S_IXUSR
        assert SHIM_MARKER_PREFIX in path.read_text(encoding="utf-8")


def test_install_skips_foreign_and_updates_ours(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    foreign = bin_dir / "python"
    foreign.write_text("#!/bin/sh\necho stock\n", encoding="utf-8")
    ours = bin_dir / "cursor-agent"
    ours.write_text(
        "#!/bin/sh\n# buddelkiste-shim:0\nold\n",
        encoding="utf-8",
    )

    results = {r.name: r for r in install_shims(["python", "cursor-agent"], bin_dir=bin_dir)}
    assert results["python"].action == "skipped"
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho stock\n"
    assert results["cursor-agent"].action == "updated"
    assert is_our_shim(ours)
    assert SHIM_MARKER in ours.read_text(encoding="utf-8")

    again = install_shims(["cursor-agent"], bin_dir=bin_dir)
    assert again[0].action == "unchanged"


def test_check_ok_when_shim_first(tmp_path: Path) -> None:
    shim_dir = tmp_path / "shims"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=shim_dir)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{shim_dir}:{real_dir}"
    assert check_shims(["tool"], bin_dir=shim_dir, path_value=path) == []


def test_check_warns_when_original_first(tmp_path: Path) -> None:
    shim_dir = tmp_path / "shims"
    real_dir = tmp_path / "real"
    install_shims(["tool"], bin_dir=shim_dir)
    real_dir.mkdir()
    real = real_dir / "tool"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    path = f"{real_dir}:{shim_dir}"
    issues = check_shims(["tool"], bin_dir=shim_dir, path_value=path)
    assert len(issues) == 1
    assert issues[0].name == "tool"
    assert "bypass the sandbox" in issues[0].message
    assert str(real) in issues[0].message


def test_check_warns_when_bin_not_on_path(tmp_path: Path) -> None:
    shim_dir = tmp_path / "shims"
    install_shims(["tool"], bin_dir=shim_dir)
    issues = check_shims(["tool"], bin_dir=shim_dir, path_value="/usr/bin")
    assert any(i.name == "*" for i in issues)
    assert any("not reachable via PATH" in i.message for i in issues)


def test_cli_shims_install_and_check(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = home / ".local" / "bin"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_BIN_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin")

    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["shims", "install"])
    assert result.exit_code == 0, result.output
    assert "created" in result.output
    shim = bin_dir / "cursor-agent"
    assert is_our_shim(shim)

    # No real binary on PATH yet — still OK if our shim is the first hit.
    # Make the shim executable-discoverable (already is) and check.
    check = runner.invoke(cli, ["shims", "check"])
    assert check.exit_code == 0, check.output
    assert "OK:" in check.output


def test_cli_shims_check_fails_on_shadow(
    tmp_path: Path,
    tmp_config: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = home / ".local" / "bin"
    real_dir = tmp_path / "elsewhere"
    real_dir.mkdir()
    real = real_dir / "cursor-agent"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_BIN_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{real_dir}:{bin_dir}")

    tmp_config.write_text(
        "[executables.cursor-agent]\nfeatures = [\"cursor\"]\n",
        encoding="utf-8",
    )
    CliRunner().invoke(cli, ["shims", "install"])

    result = CliRunner().invoke(cli, ["shims", "check"])
    assert result.exit_code == 1
    assert "bypass the sandbox" in result.output
