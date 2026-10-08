"""which() searches sbin directories that a user PATH omits."""

from __future__ import annotations

from pathlib import Path

import pytest

from buddelkiste.which import which


def test_which_finds_sbin_when_path_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    tool = sbin / "iptables"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setattr("buddelkiste.which.SBIN_DIRS", (str(sbin),))
    assert which("iptables") == str(tool)
    assert which("iptables", path="/usr/bin") == str(tool)


def test_which_prefers_path_over_sbin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bindir = tmp_path / "bin"
    sbin = tmp_path / "sbin"
    bindir.mkdir()
    sbin.mkdir()
    for directory in (bindir, sbin):
        tool = directory / "iptables"
        tool.write_text("#!/bin/sh\n", encoding="utf-8")
        tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr("buddelkiste.which.SBIN_DIRS", (str(sbin),))
    assert which("iptables") == str(bindir / "iptables")
    assert which("missing-tool") is None
