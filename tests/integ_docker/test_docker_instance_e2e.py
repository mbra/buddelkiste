"""Optional smoke test for docker-instance (skipped without rootlesskit)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from buddelkiste.docker_instance import DockerInstanceConfig, docker_instance_setup

pytestmark = pytest.mark.requires_rootless_docker


def _docker_host_from_args(args: list[str] | tuple[str, ...]) -> str:
    for i, arg in enumerate(args):
        if arg == "--setenv" and i + 2 < len(args) and args[i + 1] == "DOCKER_HOST":
            return str(args[i + 2])
    raise AssertionError(f"DOCKER_HOST missing from setup args: {args!r}")


def test_instance_docker_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    data = tmp_path / "data"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.chdir(tmp_path)

    cfg = DockerInstanceConfig(
        data_root=data,
        fs="host",
        net="userspace",
        proxy=True,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run) as args:
        host = _docker_host_from_args(args)
        env = {**os.environ, "DOCKER_HOST": host}
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout.strip()
