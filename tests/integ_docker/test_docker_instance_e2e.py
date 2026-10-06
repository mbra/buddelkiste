"""Host-only docker-instance e2e (skipped without rootlesskit / subuid)."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from buddelkiste.docker_instance import (
    INSTANCE_API_DENY,
    DockerInstanceConfig,
    docker_instance_setup,
)
from buddelkiste.docker_proxy import DEFAULT_DENY_HOST_CONFIG, DockerProxyPolicy

pytestmark = pytest.mark.requires_rootless_docker

ALPINE = "alpine:3.20"


def _docker_host_from_args(args: list[str] | tuple[str, ...]) -> str:
    for i, arg in enumerate(args):
        if arg == "--setenv" and i + 2 < len(args) and args[i + 1] == "DOCKER_HOST":
            return str(args[i + 2])
    raise AssertionError(f"DOCKER_HOST missing from setup args: {args!r}")


def _prepare_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path]:
    """Isolate HOME / XDG and use tmp_path as the project root."""
    home = tmp_path / "home"
    home.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (project / ".buddelkiste.toml").write_text(
        "features = { docker = false, docker-instance = true }\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.chdir(project)
    return home, run, project


def _docker(
    host: str,
    *argv: str,
    timeout: float = 120,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DOCKER_HOST": host}
    return subprocess.run(
        ["docker", *argv],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        cwd=cwd,
    )


@pytest.mark.parametrize("fs_mode", ["host", "project", "data"])
def test_instance_docker_version_per_fs_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fs_mode: str
) -> None:
    """Daemon must come up under every fs jail (project binds /etc/subuid)."""
    _home, run, _project = _prepare_env(tmp_path, monkeypatch)
    data = tmp_path / f"data-{fs_mode}"
    cfg = DockerInstanceConfig(
        data_root=data,
        fs=fs_mode,
        net="userspace",
        proxy=True,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / fs_mode) as args:
        host = _docker_host_from_args(args)
        proc = _docker(host, "version", "--format", "{{.Server.Version}}")
        log_path = run / fs_mode / "dockerd.log"
        detail = proc.stderr + proc.stdout
        if proc.returncode != 0 and log_path.is_file():
            detail += "\n--- dockerd.log ---\n" + log_path.read_text(
                encoding="utf-8", errors="replace"
            )[-4000:]
        assert proc.returncode == 0, detail
        assert proc.stdout.strip()
        # Store stays under the dedicated data_root, not the user-global engine.
        assert data.is_dir()


def test_instance_proxy_denies_privileged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home, run, _project = _prepare_env(tmp_path, monkeypatch)
    cfg = DockerInstanceConfig(
        data_root=tmp_path / "data-priv",
        fs="project",
        net="userspace",
        proxy=True,
        policy=DockerProxyPolicy(
            images=("*",),
            api_deny=INSTANCE_API_DENY,
            deny_host_config=DEFAULT_DENY_HOST_CONFIG,
            on_unknown_image="deny",
        ),
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / "priv") as args:
        host = _docker_host_from_args(args)
        # Pull may fail offline; privileged deny should still trigger on create.
        proc = _docker(
            host,
            "run",
            "--rm",
            "--privileged",
            ALPINE,
            "true",
            timeout=180,
        )
        assert proc.returncode != 0
        combined = (proc.stdout + proc.stderr).lower()
        assert (
            "privileged" in combined
            or "hostconfig" in combined
            or "403" in combined
            or "denied" in combined
        ), combined


def test_instance_build_and_run_under_project_jail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fs=project + allow build: the path that agents hit for fixture images."""
    _home, run, project = _prepare_env(tmp_path, monkeypatch)
    dockerfile = textwrap.dedent(
        f"""\
        FROM {ALPINE}
        RUN echo built-in-instance > /marker
        CMD cat /marker
        """
    )
    (project / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    cfg = DockerInstanceConfig(
        data_root=tmp_path / "data-build",
        fs="project",
        net="userspace",
        proxy=True,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / "build") as args:
        host = _docker_host_from_args(args)
        # Directory context + legacy builder: BuildKit/buildx is not required in
        # the rootless instance. Proxy must forward chunked build bodies intact.
        env = {
            **os.environ,
            "DOCKER_HOST": host,
            "DOCKER_BUILDKIT": "0",
        }
        build = subprocess.run(
            ["docker", "build", "-t", "bk-instance-smoke:latest", "."],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            cwd=project,
        )
        if build.returncode != 0:
            combined = build.stdout + build.stderr
            if "network" in combined.lower() or "timeout" in combined.lower():
                pytest.skip(f"build needs network: {combined[-500:]}")
            pytest.fail(combined)
        run_proc = _docker(
            host,
            "run",
            "--rm",
            "bk-instance-smoke:latest",
            timeout=120,
        )
        assert run_proc.returncode == 0, run_proc.stderr + run_proc.stdout
        assert "built-in-instance" in run_proc.stdout


def test_instance_without_proxy_exposes_raw_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home, run, _project = _prepare_env(tmp_path, monkeypatch)
    cfg = DockerInstanceConfig(
        data_root=tmp_path / "data-raw",
        fs="host",
        net="userspace",
        proxy=False,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / "raw") as args:
        host = _docker_host_from_args(args)
        assert host.startswith("unix://")
        sock = Path(host.removeprefix("unix://"))
        assert sock.exists()
        proc = _docker(host, "info", "--format", "{{.ID}}")
        assert proc.returncode == 0, proc.stderr + proc.stdout
        assert proc.stdout.strip()
