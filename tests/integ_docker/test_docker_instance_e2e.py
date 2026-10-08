"""Host-only docker-instance e2e (skipped without rootlesskit / subuid)."""

from __future__ import annotations

import http.client
import os
import socket
import subprocess
import textwrap
import uuid
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


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 30) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


def _buildx_available() -> bool:
    proc = subprocess.run(
        ["docker", "buildx", "version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode == 0


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
    # Docker CLI 29 picks secretservice when the config has no auths. That
    # helper aborts if the secret service is down, so pulls never start.
    # An auth map entry selects the file store and allows anonymous pulls.
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    docker_cfg = home / ".docker"
    docker_cfg.mkdir()
    (docker_cfg / "config.json").write_text(
        '{"auths":{"https://index.docker.io/v1/":{}}}\n',
        encoding="utf-8",
    )
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


def test_instance_container_dns_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bridge containers must reach DNS (iptables + ip_forward + host --dns)."""
    _home, run, _project = _prepare_env(tmp_path, monkeypatch)
    cfg = DockerInstanceConfig(
        data_root=tmp_path / "data-dns",
        fs="project",
        net="userspace",
        proxy=True,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / "dns") as args:
        host = _docker_host_from_args(args)
        # Pull may need network; skip offline rather than fail the suite.
        pull = _docker(host, "pull", ALPINE, timeout=180)
        if pull.returncode != 0:
            pytest.skip(f"pull needs network: {(pull.stdout + pull.stderr)[-300:]}")
        proc = _docker(
            host,
            "run",
            "--rm",
            ALPINE,
            "getent",
            "hosts",
            "deb.debian.org",
            timeout=60,
        )
        if proc.returncode != 0:
            detail = proc.stderr + proc.stdout
            log_path = run / "dns" / "dockerd.log"
            if log_path.is_file():
                detail += "\n--- dockerd.log ---\n" + log_path.read_text(
                    encoding="utf-8", errors="replace"
                )[-3000:]
            pytest.fail(detail)
        assert proc.stdout.strip()


def test_instance_proxy_allows_buildkit_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BuildKit needs POST /session through the proxy (not a policy 403)."""
    _home, run, _project = _prepare_env(tmp_path, monkeypatch)
    cfg = DockerInstanceConfig(
        data_root=tmp_path / "data-session",
        fs="project",
        net="userspace",
        proxy=True,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / "session") as args:
        host = _docker_host_from_args(args)
        sock = host.removeprefix("unix://")
        session = "bktest" + uuid.uuid4().hex[:16]
        conn = _UnixHTTPConnection(sock, timeout=30)
        try:
            conn.putrequest("POST", "/session")
            conn.putheader("Connection", "Upgrade")
            conn.putheader("Upgrade", "h2c")
            conn.putheader("X-Docker-Expose-Session-Uuid", session)
            conn.putheader("X-Docker-Expose-Session-Name", "bk-e2e")
            conn.putheader("X-Docker-Expose-Session-Sharedkey", "bk-e2e")
            conn.endheaders()
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "replace")
        finally:
            conn.close()
        assert resp.status != 403, body
        assert "API category 'session' is denied" not in body


def test_instance_buildkit_cli_build_when_buildx_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not _buildx_available():
        pytest.skip("docker buildx not installed on host")
    _home, run, project = _prepare_env(tmp_path, monkeypatch)
    dockerfile = textwrap.dedent(
        f"""\
        FROM {ALPINE}
        RUN echo built-with-buildkit > /marker
        """
    )
    (project / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    cfg = DockerInstanceConfig(
        data_root=tmp_path / "data-buildkit",
        fs="project",
        net="userspace",
        proxy=True,
    )
    with docker_instance_setup(instance=cfg, runtime_dir=run / "buildkit") as args:
        host = _docker_host_from_args(args)
        env = {
            **os.environ,
            "DOCKER_HOST": host,
            "DOCKER_BUILDKIT": "1",
        }
        build = subprocess.run(
            ["docker", "build", "-t", "bk-instance-buildkit:latest", "."],
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
        run_proc = _docker(host, "run", "--rm", "bk-instance-buildkit:latest", "cat", "/marker")
        assert run_proc.returncode == 0, run_proc.stderr + run_proc.stdout
        assert "built-with-buildkit" in run_proc.stdout


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
