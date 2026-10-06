"""Host-only docker-proxy e2e (skipped inside bwrap / without Docker)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from buddelkiste.docker_proxy import (
    DockerProxyPolicy,
    docker_proxy_setup,
    write_policy_file,
)

pytestmark = pytest.mark.requires_docker

ALPINE = "alpine:3.20"


def _docker_host_from_setup_args(args: list[str] | tuple[str, ...]) -> str:
    for i, arg in enumerate(args):
        if arg == "--setenv" and i + 2 < len(args) and args[i + 1] == "DOCKER_HOST":
            return args[i + 2]
    raise AssertionError(f"DOCKER_HOST missing from setup args: {args!r}")


def _ensure_image(image: str) -> None:
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
    )
    if inspect.returncode == 0:
        return
    pull = subprocess.run(
        ["docker", "pull", image],
        check=False,
        capture_output=True,
        text=True,
    )
    if pull.returncode != 0:
        pytest.skip(f"cannot pull {image}: {pull.stderr}")


def test_proxy_allows_listed_image_via_docker_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    _ensure_image(ALPINE)

    policy = DockerProxyPolicy(images=(ALPINE,))
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        proc = subprocess.run(
            ["docker", "run", "--rm", ALPINE, "echo", "ok-from-proxy"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr
        assert "ok-from-proxy" in proc.stdout


def test_proxy_denies_unlisted_image_via_docker_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    policy = DockerProxyPolicy(images=(ALPINE,), on_unknown_image="deny")
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        proc = subprocess.run(
            ["docker", "run", "--rm", "busybox:1.36", "echo", "should-not-run"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        combined = (proc.stdout or "") + (proc.stderr or "")
        assert "should-not-run" not in combined
        assert "docker-proxy" in combined or "not allowlisted" in combined or "403" in combined


def test_proxy_denies_privileged_even_for_allowlisted_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    _ensure_image(ALPINE)

    policy = DockerProxyPolicy(images=(ALPINE,))
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        proc = subprocess.run(
            ["docker", "run", "--rm", "--privileged", ALPINE, "true"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        combined = (proc.stdout or "") + (proc.stderr or "")
        assert "Privileged" in combined or "HostConfig" in combined or "docker-proxy" in combined


def test_proxy_version_and_info_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    policy = DockerProxyPolicy(images=(ALPINE,))
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        version = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert version.returncode == 0, version.stderr
        assert version.stdout.strip()
        info = subprocess.run(
            ["docker", "info", "--format", "{{.ID}}"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert info.returncode == 0, info.stderr


def test_proxy_loads_policy_from_host_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _ensure_image(ALPINE)

    from buddelkiste.docker_proxy import host_policy_path, project_policy_key

    key = project_policy_key()
    # deny so the unlisted busybox run fails immediately (session would hold).
    write_policy_file(
        host_policy_path(key),
        DockerProxyPolicy(images=(ALPINE,), on_unknown_image="deny"),
    )

    with docker_proxy_setup() as args:  # loads effective policy from host store
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        ok = subprocess.run(
            ["docker", "run", "--rm", ALPINE, "echo", "from-host-policy"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert ok.returncode == 0, ok.stderr
        assert "from-host-policy" in ok.stdout
        denied = subprocess.run(
            ["docker", "run", "--rm", "busybox:1.36", "true"],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert denied.returncode != 0


def test_proxy_raw_api_create_denied_for_bind_mount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hit evaluate_request bind denial through the live proxy socket."""
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    policy = DockerProxyPolicy(images=(ALPINE,))
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        assert host.startswith("unix://")
        sock_path = host.removeprefix("unix://")
        body = json.dumps(
            {
                "Image": ALPINE,
                "HostConfig": {"Binds": ["/:/host"]},
                "Cmd": ["true"],
            }
        ).encode()
        req = (
            b"POST /containers/create HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(5.0)
            client.connect(sock_path)
            client.sendall(req)
            resp = client.recv(65536)
        finally:
            client.close()
        assert b"403" in resp
        assert b"Binds" in resp or b"HostConfig" in resp
