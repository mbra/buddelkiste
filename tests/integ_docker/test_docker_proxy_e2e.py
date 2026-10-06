"""Host-only docker-proxy e2e (skipped inside bwrap / without Docker)."""

from __future__ import annotations

import os
import subprocess

import pytest

from buddelkiste.docker_proxy import DockerProxyPolicy, docker_proxy_setup

pytestmark = pytest.mark.requires_docker


def _docker_host_from_setup_args(args: list[str] | tuple[str, ...]) -> str:
    for i, arg in enumerate(args):
        if arg == "--setenv" and i + 2 < len(args) and args[i + 1] == "DOCKER_HOST":
            return args[i + 2]
    raise AssertionError(f"DOCKER_HOST missing from setup args: {args!r}")


def test_proxy_allows_listed_image_via_docker_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    # Use a tiny local image that should already exist on developer machines;
    # fall back to pulling alpine if needed outside CI sandboxes.
    image = "alpine:3.20"
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
    )
    if inspect.returncode != 0:
        pull = subprocess.run(
            ["docker", "pull", image],
            check=False,
            capture_output=True,
            text=True,
        )
        if pull.returncode != 0:
            pytest.skip(f"cannot pull {image}: {pull.stderr}")

    policy = DockerProxyPolicy(images=(image,))
    # Do not pass a long pytest tmp_path as runtime_dir; AF_UNIX paths are short.
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                image,
                "echo",
                "ok-from-proxy",
            ],
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

    policy = DockerProxyPolicy(images=("alpine:3.20",))
    with docker_proxy_setup(policy=policy) as args:
        host = _docker_host_from_setup_args(args)
        env = os.environ.copy()
        env["DOCKER_HOST"] = host
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "busybox:1.36",
                "echo",
                "should-not-run",
            ],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0
        combined = (proc.stdout or "") + (proc.stderr or "")
        assert "should-not-run" not in combined
        assert "docker-proxy" in combined or "not allowlisted" in combined or "403" in combined
