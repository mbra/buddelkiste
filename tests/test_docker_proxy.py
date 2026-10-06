from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import click
import pytest

from buddelkiste.docker_proxy import (
    DockerProxyPolicy,
    DockerProxyServer,
    evaluate_request,
    load_policy_file,
    merge_policies,
    policy_from_mapping,
    write_policy_file,
)


def test_image_allowlist_globs() -> None:
    policy = DockerProxyPolicy(images=("postgres:16-alpine", "redis:*", "testcontainers/ryuk:*"))
    assert policy.allows_image("postgres:16-alpine")
    assert not policy.allows_image("postgres:15-alpine")
    assert policy.allows_image("redis:7-alpine")
    assert policy.allows_image("testcontainers/ryuk:0.3.3")
    assert not policy.allows_image("evil:latest")


def test_evaluate_create_allow_and_deny() -> None:
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    allow = evaluate_request(
        "POST",
        "/v1.45/containers/create",
        json.dumps({"Image": "alpine:3.20", "HostConfig": {}}).encode(),
        policy,
    )
    assert allow.allow

    deny = evaluate_request(
        "POST",
        "/containers/create",
        json.dumps({"Image": "evil:latest", "HostConfig": {}}).encode(),
        policy,
    )
    assert not deny.allow
    assert "not allowlisted" in deny.reason


def test_evaluate_create_denies_privileged() -> None:
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    decision = evaluate_request(
        "POST",
        "/containers/create",
        json.dumps(
            {"Image": "alpine:3.20", "HostConfig": {"Privileged": True}}
        ).encode(),
        policy,
    )
    assert not decision.allow
    assert "Privileged" in decision.reason


def test_evaluate_create_denies_binds_by_default() -> None:
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    decision = evaluate_request(
        "POST",
        "/containers/create",
        json.dumps(
            {
                "Image": "alpine:3.20",
                "HostConfig": {"Binds": ["/:/host"]},
            }
        ).encode(),
        policy,
    )
    assert not decision.allow
    assert "Binds" in decision.reason


def test_evaluate_pull_checks_from_image() -> None:
    policy = DockerProxyPolicy(images=("alpine:*",))
    ok = evaluate_request(
        "POST",
        "/images/create?fromImage=alpine&tag=3.20",
        b"",
        policy,
    )
    assert ok.allow
    bad = evaluate_request(
        "POST",
        "/images/create?fromImage=evil&tag=latest",
        b"",
        policy,
    )
    assert not bad.allow


def test_evaluate_denies_build() -> None:
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    decision = evaluate_request("POST", "/build", b"", policy)
    assert not decision.allow
    assert "build" in decision.reason


def test_policy_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    policy = DockerProxyPolicy(
        images=("postgres:16-alpine", "redis:7"),
        on_unknown_image="session",
    )
    write_policy_file(path, policy)
    loaded = load_policy_file(path)
    assert loaded.images == policy.images
    assert loaded.on_unknown_image == "session"


def test_policy_from_mapping_images_tables() -> None:
    policy = policy_from_mapping(
        {"images": [{"ref": "a:1"}, "b:2"]},
        where="test",
    )
    assert policy.images == ("a:1", "b:2")


def test_policy_from_mapping_rejects_bad_unknown() -> None:
    with pytest.raises(click.ClickException, match="on_unknown_image"):
        policy_from_mapping({"on_unknown_image": "prompt"}, where="test")


def test_merge_policies_extends_images() -> None:
    merged = merge_policies(
        DockerProxyPolicy(images=("a:1",)),
        DockerProxyPolicy(images=("b:2", "a:1")),
    )
    assert merged.images == ("a:1", "b:2")


def _start_fake_docker(sock_path: Path) -> tuple[threading.Event, socket.socket]:
    """Minimal Docker-like unix server: echo 200 OK for any request."""
    if sock_path.exists():
        sock_path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(8)
    server.settimeout(0.5)
    done = threading.Event()

    def serve() -> None:
        try:
            while not done.is_set():
                try:
                    client, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with client:
                    data = client.recv(65536)
                    if not data:
                        continue
                    body = b'{"Ok":true}'
                    client.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode()
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
                    break
        finally:
            try:
                server.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return done, server


def test_proxy_server_allows_and_forwards(tmp_path: Path) -> None:
    docker_sock = tmp_path / "docker.sock"
    listen = tmp_path / "proxy.sock"
    done, _upstream = _start_fake_docker(docker_sock)
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    proxy = DockerProxyServer(listen, docker_sock, policy)
    proxy.start()
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(str(listen))
        body = json.dumps({"Image": "alpine:3.20", "HostConfig": {}}).encode()
        req = (
            b"POST /containers/create HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"\r\n"
            + body
        )
        client.sendall(req)
        resp = client.recv(65536)
        client.close()
        assert b"200 OK" in resp
        assert b'{"Ok":true}' in resp
    finally:
        proxy.stop()
        done.set()


def test_proxy_server_rejects_unknown_image(tmp_path: Path) -> None:
    docker_sock = tmp_path / "docker.sock"
    listen = tmp_path / "proxy.sock"
    # Upstream should not be contacted; still bind a socket so connect would work.
    done, _upstream = _start_fake_docker(docker_sock)
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    proxy = DockerProxyServer(listen, docker_sock, policy)
    proxy.start()
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(str(listen))
        body = json.dumps({"Image": "evil:latest", "HostConfig": {}}).encode()
        req = (
            b"POST /containers/create HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"\r\n"
            + body
        )
        client.sendall(req)
        resp = client.recv(65536)
        client.close()
        assert b"403" in resp
        assert b"not allowlisted" in resp
    finally:
        proxy.stop()
        done.set()


def test_feature_mutex_docker_and_proxy() -> None:
    from buddelkiste.conflicts import check_feature_mutex
    from buddelkiste.features import FEATURE_NAMES

    enabled = {name: False for name in FEATURE_NAMES}
    enabled["docker"] = True
    enabled["docker-proxy"] = True
    errors = check_feature_mutex(enabled, {})
    assert errors
    assert "docker" in errors[0] and "docker-proxy" in errors[0]


def test_docker_policy_apply_and_mutex_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from buddelkiste.binds import RWBindConfig
    from buddelkiste.cli import cli

    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    runtime = tmp_path / "run"
    runtime.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.chdir(work)

    config = home / ".config" / "buddelkiste" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "[docker_proxy]\n"
        'images = ["postgres:16-alpine"]\n',
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["docker-policy", "apply"])
    assert result.exit_code == 0, result.output
    assert "Wrote 1 image" in result.output

    show = runner.invoke(cli, ["docker-policy", "show"])
    assert show.exit_code == 0
    assert "postgres:16-alpine" in show.output

    path = runner.invoke(cli, ["docker-policy", "path"])
    assert path.exit_code == 0
    assert "docker-proxy" in path.output

    monkeypatch.setattr(
        "buddelkiste.cli.get_binds",
        lambda config, enabled=None: [RWBindConfig(work)],
    )
    monkeypatch.setattr("buddelkiste.cli.run_bwrap", lambda *a, **k: 0)
    conflict = runner.invoke(
        cli,
        ["run", "--feature", "docker", "--feature", "docker-proxy", "/bin/true"],
    )
    assert conflict.exit_code != 0
    assert "cannot be enabled together" in conflict.output
