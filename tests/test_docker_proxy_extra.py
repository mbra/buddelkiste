"""Additional coverage for docker_proxy policy, HTTP, and proxy plumbing."""

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
    _build_upstream_request,
    _host_config_violations,
    _path_category,
    _read_http_request,
    _reject,
    _short_listen_socket,
    declaration_from_config,
    docker_proxy_setup,
    evaluate_request,
    load_effective_policy,
    load_policy_file,
    policy_from_mapping,
    project_policy_key,
    resolve_docker_socket,
    write_policy_file,
)


def test_allows_image_empty_and_digest_normalization() -> None:
    policy = DockerProxyPolicy(images=("alpine:3.20", "redis:*"))
    assert not policy.allows_image("")
    assert not policy.allows_image("   ")
    assert policy.allows_image("alpine:3.20@sha256:deadbeef")
    assert policy.allows_image("redis")  # untagged → matches redis:*


def test_image_match_empty_pattern_and_prefix() -> None:
    from buddelkiste.docker_proxy import _image_matches

    assert not _image_matches("alpine", "")
    assert _image_matches("library/redis", "library/redis:*")


def test_project_policy_key_uses_buddelkiste_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    nested = tmp_path / "proj" / "sub"
    nested.mkdir(parents=True)
    (tmp_path / "proj" / ".buddelkiste.toml").write_text("features = []\n", encoding="utf-8")
    key = project_policy_key(nested)
    assert key.startswith("proj-")


def test_load_policy_file_missing_and_roundtrip_allow_binds(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    assert load_policy_file(missing).images == ()

    path = tmp_path / "policy.toml"
    policy = DockerProxyPolicy(
        images=("a:1",),
        allow_binds=("/tmp/tc-*",),
        on_unknown_image="session",
    )
    write_policy_file(path, policy)
    loaded = load_policy_file(path)
    assert loaded.allow_binds == ("/tmp/tc-*",)
    assert loaded.on_unknown_image == "session"


def test_policy_from_mapping_error_paths() -> None:
    with pytest.raises(click.ClickException, match="TOML table"):
        policy_from_mapping("nope", where="t")  # type: ignore[arg-type]
    with pytest.raises(click.ClickException, match="images must be a list"):
        policy_from_mapping({"images": "x"}, where="t")
    with pytest.raises(click.ClickException, match="images\\[0\\]"):
        policy_from_mapping({"images": [123]}, where="t")
    with pytest.raises(click.ClickException, match="api must be a table"):
        policy_from_mapping({"images": [], "api": []}, where="t")
    with pytest.raises(click.ClickException, match="host_config must be a table"):
        policy_from_mapping({"images": [], "host_config": []}, where="t")
    with pytest.raises(click.ClickException, match="approval must be a table"):
        policy_from_mapping({"images": [], "approval": []}, where="t")


def test_load_effective_policy_merges_session_and_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)

    key = project_policy_key()
    from buddelkiste.docker_proxy import host_policy_path, session_policy_path

    write_policy_file(host_policy_path(key), DockerProxyPolicy(images=("host:1",)))
    write_policy_file(session_policy_path(key), DockerProxyPolicy(images=("session:1",)))
    effective = load_effective_policy(
        key=key,
        config={"docker_proxy": {"images": ["cfg:1"]}},
    )
    assert effective.images == ("host:1", "session:1", "cfg:1")


def test_declaration_from_config() -> None:
    assert declaration_from_config({}) is None
    with pytest.raises(click.ClickException, match="must be a table"):
        declaration_from_config({"docker_proxy": "x"})
    decl = declaration_from_config({"docker_proxy": {"images": ["a:1"]}})
    assert decl is not None
    assert decl.images == ("a:1",)


def test_resolve_docker_socket_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/custom.sock")
    assert resolve_docker_socket() == Path("/tmp/custom.sock")
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    with pytest.raises(click.ClickException, match="only supports unix://"):
        resolve_docker_socket()
    monkeypatch.delenv("DOCKER_HOST")
    assert resolve_docker_socket() == Path("/var/run/docker.sock")


def test_path_categories() -> None:
    assert _path_category("/commit") == "commit"
    assert _path_category("/v1.45/swarm") == "swarm"
    assert _path_category("/plugins/foo") == "plugins"
    assert _path_category("/session") == "session"
    assert _path_category("/containers/json") is None


def test_host_config_mounts_and_allow_binds() -> None:
    violations = _host_config_violations(
        {
            "Mounts": [
                {"Type": "bind", "Source": "/tmp/ok-data"},
                {"Type": "bind", "Source": "/etc/passwd"},
                {"Type": "volume", "Source": "vol"},
            ],
            "NetworkMode": "host",
        },
        DockerProxyPolicy(
            images=("a:1",),
            allow_binds=("/tmp/ok*",),
            deny_host_config=("NetworkMode=host",),
        ),
    )
    assert "NetworkMode=host" in violations
    assert any(v.startswith("Binds:/etc/passwd") for v in violations)
    assert not any("ok-data" in v for v in violations)


def test_evaluate_request_create_error_paths() -> None:
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    assert not evaluate_request("POST", "/containers/create", b"{", policy).allow
    assert not evaluate_request("POST", "/containers/create", b"[]", policy).allow
    bad_hc = json.dumps({"Image": "alpine:3.20", "HostConfig": []}).encode()
    assert not evaluate_request("POST", "/containers/create", bad_hc, policy).allow
    assert evaluate_request("GET", "/version", b"", policy).allow
    assert not evaluate_request("POST", "/commit", b"", policy).allow
    assert not evaluate_request("POST", "/plugins/pull", b"", policy).allow


def test_read_http_request_and_reject() -> None:
    server, client = socket.socketpair()
    try:
        body = b'{"Image":"x"}'
        raw = (
            b"POST /containers/create HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"\r\n"
            + body
        )
        client.sendall(raw)
        parsed = _read_http_request(server)
        assert parsed is not None
        method, path, _headers, got = parsed
        assert method == "POST"
        assert path == "/containers/create"
        assert got == body

        _reject(client, 403, "nope")
        dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _reject(dead, 403, "already-closed")
        dead.close()
    finally:
        server.close()
        client.close()


def test_read_http_request_eof_and_bad_request_line() -> None:
    server, client = socket.socketpair()
    try:
        client.close()
        assert _read_http_request(server) is None
    finally:
        server.close()

    server, client = socket.socketpair()
    try:
        client.sendall(b"GARBAGE\r\n\r\n")
        assert _read_http_request(server) is None
    finally:
        server.close()
        client.close()


def test_build_upstream_injects_hijack_headers_when_missing() -> None:
    raw = _build_upstream_request(
        "POST",
        "/attach",
        {"Connection": "Upgrade"},
        b"",
    )
    text = raw.decode("latin-1")
    assert "Upgrade: tcp" in text
    assert "Connection: Upgrade" in text


def test_handle_client_denies_and_502(tmp_path: Path) -> None:
    from buddelkiste.docker_proxy import _handle_client

    policy = DockerProxyPolicy(images=("alpine:3.20",))
    server, client = socket.socketpair()
    try:
        body = json.dumps({"Image": "alpine:3.20", "HostConfig": {}}).encode()
        client.sendall(
            b"POST /containers/create HTTP/1.1\r\nHost: x\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        _handle_client(server, tmp_path / "missing.sock", policy)
        resp = client.recv(65536)
        assert b"502" in resp or b"cannot connect" in resp
    finally:
        try:
            client.close()
        except OSError:
            pass

    server, client = socket.socketpair()
    try:
        body = json.dumps({"Image": "evil:1", "HostConfig": {}}).encode()
        client.sendall(
            b"POST /containers/create HTTP/1.1\r\nHost: x\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        _handle_client(server, tmp_path / "missing.sock", policy)
        resp = client.recv(65536)
        assert b"403" in resp
        assert b"not allowlisted" in resp
    finally:
        try:
            client.close()
        except OSError:
            pass


def test_proxy_server_stop_unlinks_and_existing_sock(tmp_path: Path) -> None:
    docker_sock = tmp_path / "docker.sock"
    if docker_sock.exists():
        docker_sock.unlink()
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.bind(str(docker_sock))
    upstream.listen(1)
    upstream.settimeout(0.5)

    def serve() -> None:
        try:
            c, _ = upstream.accept()
            c.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()

    listen = tmp_path / "proxy.sock"
    listen.write_text("stale")
    proxy = DockerProxyServer(listen, docker_sock, DockerProxyPolicy())
    proxy.start()
    assert listen.exists()
    proxy.stop()
    assert not listen.exists()
    upstream.close()


def test_docker_proxy_setup_missing_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path / 'no.sock'}")
    with (
        pytest.raises(click.ClickException, match="Docker socket not found"),
        docker_proxy_setup(policy=DockerProxyPolicy()),
    ):
        pass


def test_short_listen_socket_fallback_when_all_long(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(
        "buddelkiste.docker_proxy.tempfile.gettempdir",
        lambda: "/" + ("y" * 120),
    )
    path = _short_listen_socket(Path("/" + ("z" * 120)))
    assert path.as_posix().startswith("/tmp/")


def test_handle_client_empty_request() -> None:
    from buddelkiste.docker_proxy import _handle_client

    server, client = socket.socketpair()
    try:
        client.close()
        _handle_client(server, Path("/tmp/no.sock"), DockerProxyPolicy())
    finally:
        try:
            server.close()
        except OSError:
            pass


def test_relay_send_failure_exits() -> None:
    from buddelkiste.docker_proxy import _relay

    a, b = socket.socketpair()
    try:
        b.close()  # peer closed → sendall/select must not crash the thread
        thread = threading.Thread(target=_relay, args=(a, b), daemon=True)
        thread.start()
        try:
            a.sendall(b"x")
        except OSError:
            pass
        thread.join(timeout=2)
        assert not thread.is_alive()
    finally:
        try:
            a.close()
        except OSError:
            pass


def test_strip_api_prefix_empty_becomes_root() -> None:
    from buddelkiste.docker_proxy import _strip_api_prefix

    assert _strip_api_prefix("/v1.45") == "/"
    assert _strip_api_prefix("/v1.45/containers/json") == "/containers/json"


def test_host_config_mount_edge_cases() -> None:
    # Non-dict / non-bind mounts ignored; empty Source skipped; binds with allowlist miss.
    violations = _host_config_violations(
        {
            "Mounts": ["skip", {"Type": "bind"}, {"Type": "bind", "Source": ""}],
            "Binds": ["/secret:/x"],
        },
        DockerProxyPolicy(images=("a:1",), allow_binds=("/tmp/*",)),
    )
    assert any(v.startswith("Binds:/secret") for v in violations)


def test_read_http_headers_too_large_and_body_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import buddelkiste.docker_proxy as dp

    monkeypatch.setattr(dp, "_MAX_HTTP_HEADERS", 64)
    server, client = socket.socketpair()
    try:
        # No trailing \r\n\r\n so the size check fires before header end.
        client.sendall(b"GET / HTTP/1.1\r\nX: " + b"y" * 80)
        with pytest.raises(ValueError, match="too large"):
            _read_http_request(server)
    finally:
        server.close()
        client.close()

    server, client = socket.socketpair()
    try:
        # Header without colon is skipped; body arrives in a second recv.
        hdr = b"POST /x HTTP/1.1\r\nHost: h\r\nIgnoreMe\r\nContent-Length: 4\r\n\r\n"
        client.sendall(hdr)

        def send_rest() -> None:
            import time

            time.sleep(0.05)
            client.sendall(b"abcd")

        threading.Thread(target=send_rest, daemon=True).start()
        parsed = _read_http_request(server)
        assert parsed is not None
        assert parsed[3] == b"abcd"
    finally:
        server.close()
        client.close()


def test_build_upstream_skips_duplicate_connection_upgrade() -> None:
    raw = _build_upstream_request(
        "POST",
        "/attach",
        {"Upgrade": "tcp", "Connection": "Upgrade"},
        b"",
    )
    text = raw.decode("latin-1")
    assert text.count("Connection: Upgrade") == 1
    assert text.count("Upgrade: tcp") == 1


def test_handle_client_logs_handler_exception(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import logging

    import buddelkiste.docker_proxy as dp
    from buddelkiste.docker_proxy import _handle_client

    monkeypatch.setattr(dp, "_MAX_HTTP_HEADERS", 64)
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    server, client = socket.socketpair()
    try:
        client.sendall(b"GET / HTTP/1.1\r\nX: " + b"z" * 80)
        with caplog.at_level(logging.ERROR):
            _handle_client(server, tmp_path / "no.sock", policy)
        assert "docker-proxy client handler failed" in caplog.text
    finally:
        try:
            client.close()
        except OSError:
            pass
        try:
            server.close()
        except OSError:
            pass
