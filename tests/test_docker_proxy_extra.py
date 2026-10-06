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
    from buddelkiste.docker_proxy import DockerProxyServer, _handle_client

    policy = DockerProxyPolicy(images=("alpine:3.20",), on_unknown_image="deny")
    server_obj = DockerProxyServer(
        tmp_path / "p.sock", tmp_path / "missing.sock", policy
    )
    server, client = socket.socketpair()
    try:
        body = json.dumps({"Image": "alpine:3.20", "HostConfig": {}}).encode()
        client.sendall(
            b"POST /containers/create HTTP/1.1\r\nHost: x\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        _handle_client(server, tmp_path / "missing.sock", server_obj)
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
        _handle_client(server, tmp_path / "missing.sock", server_obj)
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


def test_handle_client_empty_request(tmp_path: Path) -> None:
    from buddelkiste.docker_proxy import DockerProxyServer, _handle_client

    server_obj = DockerProxyServer(
        tmp_path / "p.sock", tmp_path / "d.sock", DockerProxyPolicy()
    )
    server, client = socket.socketpair()
    try:
        client.close()
        _handle_client(server, Path("/tmp/no.sock"), server_obj)
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
    from buddelkiste.docker_proxy import DockerProxyServer, _handle_client

    monkeypatch.setattr(dp, "_MAX_HTTP_HEADERS", 64)
    policy = DockerProxyPolicy(images=("alpine:3.20",))
    server_obj = DockerProxyServer(tmp_path / "p.sock", tmp_path / "no.sock", policy)
    server, client = socket.socketpair()
    try:
        client.sendall(b"GET / HTTP/1.1\r\nX: " + b"z" * 80)
        with caplog.at_level(logging.ERROR):
            _handle_client(server, tmp_path / "no.sock", server_obj)
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


def test_grant_session_image_empty_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.docker_proxy import grant_session_image, session_policy_path

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)

    with pytest.raises(click.ClickException, match="empty image"):
        grant_session_image("  ")

    path = grant_session_image("redis:7", key="proj")
    assert path == session_policy_path("proj")
    assert "redis:7" in load_policy_file(path).images
    # Second grant is a no-op when already allowlisted.
    assert grant_session_image("redis:7", key="proj") == path
    assert load_policy_file(path).images == ("redis:7",)


def test_pull_without_tag_and_create_without_host_config() -> None:
    policy = DockerProxyPolicy(images=("busybox", "alpine:3.20"))
    pull = evaluate_request(
        "POST",
        "/images/create?fromImage=busybox",
        b"",
        policy,
    )
    assert pull.allow
    assert pull.image == "busybox"

    create = evaluate_request(
        "POST",
        "/containers/create",
        json.dumps({"Image": "alpine:3.20"}).encode(),
        policy,
    )
    assert create.allow


def test_host_config_lowercase_source_key() -> None:
    violations = _host_config_violations(
        {"Mounts": [{"Type": "bind", "source": "/etc/shadow"}]},
        DockerProxyPolicy(images=("a:1",), allow_binds=("/tmp/*",)),
    )
    assert any(v.startswith("Binds:/etc/shadow") for v in violations)


def test_build_upstream_adds_connection_when_only_upgrade() -> None:
    raw = _build_upstream_request("POST", "/attach", {"Upgrade": "tcp"}, b"")
    text = raw.decode("latin-1")
    assert "Upgrade: tcp" in text
    assert "Connection: Upgrade" in text


def test_read_http_body_truncated_on_eof() -> None:
    server, client = socket.socketpair()
    try:
        client.sendall(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc")
        client.close()
        parsed = _read_http_request(server)
        assert parsed is not None
        assert parsed[3] == b"abc"
    finally:
        server.close()


def test_reload_policy_and_resolve_pending_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    from buddelkiste.docker_proxy import (
        _PendingImage,
        control_request,
        host_policy_path,
        runtime_path,
    )

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    key = "edgeproj"
    write_policy_file(
        host_policy_path(key),
        DockerProxyPolicy(images=("kept:1",), on_unknown_image="session"),
    )

    listen = tmp_path / "proxy.sock"
    docker_sock = tmp_path / "docker.sock"
    proxy = DockerProxyServer(
        listen,
        docker_sock,
        DockerProxyPolicy(images=("kept:1",), on_unknown_image="session"),
        policy_key=key,
        config={"docker_proxy": {"images": ["cfg:1"]}},
    )
    # Pre-create sockets so start() unlinks them.
    listen.write_text("stale")
    proxy.control_sock.write_text("stale-ctl")
    proxy.start()
    try:
        assert runtime_path(key).is_file()
        reloaded = proxy.reload_policy()
        assert "kept:1" in reloaded.images
        assert "cfg:1" in reloaded.images

        with pytest.raises(click.ClickException, match="no pending"):
            proxy.resolve_pending(approve=True)

        with proxy._pending_lock:
            proxy._pending["one:1"] = _PendingImage(
                id="aaaa1111", image="one:1", created=time.time()
            )
            proxy._pending["two:1"] = _PendingImage(
                id="bbbb2222", image="two:1", created=time.time() + 0.01
            )

        with pytest.raises(click.ClickException, match="multiple pending"):
            proxy.resolve_pending(approve=False)

        with pytest.raises(click.ClickException, match="no pending approval matching"):
            proxy.resolve_pending(target="missing:9", approve=False)

        denied = proxy.resolve_pending(target="aaaa1111", approve=False)
        assert denied["image"] == "one:1"
        assert denied["approved"] is False

        # Coalesce concurrent waiters for the remaining pending image.
        results: list[bool] = []

        def waiter() -> None:
            results.append(proxy.wait_for_image_approval("two:1"))

        w1 = threading.Thread(target=waiter, daemon=True)
        w2 = threading.Thread(target=waiter, daemon=True)
        w1.start()
        w2.start()
        for _ in range(50):
            if len(proxy.list_pending()) >= 1:
                break
            time.sleep(0.02)
        ok = control_request(
            {"op": "approve", "target": "two:1@sha256:abc"}, key=key
        )
        assert ok.get("ok") is True
        w1.join(timeout=2)
        w2.join(timeout=2)
        assert results == [True, True]
        assert proxy.current_policy().allows_image("two:1")

        bad = control_request({"op": "nope"}, key=key)
        assert bad.get("ok") is False
        empty_deny = control_request({"op": "deny"}, key=key)
        assert empty_deny.get("ok") is False

        # Approve when image already allowlisted skips in-memory append branch.
        with proxy._pending_lock:
            proxy._pending["kept:1"] = _PendingImage(
                id="cccc3333", image="kept:1", created=time.time()
            )
        already = proxy.resolve_pending(target="kept:1", approve=True)
        assert already["approved"] is True
    finally:
        proxy.stop()
        assert not runtime_path(key).is_file()


def test_clear_runtime_ignores_foreign_pid_and_bad_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from buddelkiste.docker_proxy import runtime_path

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)

    key = "clearkey"
    path = runtime_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"pid": 1, "control_sock": "/tmp/x"}\n', encoding="utf-8")
    proxy = DockerProxyServer(
        tmp_path / "p.sock", tmp_path / "d.sock", DockerProxyPolicy(), policy_key=key
    )
    proxy._clear_runtime()
    assert path.is_file()  # foreign pid left alone

    path.write_text("{not-json", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        proxy._clear_runtime()  # invalid JSON ignored with a warning
    assert path.is_file()
    assert "failed to clear docker-proxy runtime" in caplog.text


def test_read_runtime_and_control_request_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.docker_proxy import (
        control_request,
        read_runtime,
        runtime_path,
    )

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)
    key = "rtkey"
    path = runtime_path(key)

    with pytest.raises(click.ClickException, match="no live docker-proxy"):
        read_runtime(key=key)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(click.ClickException, match="invalid runtime"):
        read_runtime(key=key)

    path.write_text("[1, 2]\n", encoding="utf-8")
    with pytest.raises(click.ClickException, match="invalid runtime"):
        read_runtime(key=key)

    path.write_text(json.dumps({"pid": 1}) + "\n", encoding="utf-8")
    with pytest.raises(click.ClickException, match="missing control_sock"):
        control_request({"op": "list"}, key=key)

    path.write_text(
        json.dumps({"pid": 1, "control_sock": str(tmp_path / "missing.ctl")}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(click.ClickException, match="cannot connect"):
        control_request({"op": "list"}, key=key)


def test_recv_json_line_edge_cases() -> None:
    from buddelkiste.docker_proxy import _recv_json_line

    server, client = socket.socketpair()
    try:
        client.close()
        assert _recv_json_line(server) is None
    finally:
        server.close()

    server, client = socket.socketpair()
    try:
        client.sendall(b"[1,2]\n")
        with pytest.raises(ValueError, match="JSON object"):
            _recv_json_line(server)
    finally:
        server.close()
        client.close()

    server, client = socket.socketpair()
    try:
        client.sendall(b"x" * 20)
        with pytest.raises(ValueError, match="too large"):
            _recv_json_line(server, limit=8)
    finally:
        server.close()
        client.close()


def test_control_handler_empty_and_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from buddelkiste.docker_proxy import control_request, runtime_path

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)

    proxy = DockerProxyServer(
        tmp_path / "p.sock",
        tmp_path / "d.sock",
        DockerProxyPolicy(),
        policy_key="ctl",
    )
    server, client = socket.socketpair()
    try:
        client.close()
        proxy._handle_control_client(server)
    finally:
        try:
            server.close()
        except OSError:
            pass

    # Invalid JSON triggers exception path and error response.
    server, client = socket.socketpair()
    try:
        client.sendall(b"{bad\n")
        proxy._handle_control_client(server)
        resp = client.recv(65536)
        assert b'"ok": false' in resp or b'"ok":false' in resp
    finally:
        try:
            client.close()
        except OSError:
            pass
        try:
            server.close()
        except OSError:
            pass

    # Peer accepts, reads the request, then closes without a reply.
    listen = tmp_path / "ctl.sock"
    if listen.exists():
        listen.unlink()
    acceptor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    acceptor.bind(str(listen))
    acceptor.listen(1)

    def accept_read_close() -> None:
        c, _ = acceptor.accept()
        try:
            c.recv(4096)
        finally:
            c.close()

    threading.Thread(target=accept_read_close, daemon=True).start()
    rt = runtime_path("ctl")
    rt.parent.mkdir(parents=True, exist_ok=True)
    rt.write_text(
        json.dumps({"pid": 1, "control_sock": str(listen)}) + "\n", encoding="utf-8"
    )
    with pytest.raises(click.ClickException, match="empty response"):
        control_request({"op": "list"}, key="ctl")
    acceptor.close()


def test_short_listen_socket_impossible_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import buddelkiste.docker_proxy as dp

    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(dp, "_AF_UNIX_PATH_MAX", 5)
    monkeypatch.setattr(dp.tempfile, "gettempdir", lambda: "/" + ("y" * 20))
    with pytest.raises(click.ClickException, match="short enough path"):
        _short_listen_socket(Path("/" + ("z" * 20)))


def test_stop_denies_pending_waiters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)

    proxy = DockerProxyServer(
        tmp_path / "p.sock",
        tmp_path / "d.sock",
        DockerProxyPolicy(on_unknown_image="session"),
        policy_key="stopkey",
    )
    proxy.start()
    result: list[bool] = []

    def waiter() -> None:
        result.append(proxy.wait_for_image_approval("gone:1"))

    thread = threading.Thread(target=waiter, daemon=True)
    thread.start()
    for _ in range(50):
        if proxy.list_pending():
            break
        time.sleep(0.02)
    proxy.stop()
    thread.join(timeout=2)
    assert result == [False]


def test_notify_pending_image_approval_best_effort(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from buddelkiste.docker_proxy import _notify_pending_image_approval

    calls: list[list[str]] = []

    def fake_popen(cmd: list[str], **kwargs: object) -> object:
        calls.append(list(cmd))
        return object()

    # Autouse conftest already hides notify-send; exercise that path first.
    with caplog.at_level(logging.WARNING):
        _notify_pending_image_approval("deadbeef", "evil:1")
    assert calls == []
    assert "notify-send not found" in caplog.text
    assert "evil:1" in caplog.text

    monkeypatch.setattr(
        "buddelkiste.docker_proxy.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("buddelkiste.docker_proxy.subprocess.Popen", fake_popen)
    _notify_pending_image_approval("deadbeef", "evil:1")
    assert len(calls) == 1
    assert calls[0][0] == "/usr/bin/notify-send"
    assert "evil:1" in calls[0][-1]
    assert "approve deadbeef" in calls[0][-1]

    def boom(*_a: object, **_k: object) -> object:
        raise OSError("no dbus")

    monkeypatch.setattr("buddelkiste.docker_proxy.subprocess.Popen", boom)
    with caplog.at_level(logging.WARNING):
        _notify_pending_image_approval("deadbeef", "evil:1")  # must not raise
    assert "notify-send failed" in caplog.text


def test_wait_for_image_approval_notifies_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.chdir(tmp_path)

    notified: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "buddelkiste.docker_proxy._notify_pending_image_approval",
        lambda pid, image: notified.append((pid, image)),
    )

    proxy = DockerProxyServer(
        tmp_path / "p.sock",
        tmp_path / "d.sock",
        DockerProxyPolicy(on_unknown_image="session"),
        policy_key="notifykey",
    )
    proxy.start()
    try:
        results: list[bool] = []

        def waiter() -> None:
            results.append(proxy.wait_for_image_approval("img:9"))

        t1 = threading.Thread(target=waiter, daemon=True)
        t1.start()
        for _ in range(50):
            if proxy.list_pending():
                break
            time.sleep(0.02)
        else:
            raise AssertionError("pending never appeared")

        t2 = threading.Thread(target=waiter, daemon=True)
        t2.start()
        for _ in range(50):
            if t1.is_alive() and t2.is_alive():
                break
            time.sleep(0.02)
        time.sleep(0.05)
        assert len(notified) == 1
        assert notified[0][1] == "img:9"
        assert len(proxy.list_pending()) == 1

        proxy.resolve_pending(approve=False)
        t1.join(timeout=2)
        t2.join(timeout=2)
        assert sorted(results) == [False, False]
    finally:
        proxy.stop()


def test_cli_docker_policy_approve_deny_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    from click.testing import CliRunner

    from buddelkiste.cli import cli
    from buddelkiste.docker_proxy import _PendingImage

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    key = project_policy_key()
    listen = tmp_path / "proxy.sock"
    proxy = DockerProxyServer(
        listen,
        tmp_path / "d.sock",
        DockerProxyPolicy(on_unknown_image="session"),
        policy_key=key,
    )
    proxy.start()
    runner = CliRunner()
    try:
        listed = runner.invoke(cli, ["docker-policy", "pending"])
        assert listed.exit_code == 0
        assert "No pending" in listed.output

        with proxy._pending_lock:
            proxy._pending["img:1"] = _PendingImage(
                id="deadbeef", image="img:1", created=time.time()
            )
        pending = runner.invoke(cli, ["docker-policy", "pending"])
        assert pending.exit_code == 0
        assert "deadbeef" in pending.output
        assert "img:1" in pending.output

        deny = runner.invoke(cli, ["docker-policy", "deny", "deadbeef"])
        assert deny.exit_code == 0
        assert "Denied" in deny.output

        with proxy._pending_lock:
            proxy._pending["img:2"] = _PendingImage(
                id="cafebabe", image="img:2", created=time.time()
            )
        approve = runner.invoke(cli, ["docker-policy", "approve", "img:2"])
        assert approve.exit_code == 0
        assert "Approved" in approve.output

        fail = runner.invoke(cli, ["docker-policy", "approve"])
        assert fail.exit_code != 0
    finally:
        proxy.stop()
