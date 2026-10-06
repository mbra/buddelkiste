"""Filtered Docker Engine API proxy for the ``docker-proxy`` feature.

Listens on a Unix socket, forwards allowed requests to the real Docker socket,
and rejects container creates / image pulls that violate the allowlist or
dangerous HostConfig fields.
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import socket
import tempfile
import threading
import tomllib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import click

log = logging.getLogger(__name__)

_API_PREFIX = re.compile(r"^/v[\d.]+")
_CONTAINER_CREATE = re.compile(r"^(/v[\d.]+)?/containers/create/?$")
_IMAGE_CREATE = re.compile(r"^(/v[\d.]+)?/images/create/?$")
_BUILD = re.compile(r"^(/v[\d.]+)?/(build|buildkit)(/|$)")
_COMMIT = re.compile(r"^(/v[\d.]+)?/commit/?$")
_SWARM = re.compile(r"^(/v[\d.]+)?/(swarm|services|nodes|tasks|secrets|configs)(/|$)")
_PLUGINS = re.compile(r"^(/v[\d.]+)?/plugins(/|$)")
_SESSION = re.compile(r"^(/v[\d.]+)?/(session|grpc)(/|$)")

DEFAULT_DENY_HOST_CONFIG = (
    "Privileged",
    "PidMode=host",
    "NetworkMode=host",
    "IpcMode=host",
    "UTSMode=host",
    "UsernsMode=host",
    "CapAdd",
    "Devices",
    "DeviceCgroupRules",
    "DeviceRequests",
)

DEFAULT_API_DENY = ("build", "commit", "swarm", "plugins", "session")


@dataclass(frozen=True)
class DockerProxyPolicy:
    """Allow/deny rules for the Docker API proxy."""

    images: tuple[str, ...] = ()
    api_deny: tuple[str, ...] = DEFAULT_API_DENY
    deny_host_config: tuple[str, ...] = DEFAULT_DENY_HOST_CONFIG
    allow_binds: tuple[str, ...] = ()
    on_unknown_image: str = "deny"  # deny | session (session grants via session file)

    def allows_image(self, ref: str) -> bool:
        image = _normalize_image_ref(ref)
        if not image:
            return False
        return any(_image_matches(image, pattern) for pattern in self.images)


def _normalize_image_ref(ref: str) -> str:
    text = ref.strip()
    if not text:
        return ""
    # Drop digest for allowlist matching against name:tag patterns.
    if "@" in text and not text.startswith("sha256:"):
        text = text.split("@", 1)[0]
    return text


def _image_matches(image: str, pattern: str) -> bool:
    """Match ``image`` against an allowlist pattern (fnmatch, optional *:tag)."""
    pat = pattern.strip()
    if not pat:
        return False
    if fnmatch(image, pat):
        return True
    # ``repo:*`` should also match untagged ``repo`` (Docker implies :latest).
    if pat.endswith(":*"):
        prefix = pat[:-2]
        if image == prefix or image.startswith(prefix + "/"):
            return True
    return ":" not in image and fnmatch(f"{image}:latest", pat)


def policy_dir() -> Path:
    return Path.home() / ".config" / "buddelkiste" / "docker-proxy"


def _find_project_config(start: Path | None = None) -> Path | None:
    cur = (start or Path.cwd()).resolve()
    for directory in (cur, *cur.parents):
        candidate = directory / ".buddelkiste.toml"
        if candidate.is_file():
            return candidate
    return None


def project_policy_key(start: Path | None = None) -> str:
    """Stable key for the current project (dirname + path hash)."""
    import hashlib

    cur = (start or Path.cwd()).resolve()
    project = _find_project_config(cur)
    base = project.parent if project is not None else cur
    digest = hashlib.sha256(str(base).encode()).hexdigest()[:12]
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", base.name).strip("-") or "project"
    return f"{safe_name}-{digest}"


def host_policy_path(key: str | None = None) -> Path:
    return policy_dir() / f"{key or project_policy_key()}.toml"


def session_policy_path(key: str | None = None) -> Path:
    return policy_dir() / f"{key or project_policy_key()}.session.toml"


def load_policy_file(path: Path) -> DockerProxyPolicy:
    if not path.is_file():
        return DockerProxyPolicy()
    with path.open("rb") as fobj:
        data = tomllib.load(fobj)
    return policy_from_mapping(data, where=str(path))


def policy_from_mapping(data: Mapping[str, Any], *, where: str) -> DockerProxyPolicy:
    if not isinstance(data, dict):
        raise click.ClickException(f"{where}: policy must be a TOML table")

    images: list[str] = []
    raw_images = data.get("images", [])
    if isinstance(raw_images, list):
        for index, item in enumerate(raw_images):
            if isinstance(item, str):
                images.append(item)
            elif isinstance(item, dict) and "ref" in item:
                images.append(str(item["ref"]))
            else:
                raise click.ClickException(
                    f"{where}: images[{index}] must be a string or a table with 'ref'"
                )
    else:
        raise click.ClickException(f"{where}: images must be a list")

    api = data.get("api") or {}
    if api and not isinstance(api, dict):
        raise click.ClickException(f"{where}: api must be a table")
    api_deny = tuple(str(x) for x in api.get("deny", DEFAULT_API_DENY)) if api else DEFAULT_API_DENY

    host_config = data.get("host_config") or {}
    if host_config and not isinstance(host_config, dict):
        raise click.ClickException(f"{where}: host_config must be a table")
    deny_hc = (
        tuple(str(x) for x in host_config.get("deny", DEFAULT_DENY_HOST_CONFIG))
        if host_config
        else DEFAULT_DENY_HOST_CONFIG
    )
    allow_binds = tuple(str(x) for x in host_config.get("allow_binds", ())) if host_config else ()

    approval = data.get("approval") or {}
    if approval and not isinstance(approval, dict):
        raise click.ClickException(f"{where}: approval must be a table")
    on_unknown = str(approval.get("on_unknown_image", data.get("on_unknown_image", "deny")))
    if on_unknown not in {"deny", "session"}:
        raise click.ClickException(
            f"{where}: on_unknown_image must be 'deny' or 'session' (got {on_unknown!r})"
        )

    return DockerProxyPolicy(
        images=tuple(images),
        api_deny=api_deny,
        deny_host_config=deny_hc,
        allow_binds=allow_binds,
        on_unknown_image=on_unknown,
    )


def merge_policies(*policies: DockerProxyPolicy) -> DockerProxyPolicy:
    """Merge policies; later entries extend image allowlists."""
    images: list[str] = []
    seen: set[str] = set()
    api_deny = DEFAULT_API_DENY
    deny_hc = DEFAULT_DENY_HOST_CONFIG
    allow_binds: list[str] = []
    on_unknown = "deny"
    for policy in policies:
        for ref in policy.images:
            if ref not in seen:
                seen.add(ref)
                images.append(ref)
        api_deny = policy.api_deny
        deny_hc = policy.deny_host_config
        allow_binds = list(policy.allow_binds)
        on_unknown = policy.on_unknown_image
    return DockerProxyPolicy(
        images=tuple(images),
        api_deny=api_deny,
        deny_host_config=deny_hc,
        allow_binds=tuple(allow_binds),
        on_unknown_image=on_unknown,
    )


def load_effective_policy(
    *,
    key: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> DockerProxyPolicy:
    """Host policy + session overlays + optional ``[docker_proxy]`` from config."""
    key = key or project_policy_key()
    policies = [load_policy_file(host_policy_path(key))]
    session = session_policy_path(key)
    if session.is_file():
        policies.append(load_policy_file(session))
    if config and isinstance(config.get("docker_proxy"), dict):
        policies.append(
            policy_from_mapping(config["docker_proxy"], where="config docker_proxy")
        )
    return merge_policies(*policies)


def declaration_from_config(config: Mapping[str, Any]) -> DockerProxyPolicy | None:
    """Return project declaration from ``[docker_proxy]`` if present."""
    raw = config.get("docker_proxy")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise click.ClickException("docker_proxy must be a table")
    return policy_from_mapping(raw, where="config docker_proxy")


def write_policy_file(path: Path, policy: DockerProxyPolicy) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Managed by buddelkiste docker-proxy. Prefer `bk docker-policy apply`.",
        "version = 1",
        "",
        "images = [",
    ]
    for ref in policy.images:
        lines.append(f"  {json.dumps(ref)},")
    lines.append("]")
    lines.append("")
    lines.append("[api]")
    lines.append("deny = [" + ", ".join(json.dumps(x) for x in policy.api_deny) + "]")
    lines.append("")
    lines.append("[host_config]")
    lines.append(
        "deny = [" + ", ".join(json.dumps(x) for x in policy.deny_host_config) + "]"
    )
    if policy.allow_binds:
        lines.append(
            "allow_binds = ["
            + ", ".join(json.dumps(x) for x in policy.allow_binds)
            + "]"
        )
    lines.append("")
    lines.append("[approval]")
    lines.append(f"on_unknown_image = {json.dumps(policy.on_unknown_image)}")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def resolve_docker_socket() -> Path:
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return Path(host.removeprefix("unix://"))
    if host and not host.startswith("unix:"):
        raise click.ClickException(
            f"docker-proxy only supports unix:// DOCKER_HOST (got {host!r})"
        )
    return Path("/var/run/docker.sock")


def _strip_api_prefix(path: str) -> str:
    return _API_PREFIX.sub("", path) or "/"


def _path_category(path: str) -> str | None:
    if _BUILD.search(path):
        return "build"
    if _COMMIT.search(path):
        return "commit"
    if _SWARM.search(path):
        return "swarm"
    if _PLUGINS.search(path):
        return "plugins"
    if _SESSION.search(path):
        return "session"
    return None


def _host_config_violations(
    host_config: Mapping[str, Any],
    policy: DockerProxyPolicy,
) -> list[str]:
    violations: list[str] = []
    for rule in policy.deny_host_config:
        if "=" in rule:
            key, value = rule.split("=", 1)
            actual = host_config.get(key)
            if actual is not None and str(actual) == value:
                violations.append(rule)
            continue
        actual = host_config.get(rule)
        if actual in (None, False, "", [], {}):
            continue
        violations.append(rule)

    binds = list(host_config.get("Binds") or [])
    mounts = host_config.get("Mounts") or []
    if isinstance(mounts, list):
        for mount in mounts:
            if isinstance(mount, dict) and mount.get("Type") == "bind":
                src = mount.get("Source") or mount.get("source")
                if src:
                    binds.append(str(src))
    if binds and not policy.allow_binds:
        violations.append("Binds")
    elif binds:
        for bind in binds:
            source = str(bind).split(":", 1)[0]
            if not any(fnmatch(source, pat) for pat in policy.allow_binds):
                violations.append(f"Binds:{source}")
    return violations


@dataclass
class ProxyDecision:
    allow: bool
    reason: str = ""


def evaluate_request(
    method: str,
    path: str,
    body: bytes,
    policy: DockerProxyPolicy,
) -> ProxyDecision:
    """Return whether a Docker API request may be forwarded."""
    path_only = path.split("?", 1)[0]
    category = _path_category(path_only)
    if category and category in policy.api_deny:
        return ProxyDecision(False, f"API category {category!r} is denied")

    if method == "POST" and _IMAGE_CREATE.match(path_only):
        parsed = urlparse(path if "://" in path else f"http://docker{path}")
        query = parse_qs(parsed.query)
        from_image = (query.get("fromImage") or [""])[0]
        tag = (query.get("tag") or [""])[0]
        ref = f"{from_image}:{tag}" if tag and from_image else from_image
        if not policy.allows_image(ref):
            return ProxyDecision(
                False, f"image pull not allowlisted: {ref or from_image}"
            )
        return ProxyDecision(True)

    if method == "POST" and _CONTAINER_CREATE.match(path_only):
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return ProxyDecision(False, f"invalid create JSON: {exc}")
        if not isinstance(payload, dict):
            return ProxyDecision(False, "container create body must be a JSON object")
        image = str(payload.get("Image") or "")
        if not policy.allows_image(image):
            return ProxyDecision(False, f"image not allowlisted: {image}")
        host_config = payload.get("HostConfig") or {}
        if not isinstance(host_config, dict):
            return ProxyDecision(False, "HostConfig must be an object")
        violations = _host_config_violations(host_config, policy)
        if violations:
            return ProxyDecision(
                False,
                "HostConfig denied: " + ", ".join(violations),
            )
        return ProxyDecision(True)

    return ProxyDecision(True)


def _read_http_request(conn: socket.socket) -> tuple[str, str, dict[str, str], bytes] | None:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf.extend(chunk)
        if len(buf) > 16 * 1024 * 1024:
            raise ValueError("HTTP headers too large")

    header_blob, rest = bytes(buf).split(b"\r\n\r\n", 1)
    lines = header_blob.split(b"\r\n")
    if not lines:
        return None
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ")
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1").title()] = value.decode("latin-1").strip()

    body = rest
    length = int(headers.get("Content-Length", "0") or "0")
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    body = body[:length]
    return method, path, headers, body


def _reject(conn: socket.socket, status: int, message: str) -> None:
    payload = json.dumps({"message": message}).encode()
    response = (
        f"HTTP/1.1 {status} Forbidden\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + payload
    try:
        conn.sendall(response)
    except OSError:
        pass


def _relay(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 60.0)
            if errored or not readable:
                break
            for src in readable:
                data = src.recv(65536)
                if not data:
                    return
                dst = b if src is a else a
                dst.sendall(data)
    except OSError:
        return


def _is_hijack_request(headers: Mapping[str, str]) -> bool:
    upgrade = headers.get("Upgrade", "")
    connection = headers.get("Connection", "")
    return bool(upgrade) or "upgrade" in connection.lower()


def _build_upstream_request(
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
) -> bytes:
    """Rebuild a client request for the Docker daemon.

    Preserve ``Upgrade`` / ``Connection: Upgrade`` so attach/exec hijacking
    still yields ``101 UPGRADED`` instead of a plain ``200`` with no stream.
    """
    hijack = _is_hijack_request(headers)
    header_lines = [f"{method} {path} HTTP/1.1"]
    skip = {"Content-Length", "Host"}
    if not hijack:
        skip.add("Connection")
    for key, value in headers.items():
        if key in skip:
            continue
        header_lines.append(f"{key}: {value}")
    header_lines.append("Host: localhost")
    header_lines.append(f"Content-Length: {len(body)}")
    if hijack:
        if "Upgrade" not in headers:
            header_lines.append("Upgrade: tcp")
        if "upgrade" not in headers.get("Connection", "").lower():
            header_lines.append("Connection: Upgrade")
    else:
        header_lines.append("Connection: close")
    return ("\r\n".join(header_lines) + "\r\n\r\n").encode("latin-1") + body


def _handle_client(
    client: socket.socket,
    docker_sock: Path,
    policy: DockerProxyPolicy,
) -> None:
    try:
        parsed = _read_http_request(client)
        if parsed is None:
            return
        method, path, headers, body = parsed
        decision = evaluate_request(method, path, body, policy)
        if not decision.allow:
            log.warning("docker-proxy deny %s %s: %s", method, path, decision.reason)
            _reject(client, 403, f"buddelkiste docker-proxy: {decision.reason}")
            return

        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(os.fspath(docker_sock))
        except OSError as exc:
            _reject(client, 502, f"cannot connect to Docker socket: {exc}")
            return

        try:
            upstream.sendall(_build_upstream_request(method, path, headers, body))
            client.settimeout(None)
            upstream.settimeout(None)
            _relay(client, upstream)
        finally:
            upstream.close()
    except Exception:
        log.exception("docker-proxy client handler failed")
    finally:
        try:
            client.close()
        except OSError:
            pass


class DockerProxyServer:
    """Background Docker API proxy bound to a Unix socket."""

    def __init__(
        self,
        listen_sock: Path,
        docker_sock: Path,
        policy: DockerProxyPolicy,
    ) -> None:
        self.listen_sock = listen_sock
        self.docker_sock = docker_sock
        self.policy = policy
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self.listen_sock.exists():
            self.listen_sock.unlink()
        self.listen_sock.parent.mkdir(parents=True, exist_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(os.fspath(self.listen_sock))
        server.listen(64)
        server.settimeout(0.5)
        self._server = server
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="docker-proxy", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            thread = threading.Thread(
                target=_handle_client,
                args=(client, self.docker_sock, self.policy),
                daemon=True,
            )
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self.listen_sock.exists():
            try:
                self.listen_sock.unlink()
            except OSError:
                pass


# Linux sockaddr_un.sun_path is typically 108 bytes including NUL.
_AF_UNIX_PATH_MAX = 107


def _short_listen_socket(runtime_dir: Path | None = None) -> Path:
    """Return a Unix socket path that fits in ``sockaddr_un.sun_path``."""
    pid = os.getpid()
    name = f"bk-dp-{pid}.sock"
    candidates: list[Path] = []
    if runtime_dir is not None:
        candidates.append(runtime_dir / name)
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidates.append(Path(xdg) / name)
    candidates.append(Path(tempfile.gettempdir()) / name)
    candidates.append(Path("/tmp") / name)

    for path in candidates:
        encoded = os.fspath(path).encode()
        if len(encoded) <= _AF_UNIX_PATH_MAX:
            path.parent.mkdir(parents=True, exist_ok=True)
            return path

    # Last resort: tiny name under /tmp.
    fallback = Path("/tmp") / f"b{pid}.s"
    if len(os.fspath(fallback).encode()) > _AF_UNIX_PATH_MAX:
        raise click.ClickException(
            "cannot find a short enough path for the docker-proxy Unix socket"
        )
    return fallback


@contextmanager
def docker_proxy_setup(
    *,
    policy: DockerProxyPolicy | None = None,
    config: Mapping[str, Any] | None = None,
    runtime_dir: Path | None = None,
) -> Iterator[Sequence[str]]:
    """Start the proxy and yield bwrap args that expose only the filtered socket."""
    docker_sock = resolve_docker_socket()
    if not docker_sock.exists():
        raise click.ClickException(f"Docker socket not found at {docker_sock}")

    effective = policy or load_effective_policy(config=config)
    listen = _short_listen_socket(runtime_dir)
    server = DockerProxyServer(listen, docker_sock, effective)
    server.start()
    host = f"unix://{listen}"
    try:
        yield [
            "--ro-bind",
            str(listen),
            str(listen),
            "--setenv",
            "DOCKER_HOST",
            host,
        ]
    finally:
        server.stop()
