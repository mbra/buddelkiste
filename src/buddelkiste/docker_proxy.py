"""Filtered Docker Engine API proxy for the ``docker-proxy`` feature.

Listens on a Unix socket, forwards allowed requests to the real Docker socket,
and rejects container creates / image pulls that violate the allowlist or
dangerous HostConfig fields.

When ``on_unknown_image`` is ``session``, unknown image pulls/creates are held
until ``bk docker-policy approve`` / ``deny`` resolves them via the control
socket (so the agent TTY is not used for the prompt). A desktop notification
is raised when a new pending approval appears (best-effort via ``notify-send``).
"""

from __future__ import annotations

import json
import logging
import os
import re
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import tomllib
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
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
    # deny: immediate 403. session: hold until CLI approve/deny; approve → session file.
    on_unknown_image: str = "session"

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


def runtime_path(key: str | None = None) -> Path:
    """Metadata for a live docker-proxy (control socket path, pid)."""
    return policy_dir() / f"{key or project_policy_key()}.runtime.json"


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

    api = data.get("api", {})
    if not isinstance(api, dict):
        raise click.ClickException(f"{where}: api must be a table")
    api_deny = (
        tuple(str(x) for x in api.get("deny", DEFAULT_API_DENY)) if api else DEFAULT_API_DENY
    )

    host_config = data.get("host_config", {})
    if not isinstance(host_config, dict):
        raise click.ClickException(f"{where}: host_config must be a table")
    deny_hc = (
        tuple(str(x) for x in host_config.get("deny", DEFAULT_DENY_HOST_CONFIG))
        if host_config
        else DEFAULT_DENY_HOST_CONFIG
    )
    allow_binds = (
        tuple(str(x) for x in host_config.get("allow_binds", ())) if host_config else ()
    )

    approval = data.get("approval", {})
    if not isinstance(approval, dict):
        raise click.ClickException(f"{where}: approval must be a table")
    on_unknown = str(
        approval.get("on_unknown_image", data.get("on_unknown_image", "session"))
    )
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
    on_unknown = "session"
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


def grant_session_image(image: str, *, key: str | None = None) -> Path:
    """Append ``image`` to the session policy file; return the path written."""
    key = key or project_policy_key()
    path = session_policy_path(key)
    current = load_policy_file(path)
    normalized = _normalize_image_ref(image)
    if not normalized:
        raise click.ClickException("empty image reference")
    if current.allows_image(normalized):
        return path
    images = list(current.images) + [normalized]
    write_policy_file(
        path,
        DockerProxyPolicy(
            images=tuple(images),
            api_deny=current.api_deny,
            deny_host_config=current.deny_host_config,
            allow_binds=current.allow_binds,
            on_unknown_image=current.on_unknown_image,
        ),
    )
    return path


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
    image: str = ""
    # True when the only blocker is the image allowlist (eligible for session hold).
    image_blocked: bool = False


def _image_ref_from_pull(path: str) -> str:
    parsed = urlparse(path if "://" in path else f"http://docker{path}")
    query = parse_qs(parsed.query)
    from_image = (query.get("fromImage") or [""])[0]
    tag = (query.get("tag") or [""])[0]
    if tag and from_image:
        return f"{from_image}:{tag}"
    return from_image


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
        ref = _image_ref_from_pull(path)
        if not policy.allows_image(ref):
            return ProxyDecision(
                False,
                f"image pull not allowlisted: {ref or '(empty)'}",
                image=_normalize_image_ref(ref),
                image_blocked=True,
            )
        return ProxyDecision(True, image=_normalize_image_ref(ref))

    if method == "POST" and _CONTAINER_CREATE.match(path_only):
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return ProxyDecision(False, f"invalid create JSON: {exc}")
        if not isinstance(payload, dict):
            return ProxyDecision(False, "container create body must be a JSON object")
        image = str(payload.get("Image") or "")
        normalized = _normalize_image_ref(image)
        if not policy.allows_image(image):
            return ProxyDecision(
                False,
                f"image not allowlisted: {image}",
                image=normalized,
                image_blocked=True,
            )
        host_config = payload.get("HostConfig")
        if host_config is None:
            host_config = {}
        if not isinstance(host_config, dict):
            return ProxyDecision(False, "HostConfig must be an object", image=normalized)
        violations = _host_config_violations(host_config, policy)
        if violations:
            return ProxyDecision(
                False,
                "HostConfig denied: " + ", ".join(violations),
                image=normalized,
            )
        return ProxyDecision(True, image=normalized)

    return ProxyDecision(True)


_MAX_HTTP_HEADERS = 16 * 1024 * 1024


def _read_http_request(conn: socket.socket) -> tuple[str, str, dict[str, str], bytes] | None:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf.extend(chunk)
        if len(buf) > _MAX_HTTP_HEADERS:
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
    """Bidirectional copy until both sides finish.

    Docker attach/exec often half-closes the client write side right after the
    HTTP request (readable EOF) while still reading the upgraded stream. Treat
    that as ``SHUT_WR`` toward the peer, not as tearing down the whole relay.
    """
    sockets = {a, b}
    try:
        while sockets:
            watch: list[socket.socket] = []
            for sock in tuple(sockets):
                try:
                    if sock.fileno() < 0:
                        sockets.discard(sock)
                        continue
                except OSError:
                    sockets.discard(sock)
                    continue
                watch.append(sock)
            if not watch:
                break
            try:
                readable, _, errored = select.select(watch, [], watch, 60.0)
            except (ValueError, OSError):
                # Closed/invalid fds (fileno -1) race with teardown.
                break
            if errored:
                break
            if not readable:
                # Idle timeout: keep waiting; attach streams can be quiet.
                continue
            for src in readable:
                try:
                    data = src.recv(65536)
                except OSError:
                    data = b""
                dst = b if src is a else a
                if not data:
                    sockets.discard(src)
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    dst.sendall(data)
                except OSError:
                    return
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
    server: DockerProxyServer,
) -> None:
    try:
        parsed = _read_http_request(client)
        if parsed is None:
            return
        method, path, headers, body = parsed
        policy = server.current_policy()
        decision = evaluate_request(method, path, body, policy)
        if not decision.allow:
            if (
                decision.image_blocked
                and decision.image
                and policy.on_unknown_image == "session"
            ):
                log.warning(
                    "docker-proxy waiting for approval of image %s (%s %s)",
                    decision.image,
                    method,
                    path.split("?", 1)[0],
                )
                approved = server.wait_for_image_approval(decision.image)
                if approved:
                    # Re-evaluate with the reloaded policy (HostConfig still enforced).
                    decision = evaluate_request(
                        method, path, body, server.current_policy()
                    )
                else:
                    decision = ProxyDecision(
                        False,
                        f"image approval denied: {decision.image}",
                        image=decision.image,
                        image_blocked=True,
                    )
            if not decision.allow:
                log.warning(
                    "docker-proxy deny %s %s: %s", method, path, decision.reason
                )
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


@dataclass
class _PendingImage:
    id: str
    image: str
    created: float
    event: threading.Event = field(default_factory=threading.Event)
    approved: bool | None = None


def _notify_pending_image_approval(pending_id: str, image: str) -> None:
    """Best-effort desktop notification for a held image (does not touch the TTY)."""
    notify = shutil.which("notify-send")
    if not notify:
        log.warning(
            "notify-send not found; cannot notify for pending image approval "
            "id=%s image=%s (bk docker-policy approve %s)",
            pending_id,
            image,
            pending_id,
        )
        return
    title = "buddelkiste docker-proxy"
    body = (
        f"Approval required for image {image}\n"
        f"bk docker-policy approve {pending_id}"
    )
    try:
        subprocess.Popen(
            [
                notify,
                "--app-name=buddelkiste",
                "--urgency=normal",
                "--icon=dialog-question",
                "--expire-time=0",
                title,
                body,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        log.warning(
            "notify-send failed for pending image approval id=%s image=%s",
            pending_id,
            image,
            exc_info=True,
        )


class DockerProxyServer:
    """Background Docker API proxy bound to a Unix socket."""

    def __init__(
        self,
        listen_sock: Path,
        docker_sock: Path,
        policy: DockerProxyPolicy,
        *,
        policy_key: str | None = None,
        config: Mapping[str, Any] | None = None,
        control_sock: Path | None = None,
    ) -> None:
        self.listen_sock = listen_sock
        self.docker_sock = docker_sock
        self._policy = policy
        self._policy_lock = threading.RLock()
        self.policy_key = policy_key or project_policy_key()
        self._config = config
        self.control_sock = control_sock or listen_sock.with_suffix(".ctl")
        self._server: socket.socket | None = None
        self._control: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._control_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._pending_lock = threading.Lock()
        # image -> pending (coalesce concurrent waits for the same image)
        self._pending: dict[str, _PendingImage] = {}

    def current_policy(self) -> DockerProxyPolicy:
        with self._policy_lock:
            return self._policy

    def reload_policy(self) -> DockerProxyPolicy:
        with self._policy_lock:
            self._policy = load_effective_policy(
                key=self.policy_key, config=self._config
            )
            return self._policy

    def wait_for_image_approval(self, image: str) -> bool:
        """Block until approve/deny for ``image``; return True if approved."""
        normalized = _normalize_image_ref(image)
        notify = False
        with self._pending_lock:
            pending = self._pending.get(normalized)
            if pending is None:
                pending = _PendingImage(
                    id=uuid.uuid4().hex[:8],
                    image=normalized,
                    created=time.time(),
                )
                self._pending[normalized] = pending
                notify = True
                log.warning(
                    "docker-proxy pending approval id=%s image=%s "
                    "(bk docker-policy approve %s)",
                    pending.id,
                    normalized,
                    pending.id,
                )
            event = pending.event
            pending_id = pending.id
        if notify:
            _notify_pending_image_approval(pending_id, normalized)
        event.wait()
        with self._pending_lock:
            # approved may be None if woken by stop(); treat as deny
            return bool(pending.approved)

    def list_pending(self) -> list[dict[str, Any]]:
        with self._pending_lock:
            return [
                {
                    "id": p.id,
                    "image": p.image,
                    "created": p.created,
                }
                for p in sorted(self._pending.values(), key=lambda x: x.created)
            ]

    def resolve_pending(
        self, *, target: str | None = None, approve: bool
    ) -> dict[str, Any]:
        """Approve or deny a pending image by id or image ref."""
        with self._pending_lock:
            if not self._pending:
                raise click.ClickException("no pending image approvals")
            pending: _PendingImage | None = None
            if target is None:
                if len(self._pending) != 1:
                    ids = ", ".join(
                        f"{p.id} ({p.image})" for p in self._pending.values()
                    )
                    raise click.ClickException(
                        f"multiple pending approvals; specify id or image: {ids}"
                    )
                pending = next(iter(self._pending.values()))
            else:
                for p in self._pending.values():
                    if p.id == target or p.image == target:
                        pending = p
                        break
                if pending is None:
                    # Allow matching un-normalized target against stored image.
                    want = _normalize_image_ref(target)
                    for p in self._pending.values():
                        if p.image == want:
                            pending = p
                            break
                if pending is None:
                    raise click.ClickException(f"no pending approval matching {target!r}")

            image = pending.image
            if approve:
                grant_session_image(image, key=self.policy_key)
                with self._policy_lock:
                    if not self._policy.allows_image(image):
                        self._policy = DockerProxyPolicy(
                            images=(*self._policy.images, image),
                            api_deny=self._policy.api_deny,
                            deny_host_config=self._policy.deny_host_config,
                            allow_binds=self._policy.allow_binds,
                            on_unknown_image=self._policy.on_unknown_image,
                        )
                    # Merge host/session/config files so apply() edits take effect.
                    disk = load_effective_policy(
                        key=self.policy_key, config=self._config
                    )
                    self._policy = merge_policies(self._policy, disk)
            pending.approved = approve
            self._pending.pop(image, None)
            pending.event.set()

        return {"id": pending.id, "image": image, "approved": approve}

    def _write_runtime(self) -> None:
        path = runtime_path(self.policy_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "policy_key": self.policy_key,
                    "control_sock": os.fspath(self.control_sock),
                    "proxy_sock": os.fspath(self.listen_sock),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def _clear_runtime(self) -> None:
        path = runtime_path(self.policy_key)
        try:
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("pid") == os.getpid():
                    path.unlink()
        except (OSError, json.JSONDecodeError):
            pass

    def start(self) -> None:
        if self.listen_sock.exists():
            self.listen_sock.unlink()
        if self.control_sock.exists():
            self.control_sock.unlink()
        self.listen_sock.parent.mkdir(parents=True, exist_ok=True)
        self.control_sock.parent.mkdir(parents=True, exist_ok=True)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(os.fspath(self.listen_sock))
        server.listen(64)
        server.settimeout(0.5)
        self._server = server

        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        control.bind(os.fspath(self.control_sock))
        control.listen(8)
        control.settimeout(0.5)
        self._control = control

        self._stop.clear()
        self._write_runtime()
        self._thread = threading.Thread(target=self._serve, name="docker-proxy", daemon=True)
        self._thread.start()
        self._control_thread = threading.Thread(
            target=self._serve_control, name="docker-proxy-ctl", daemon=True
        )
        self._control_thread.start()

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
                args=(client, self.docker_sock, self),
                daemon=True,
            )
            thread.start()

    def _serve_control(self) -> None:
        assert self._control is not None
        while not self._stop.is_set():
            try:
                client, _ = self._control.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            thread = threading.Thread(
                target=self._handle_control_client,
                args=(client,),
                daemon=True,
            )
            thread.start()

    def _handle_control_client(self, client: socket.socket) -> None:
        try:
            raw = _recv_json_line(client)
            if raw is None:
                return
            response = self._dispatch_control(raw)
            client.sendall((json.dumps(response) + "\n").encode())
        except Exception as exc:
            log.exception("docker-proxy control handler failed")
            try:
                client.sendall(
                    (json.dumps({"ok": False, "error": str(exc)}) + "\n").encode()
                )
            except OSError:
                pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _dispatch_control(self, req: Mapping[str, Any]) -> dict[str, Any]:
        op = str(req.get("op") or "")
        if op == "list":
            return {"ok": True, "pending": self.list_pending()}
        if op in {"approve", "deny"}:
            target = req.get("target")
            target_s = str(target) if target is not None else None
            try:
                result = self.resolve_pending(
                    target=target_s, approve=(op == "approve")
                )
            except click.ClickException as exc:
                return {"ok": False, "error": str(exc)}
            return {"ok": True, **result}
        return {"ok": False, "error": f"unknown op {op!r}"}

    def stop(self) -> None:
        self._stop.set()
        with self._pending_lock:
            for pending in list(self._pending.values()):
                pending.approved = False
                pending.event.set()
            self._pending.clear()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._control is not None:
            try:
                self._control.close()
            except OSError:
                pass
            self._control = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._control_thread is not None:
            self._control_thread.join(timeout=2.0)
            self._control_thread = None
        self._clear_runtime()
        for path in (self.listen_sock, self.control_sock):
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass


def _recv_json_line(conn: socket.socket, *, limit: int = 64 * 1024) -> dict[str, Any] | None:
    buf = bytearray()
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > limit:
            raise ValueError("control message too large")
    if not buf:
        return None
    line = bytes(buf).split(b"\n", 1)[0]
    data = json.loads(line.decode())
    if not isinstance(data, dict):
        raise ValueError("control message must be a JSON object")
    return data


def read_runtime(*, key: str | None = None) -> dict[str, Any]:
    path = runtime_path(key)
    if not path.is_file():
        raise click.ClickException(
            f"no live docker-proxy for this project ({path} missing); "
            "start a sandbox with the docker-proxy feature first"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"invalid runtime file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise click.ClickException(f"invalid runtime file {path}")
    return data


def control_request(
    req: Mapping[str, Any],
    *,
    key: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Send a JSON control request to the live docker-proxy for this project."""
    runtime = read_runtime(key=key)
    sock_path = runtime.get("control_sock")
    if not sock_path:
        raise click.ClickException("runtime file missing control_sock")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(os.fspath(sock_path))
        client.sendall((json.dumps(dict(req)) + "\n").encode())
        resp = _recv_json_line(client)
    except OSError as exc:
        raise click.ClickException(
            f"cannot connect to docker-proxy control socket {sock_path}: {exc}"
        ) from exc
    finally:
        try:
            client.close()
        except OSError:
            pass
    if resp is None:
        raise click.ClickException("empty response from docker-proxy control socket")
    return resp


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
        # Leave room for a sibling ``.ctl`` control socket with the same stem.
        ctl = path.with_suffix(".ctl")
        if (
            len(encoded) <= _AF_UNIX_PATH_MAX
            and len(os.fspath(ctl).encode()) <= _AF_UNIX_PATH_MAX
        ):
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
    policy_key: str | None = None,
) -> Iterator[Sequence[str]]:
    """Start the proxy and yield bwrap args that expose only the filtered socket."""
    docker_sock = resolve_docker_socket()
    if not docker_sock.exists():
        raise click.ClickException(f"Docker socket not found at {docker_sock}")

    key = policy_key or project_policy_key()
    effective = policy or load_effective_policy(key=key, config=config)
    listen = _short_listen_socket(runtime_dir)
    server = DockerProxyServer(
        listen,
        docker_sock,
        effective,
        policy_key=key,
        config=config,
    )
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
