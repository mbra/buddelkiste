"""Project-scoped rootless Docker daemon for the ``docker-instance`` feature.

Starts a temporary user dockerd with a dedicated ``data_root``, optionally
FS-jails the daemon mount namespace, and exposes the Engine API to the sandbox
through the filtered ``DockerProxyServer`` (unless ``proxy = false``).
"""

from __future__ import annotations

import logging
import os
import pwd
import shutil
import signal
import subprocess
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click

from buddelkiste.docker_proxy import (
    DEFAULT_DENY_HOST_CONFIG,
    DockerProxyPolicy,
    DockerProxyServer,
    _find_project_config,
    _short_listen_socket,
    host_policy_path,
    policy_from_mapping,
    project_policy_key,
    write_policy_file,
)

log = logging.getLogger(__name__)

FS_MODES = frozenset({"host", "project", "data"})
NET_MODES = frozenset({"host", "userspace", "none"})

# Instance defaults: allow build; deny other high-risk API categories.
INSTANCE_API_DENY = ("commit", "swarm", "plugins", "session")

_MINIMAL_RO_BINDS = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/alternatives",
)


@dataclass(frozen=True)
class DockerInstanceConfig:
    """Settings for a project-local rootless Docker daemon."""

    data_root: Path | None = None
    fs: str = "project"
    fs_allow: tuple[str, ...] = ()
    net: str = "userspace"
    proxy: bool = True
    policy: DockerProxyPolicy = field(default_factory=lambda: _default_instance_policy())


def _default_instance_policy() -> DockerProxyPolicy:
    return DockerProxyPolicy(
        images=("*",),
        api_deny=INSTANCE_API_DENY,
        deny_host_config=DEFAULT_DENY_HOST_CONFIG,
        allow_binds=(),
        on_unknown_image="deny",
    )


def _xdg_data_home() -> Path:
    raw = os.environ.get("XDG_DATA_HOME")
    if raw:
        return Path(raw)
    return Path.home() / ".local" / "share"


def default_data_root(key: str | None = None) -> Path:
    """Default store: ``$XDG_DATA_HOME/buddelkiste/docker-instance/<key>``."""
    return _xdg_data_home() / "buddelkiste" / "docker-instance" / (key or project_policy_key())


def project_root(start: Path | None = None) -> Path:
    """Directory that owns ``.buddelkiste.toml``, else cwd."""
    cur = (start or Path.cwd()).resolve()
    cfg = _find_project_config(cur)
    return cfg.parent if cfg is not None else cur


def instance_policy_from_mapping(
    data: Mapping[str, Any] | None,
    *,
    where: str = "config docker_instance.policy",
) -> DockerProxyPolicy:
    """Parse policy with instance-oriented defaults (allow build, images ``*``)."""
    raw: dict[str, Any] = dict(data or {})
    if "images" not in raw:
        raw["images"] = ["*"]
    api = raw.get("api")
    if not isinstance(api, dict):
        api = {}
    else:
        api = dict(api)
    if "deny" not in api:
        api["deny"] = list(INSTANCE_API_DENY)
    raw["api"] = api
    if "on_unknown_image" not in raw and not isinstance(raw.get("approval"), dict):
        raw["on_unknown_image"] = "deny"
    elif (
        isinstance(raw.get("approval"), dict)
        and "on_unknown_image" not in raw["approval"]
        and "on_unknown_image" not in raw
    ):
        approval = dict(raw["approval"])
        approval["on_unknown_image"] = "deny"
        raw["approval"] = approval
    return policy_from_mapping(raw, where=where)


def config_from_mapping(
    data: Mapping[str, Any],
    *,
    where: str = "config docker_instance",
) -> DockerInstanceConfig:
    if not isinstance(data, dict):
        raise click.ClickException(f"{where} must be a table")

    fs = str(data.get("fs", "project"))
    if fs not in FS_MODES:
        raise click.ClickException(
            f"{where}.fs must be one of {sorted(FS_MODES)} (got {fs!r})"
        )
    net = str(data.get("net", "userspace"))
    if net not in NET_MODES:
        raise click.ClickException(
            f"{where}.net must be one of {sorted(NET_MODES)} (got {net!r})"
        )

    fs_allow_raw = data.get("fs_allow", [])
    if not isinstance(fs_allow_raw, list):
        raise click.ClickException(f"{where}.fs_allow must be a list of paths")
    fs_allow = tuple(str(x) for x in fs_allow_raw)

    data_root_raw = data.get("data_root")
    data_root: Path | None = None
    if data_root_raw is not None and str(data_root_raw).strip():
        data_root = Path(os.path.expandvars(str(data_root_raw))).expanduser()

    proxy = bool(data.get("proxy", True))

    policy_raw = data.get("policy")
    if policy_raw is None:
        policy = _default_instance_policy()
    elif not isinstance(policy_raw, dict):
        raise click.ClickException(f"{where}.policy must be a table")
    else:
        policy = instance_policy_from_mapping(policy_raw, where=f"{where}.policy")

    unknown = set(data) - {
        "data_root",
        "fs",
        "fs_allow",
        "net",
        "proxy",
        "policy",
    }
    if unknown:
        keys = ", ".join(sorted(unknown))
        raise click.ClickException(f"{where} has unknown keys: {keys}")

    return DockerInstanceConfig(
        data_root=data_root,
        fs=fs,
        fs_allow=fs_allow,
        net=net,
        proxy=proxy,
        policy=policy,
    )


def load_instance_config(config: Mapping[str, Any] | None) -> DockerInstanceConfig:
    raw = (config or {}).get("docker_instance")
    if raw is None:
        return DockerInstanceConfig()
    if not isinstance(raw, dict):
        raise click.ClickException("docker_instance must be a table")
    return config_from_mapping(raw)


def _username() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


def _subid_has_user(path: Path, user: str) -> bool:
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    prefix = f"{user}:"
    return any(line.strip().startswith(prefix) for line in text.splitlines())


def check_rootless_prerequisites() -> None:
    """Raise if rootless dockerd cannot be started on this host."""
    missing: list[str] = []
    for name in ("dockerd", "rootlesskit", "newuidmap", "newgidmap", "bwrap"):
        if shutil.which(name) is None:
            missing.append(name)
    if missing:
        raise click.ClickException(
            "docker-instance requires: "
            + ", ".join(missing)
            + " (Arch: pacman -S docker rootlesskit shadow bubblewrap; "
            "also fuse-overlayfs and slirp4netns/passt recommended)"
        )
    user = _username()
    if not _subid_has_user(Path("/etc/subuid"), user):
        raise click.ClickException(
            f"docker-instance needs a /etc/subuid entry for {user!r} "
            f"(e.g. '{user}:100000:65536')"
        )
    if not _subid_has_user(Path("/etc/subgid"), user):
        raise click.ClickException(
            f"docker-instance needs a /etc/subgid entry for {user!r} "
            f"(e.g. '{user}:100000:65536')"
        )


def expand_fs_allow(paths: Sequence[str]) -> list[Path]:
    result: list[Path] = []
    for raw in paths:
        path = Path(os.path.expandvars(raw)).expanduser().resolve()
        if not path.exists():
            raise click.ClickException(
                f"docker_instance.fs_allow path does not exist: {path}"
            )
        result.append(path)
    return result


def rootlesskit_net_args(net: str) -> list[str]:
    """Map ``net`` mode to rootlesskit ``--net=…`` and related flags."""
    if net == "host":
        return ["--net=host"]
    if net == "none":
        return ["--net=none"]
    # userspace: prefer pasta, then slirp4netns
    if shutil.which("pasta"):
        return ["--net=pasta", "--copy-up=/etc", "--copy-up=/run"]
    if shutil.which("slirp4netns"):
        return ["--net=slirp4netns", "--copy-up=/etc", "--copy-up=/run"]
    raise click.ClickException(
        "docker-instance net=userspace needs pasta (passt) or slirp4netns"
    )


def _ro_bind_if_exists(host: str) -> list[str]:
    path = Path(host)
    if not path.exists():
        return []
    return ["--ro-bind", str(path), str(path)]


def daemon_bwrap_prefix(
    *,
    fs: str,
    data_root: Path,
    project: Path,
    runtime_dir: Path,
    fs_allow: Sequence[Path],
    net: str,
) -> list[str]:
    """bwrap argv prefix that FS-jails the daemon (no ``--unshare-user``)."""
    if fs == "host":
        return []

    args: list[str] = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/run",
        "--dir",
        str(runtime_dir),
    ]
    if net == "none":
        args.append("--unshare-net")

    for host in _MINIMAL_RO_BINDS:
        args.extend(_ro_bind_if_exists(host))

    # Dynamic linker paths on some distros
    for host in ("/lib32", "/usr/lib32", "/usr/local"):
        args.extend(_ro_bind_if_exists(host))

    data_root.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    args.extend(["--bind", str(data_root), str(data_root)])
    args.extend(["--bind", str(runtime_dir), str(runtime_dir)])

    if fs == "project":
        project.mkdir(parents=True, exist_ok=True)
        args.extend(["--bind", str(project), str(project)])
        args.extend(["--chdir", str(project)])
    else:
        args.extend(["--chdir", str(data_root)])

    for path in fs_allow:
        args.extend(["--bind", str(path), str(path)])

    args.append("--")
    return args


def build_dockerd_command(
    *,
    data_root: Path,
    exec_root: Path,
    pidfile: Path,
    sock: Path,
    net: str,
    fs: str,
    project: Path,
    runtime_dir: Path,
    fs_allow: Sequence[Path],
) -> list[str]:
    """Full argv to launch rootless dockerd (optional bwrap + rootlesskit)."""
    data_root.mkdir(parents=True, exist_ok=True)
    exec_root.mkdir(parents=True, exist_ok=True)
    sock.parent.mkdir(parents=True, exist_ok=True)

    dockerd = [
        "dockerd",
        f"--data-root={data_root}",
        f"--exec-root={exec_root}",
        f"--pidfile={pidfile}",
        f"-H=unix://{sock}",
        "--containerd-namespace=buddelkiste-instance",
        "--iptables=true",
        "--ip-forward=false",
    ]
    rootlesskit = [
        "rootlesskit",
        f"--state-dir={exec_root / 'rootlesskit'}",
        *rootlesskit_net_args(net),
        *dockerd,
    ]
    prefix = daemon_bwrap_prefix(
        fs=fs,
        data_root=data_root,
        project=project,
        runtime_dir=runtime_dir,
        fs_allow=fs_allow,
        net=net,
    )
    return [*prefix, *rootlesskit]


def _wait_for_socket(
    sock: Path,
    proc: subprocess.Popen,
    *,
    timeout: float = 30.0,
    log_path: Path | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sock.exists():
            return
        if proc.poll() is not None:
            stderr = ""
            if log_path is not None and log_path.is_file():
                try:
                    stderr = log_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
            raise click.ClickException(
                f"docker-instance dockerd exited early (code {proc.returncode})"
                + (f": {stderr.strip()[-2000:]}" if stderr.strip() else "")
            )
        time.sleep(0.05)
    raise click.ClickException(
        f"docker-instance timed out waiting for daemon socket {sock}"
    )


def _stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
    except OSError:
        return
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


@contextmanager
def docker_instance_setup(
    *,
    config: Mapping[str, Any] | None = None,
    instance: DockerInstanceConfig | None = None,
    runtime_dir: Path | None = None,
) -> Iterator[Sequence[str]]:
    """Start project dockerd (+ optional proxy) and yield agent bwrap args."""
    check_rootless_prerequisites()
    cfg = instance or load_instance_config(config)
    key = project_policy_key()
    data_root = (cfg.data_root or default_data_root(key)).resolve()
    project = project_root()
    fs_allow = expand_fs_allow(cfg.fs_allow)

    xdg_runtime = Path(os.environ["XDG_RUNTIME_DIR"]) if os.environ.get("XDG_RUNTIME_DIR") else None
    base_runtime = runtime_dir or (xdg_runtime / "bk-docker-instance" if xdg_runtime else Path("/tmp") / f"bk-di-{os.getpid()}")
    base_runtime = base_runtime.resolve()
    base_runtime.mkdir(parents=True, exist_ok=True)

    exec_root = base_runtime / "exec"
    pidfile = exec_root / "dockerd.pid"
    daemon_sock = _short_listen_socket(base_runtime)
    # Prefer a stable name under our runtime dir when path length allows.
    preferred = base_runtime / "docker.sock"
    if len(os.fspath(preferred).encode()) <= 107:
        daemon_sock = preferred

    cmd = build_dockerd_command(
        data_root=data_root,
        exec_root=exec_root,
        pidfile=pidfile,
        sock=daemon_sock,
        net=cfg.net,
        fs=cfg.fs,
        project=project,
        runtime_dir=base_runtime,
        fs_allow=fs_allow,
    )
    log.info("docker-instance starting: %s", " ".join(cmd))
    log_path = base_runtime / "dockerd.log"
    log_file = log_path.open("wb")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=log_file,
        start_new_session=True,
    )
    proxy: DockerProxyServer | None = None
    try:
        _wait_for_socket(daemon_sock, proc, log_path=log_path)
        if cfg.proxy:
            policy_key = f"instance-{key}"
            # Persist instance policy so control-socket reload keeps api_deny/build
            # defaults (empty host store would otherwise fall back to docker-proxy
            # defaults that deny build).
            write_policy_file(host_policy_path(policy_key), cfg.policy)
            listen = _short_listen_socket(base_runtime)
            proxy = DockerProxyServer(
                listen,
                daemon_sock,
                cfg.policy,
                policy_key=policy_key,
                config=None,
            )
            proxy.start()
            host = f"unix://{listen}"
            yield [
                "--ro-bind",
                str(listen),
                str(listen),
                "--setenv",
                "DOCKER_HOST",
                host,
            ]
        else:
            host = f"unix://{daemon_sock}"
            yield [
                "--ro-bind",
                str(daemon_sock),
                str(daemon_sock),
                "--setenv",
                "DOCKER_HOST",
                host,
            ]
    finally:
        if proxy is not None:
            proxy.stop()
        _stop_process(proc)
        try:
            log_file.close()
        except OSError:
            pass
        if daemon_sock.exists():
            try:
                daemon_sock.unlink()
            except OSError:
                log.warning("failed to unlink docker-instance socket %s", daemon_sock)
