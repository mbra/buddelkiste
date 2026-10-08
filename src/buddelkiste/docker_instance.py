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
import socket
import subprocess
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
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
from buddelkiste.which import path_with_tools, which

log = logging.getLogger(__name__)


# dockerd looks these up itself via PATH. which() finds them in sbin; the
# directory is then prepended so the child process can exec them by name.
_DAEMON_TOOLS = ("iptables", "ip6tables", "nft", "sysctl")


def daemon_tool_path(base: str | None = None) -> str:
    """Return PATH for dockerd, including sbin when the tools live there."""
    return path_with_tools(_DAEMON_TOOLS, base)


FS_MODES = frozenset({"host", "project", "data"})
NET_MODES = frozenset({"host", "userspace", "none"})
STORAGE_DRIVERS = frozenset({"auto", "overlay2", "fuse-overlayfs", "vfs"})

# Instance defaults: allow build + BuildKit /session; deny other high-risk APIs.
INSTANCE_API_DENY = ("commit", "swarm", "plugins")

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
    # rootlesskit needs these inside the FS jail to build uid/gid maps
    "/etc/subuid",
    "/etc/subgid",
)


_cli_overrides: ContextVar[dict[str, Any] | None] = ContextVar(
    "bk_docker_instance_cli", default=None
)


@dataclass(frozen=True)
class DockerInstanceConfig:
    """Settings for a project-local rootless Docker daemon."""

    data_root: Path | None = None
    fs: str = "project"
    fs_allow: tuple[str, ...] = ()
    net: str = "userspace"
    proxy: bool = True
    remove_data_on_teardown: bool = False
    storage_driver: str = "auto"
    policy: DockerProxyPolicy = field(default_factory=lambda: _default_instance_policy())


@dataclass(frozen=True)
class InstanceStore:
    """One project-local docker-instance data_root on disk."""

    name: str
    path: Path
    size: int
    current: bool = False


@contextmanager
def instance_cli_overrides(**kwargs: Any) -> Iterator[None]:
    """Apply ``bk run`` flags on top of ``[docker_instance]`` for this process."""
    filtered = {key: value for key, value in kwargs.items() if value is not None}
    token = _cli_overrides.set(filtered)
    try:
        yield
    finally:
        _cli_overrides.reset(token)


def _apply_cli_overrides(cfg: DockerInstanceConfig) -> DockerInstanceConfig:
    raw = _cli_overrides.get()
    if not raw:
        return cfg
    updates: dict[str, Any] = {}
    if "remove_data_on_teardown" in raw:
        updates["remove_data_on_teardown"] = bool(raw["remove_data_on_teardown"])
    if "storage_driver" in raw:
        updates["storage_driver"] = parse_storage_driver(
            raw["storage_driver"], where="--docker-instance-storage-driver"
        )
    return replace(cfg, **updates) if updates else cfg


def parse_storage_driver(raw: object, *, where: str) -> str:
    """Normalize a storage-driver name; ``auto`` means omit dockerd's flag."""
    driver = str(raw or "auto").strip() or "auto"
    if driver not in STORAGE_DRIVERS:
        allowed = ", ".join(sorted(STORAGE_DRIVERS))
        raise click.ClickException(f"{where} must be one of {allowed} (got {driver!r})")
    return driver


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


def instance_store_home() -> Path:
    """Parent directory of default per-project docker-instance stores."""
    return _xdg_data_home() / "buddelkiste" / "docker-instance"


def default_data_root(key: str | None = None) -> Path:
    """Default store: ``$XDG_DATA_HOME/buddelkiste/docker-instance/<key>``."""
    return instance_store_home() / (key or project_policy_key())


def directory_size_bytes(path: Path) -> int:
    """Best-effort recursive size; skips unreadable overlay work dirs."""
    try:
        st = path.lstat()
    except OSError:
        return 0
    total = st.st_size
    if path.is_symlink() or not path.is_dir():
        return total
    try:
        children = list(path.iterdir())
    except OSError:
        return total
    for child in children:
        total += directory_size_bytes(child)
    return total


def format_bytes(n: int) -> str:
    """Human-readable byte count (binary units)."""
    size = float(n)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = units[0]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            break
        size /= 1024.0
    if unit == "B":
        return f"{n}B"
    return f"{size:.1f}{unit}"


def list_instance_stores(
    *,
    config: Mapping[str, Any] | None = None,
    current_key: str | None = None,
) -> list[InstanceStore]:
    """Stores under the default home, plus the current project's data_root."""
    key = current_key or project_policy_key()
    cfg = load_instance_config(config)
    current_root = (cfg.data_root or default_data_root(key)).resolve()
    found: dict[Path, InstanceStore] = {}
    home = instance_store_home()
    if home.is_dir():
        for child in sorted(home.iterdir(), key=lambda p: p.name):
            if not child.is_dir() or child.is_symlink():
                continue
            resolved = child.resolve()
            found[resolved] = InstanceStore(
                name=child.name,
                path=child,
                size=directory_size_bytes(child),
                current=resolved == current_root,
            )
    if current_root.exists() and current_root.is_dir() and current_root not in found:
        found[current_root] = InstanceStore(
            name=key,
            path=current_root,
            size=directory_size_bytes(current_root),
            current=True,
        )
    elif current_root in found:
        store = found[current_root]
        found[current_root] = InstanceStore(
            name=store.name,
            path=store.path,
            size=store.size,
            current=True,
        )
    return sorted(found.values(), key=lambda s: s.name)


def resolve_prune_targets(
    names: Sequence[str],
    *,
    all_stores: bool = False,
    config: Mapping[str, Any] | None = None,
) -> list[Path]:
    """Resolve prune names, ``--all``, or the current project's data_root."""
    if all_stores and names:
        raise click.ClickException("pass store names or --all, not both")
    home = instance_store_home()
    if all_stores:
        if not home.is_dir():
            return []
        return [
            child
            for child in sorted(home.iterdir(), key=lambda p: p.name)
            if child.is_dir() and not child.is_symlink()
        ]
    if names:
        missing: list[str] = []
        targets: list[Path] = []
        home_resolved = home.resolve() if home.exists() else home
        for name in names:
            if name in {".", ".."} or "/" in name or os.sep in name:
                raise click.ClickException(f"invalid store name: {name!r}")
            path = home / name
            if not path.exists():
                missing.append(name)
                continue
            resolved = path.resolve()
            if home_resolved not in resolved.parents and resolved != home_resolved:
                raise click.ClickException(
                    f"refusing to prune path outside instance store: {path}"
                )
            targets.append(path)
        if missing:
            raise click.ClickException(
                "unknown docker-instance stores: " + ", ".join(missing)
            )
        return targets
    cfg = load_instance_config(config)
    return [(cfg.data_root or default_data_root()).resolve()]


def prune_instance_stores(paths: Sequence[Path]) -> list[Path]:
    """``force_rmtree`` each existing path; return those that were removed."""
    from buddelkiste.binds import force_rmtree

    removed: list[Path] = []
    for path in paths:
        if path.exists():
            force_rmtree(path)
            removed.append(path)
    return removed


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
    remove_data_on_teardown = bool(data.get("remove_data_on_teardown", False))
    storage_driver = parse_storage_driver(
        data.get("storage_driver", "auto"), where=f"{where}.storage_driver"
    )

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
        "remove_data_on_teardown",
        "storage_driver",
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
        remove_data_on_teardown=remove_data_on_teardown,
        storage_driver=storage_driver,
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
        if which(name) is None:
            missing.append(name)
    if missing:
        raise click.ClickException(
            "docker-instance requires: "
            + ", ".join(missing)
            + " (Arch: pacman -S docker rootlesskit shadow bubblewrap; "
            "also fuse-overlayfs and slirp4netns/passt recommended)"
        )
    user = _username()
    for label, path in (
        ("/etc/subuid", Path("/etc/subuid")),
        ("/etc/subgid", Path("/etc/subgid")),
    ):
        if not path.is_file():
            raise click.ClickException(
                f"docker-instance needs {label} with an entry for {user!r} "
                f"(e.g. echo '{user}:100000:65536' | sudo tee -a {label})"
            )
        if not _subid_has_user(path, user):
            raise click.ClickException(
                f"docker-instance needs a {label} entry for {user!r} "
                f"(e.g. echo '{user}:100000:65536' | sudo tee -a {label})"
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
    # Always copy-up /etc and /run so dockerd can create /run/docker (plugins).
    common = [
        "--disable-host-loopback",
        "--port-driver=builtin",
        "--copy-up=/etc",
        "--copy-up=/run",
        "--propagation=rslave",
    ]
    if net == "host":
        return ["--net=host", *common]
    if net == "none":
        return ["--net=none", *common]
    # Prefer slirp4netns (stable); pasta is still experimental in some releases.
    if which("slirp4netns"):
        return ["--net=slirp4netns", *common]
    if which("pasta"):
        return ["--net=pasta", *common]
    raise click.ClickException(
        "docker-instance net=userspace needs slirp4netns or pasta (passt)"
    )


def host_dns_servers(resolv: Path | None = None) -> list[str]:
    """IPv4 nameservers from host resolv.conf (skip loopback / IPv6).

    Injected as dockerd ``--dns`` so build/run containers do not rely solely on
    slirp's ``10.0.2.3`` forwarder (which still needs bridge NAT via iptables).
    """
    path = resolv or Path("/etc/resolv.conf")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    servers: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        ns = parts[1]
        if ns.startswith("127.") or ns == "::1" or ":" in ns:
            continue
        if ns not in servers:
            servers.append(ns)
        if len(servers) >= 3:
            break
    return servers


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
    """bwrap argv to FS-jail dockerd *inside* rootlesskit (already uid 0 in a userns)."""
    if fs == "host":
        return []

    # Do not put bwrap outside rootlesskit: unprivileged bwrap creates a userns
    # and then newuidmap for rootlesskit fails ("Could not set caps").
    args: list[str] = [
        "bwrap",
        "--die-with-parent",
        # uid 0 already holds the userns capability set. --cap-add ALL replaces
        # that set with every bit; capset() then fails with EPERM and bwrap
        # leaves the inheritable set empty, so the exec cannot chown the
        # engine socket. Naming one held cap makes capset() write the real
        # set into inheritable and ambient. This is the same on bwrap 0.12
        # and 0.13.
        "--cap-add",
        "CAP_CHOWN",
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

    # Expose host sysfs; then RW-bind cgroup on top for rootless delegation.
    # (Order matters: a later --ro-bind /sys would hide a prior cgroup bind.)
    sys_path = Path("/sys")
    if sys_path.is_dir():
        args.extend(["--ro-bind", str(sys_path), str(sys_path)])
    cgroup = Path("/sys/fs/cgroup")
    if cgroup.is_dir():
        args.extend(["--bind", str(cgroup), str(cgroup)])

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
    storage_driver: str = "auto",
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
    ]
    driver = parse_storage_driver(storage_driver, where="storage_driver")
    if driver != "auto":
        dockerd.append(f"--storage-driver={driver}")
    # Bridge containers need iptables MASQUERADE + ip_forward to reach slirp
    # (10.0.2.3 DNS / default gw). Without them, pulls from dockerd still work
    # (daemon is in the rootlesskit netns) but RUN apt-get / DNS inside builds fail.
    if net == "none":
        dockerd.extend(["--iptables=false", "--ip-forward=false"])
    else:
        dockerd.extend(["--iptables=true", "--ip-forward=true"])
        for dns in host_dns_servers():
            dockerd.append(f"--dns={dns}")
    # With --copy-up=/run, /run/docker is often a read-only symlink into the host
    # mount (same as dockerd-rootless.sh). Replace it so dockerd can mkdir plugins/.
    child = [
        "sh",
        "-c",
        (
            "rm -rf /run/docker /run/containerd /run/xtables.lock;"
            "mkdir -p /run/docker/plugins;"
            # Ensure forward is on even if dockerd's sysctl write is ignored.
            "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true;"
            'exec "$@"'
        ),
        "dockerd-prep",
        *dockerd,
    ]
    # FS jail must run *inside* rootlesskit (mapped root), never outside it.
    jail = daemon_bwrap_prefix(
        fs=fs,
        data_root=data_root,
        project=project,
        runtime_dir=runtime_dir,
        fs_allow=fs_allow,
        net=net,
    )
    if jail:
        inner: list[str] = [*jail, *child]
    else:
        inner = child
    return [
        "rootlesskit",
        f"--state-dir={exec_root / 'rootlesskit'}",
        *rootlesskit_net_args(net),
        *inner,
    ]


def _wait_for_socket(
    sock: Path,
    proc: subprocess.Popen,
    *,
    timeout: float = 60.0,
    log_path: Path | None = None,
) -> None:
    """Wait until the Engine API on ``sock`` answers ``GET /_ping``."""
    deadline = time.monotonic() + timeout
    last_err = "socket not created"
    while time.monotonic() < deadline:
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
        if sock.exists():
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.settimeout(1.0)
                client.connect(os.fspath(sock))
                client.sendall(b"GET /_ping HTTP/1.1\r\nHost: docker\r\n\r\n")
                data = client.recv(256)
                if data.startswith(b"HTTP/1.") and b"200" in data.split(b"\r\n", 1)[0]:
                    return
                last_err = f"unexpected ping response: {data[:80]!r}"
            except OSError as exc:
                last_err = str(exc)
            finally:
                try:
                    client.close()
                except OSError:
                    pass
        time.sleep(0.15)
    stderr = ""
    if log_path is not None and log_path.is_file():
        try:
            stderr = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    detail = stderr.strip()[-2000:] if stderr.strip() else last_err
    raise click.ClickException(
        f"docker-instance timed out waiting for daemon socket {sock}: {detail}"
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


# Linux AF_UNIX path limit (sun_path); containerd rejects paths longer than 104.
_AF_UNIX_PATH_MAX = 104
_CONTAINERD_SOCK_TAIL = "e/containerd/containerd.sock.ttrpc"


def _bwrap_off_apparmor_path(dest_dir: Path) -> Path:
    """Copy ``bwrap`` off the path Debian's AppArmor profile attaches to.

    The ``bwrap`` profile stacks every child onto ``unpriv_bwrap``, which
    denies all capabilities. ``/proc/self/status`` can still show a full
    ``CapEff`` while ``chown`` to another group and iptables fail with
    EPERM. A copy is not path-attached, so the child keeps the user-namespace
    capability set. Hosts without that profile run the same binary.
    """
    src = which("bwrap")
    if src is None:
        raise click.ClickException("bwrap not found")
    dest = dest_dir / "bwrap"
    shutil.copy2(src, dest)
    dest.chmod(0o755)
    return dest


def _short_instance_base() -> Path:
    """Return a short directory for exec-root / sockets (AF_UNIX length limit)."""
    pid = os.getpid()
    candidates: list[Path] = []
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidates.append(Path(xdg) / f"bdi{pid}")
    candidates.append(Path("/tmp") / f"bdi{pid}")
    candidates.append(Path("/tmp") / f"b{pid}")
    for base in candidates:
        worst = base / _CONTAINERD_SOCK_TAIL
        if len(os.fspath(worst).encode()) <= _AF_UNIX_PATH_MAX:
            base.mkdir(parents=True, exist_ok=True)
            return base
    raise click.ClickException(
        "cannot find a short enough path for docker-instance sockets "
        f"(need room for {_CONTAINERD_SOCK_TAIL!r} within {_AF_UNIX_PATH_MAX} bytes)"
    )


@contextmanager
def docker_instance_setup(
    *,
    config: Mapping[str, Any] | None = None,
    instance: DockerInstanceConfig | None = None,
    runtime_dir: Path | None = None,
) -> Iterator[Sequence[str]]:
    """Start project dockerd (+ optional proxy) and yield agent bwrap args."""
    check_rootless_prerequisites()
    cfg = instance or _apply_cli_overrides(load_instance_config(config))
    key = project_policy_key()
    data_root = (cfg.data_root or default_data_root(key)).resolve()
    project = project_root()
    fs_allow = expand_fs_allow(cfg.fs_allow)

    # exec-root holds containerd.sock.ttrpc — must stay under AF_UNIX path limits.
    # pytest tmp_path is often too long, so always prefer a short base.
    short_base = _short_instance_base()
    if runtime_dir is not None:
        runtime_dir.mkdir(parents=True, exist_ok=True)
    exec_root = short_base / "e"
    exec_root.mkdir(parents=True, exist_ok=True)
    pidfile = exec_root / "dockerd.pid"
    daemon_sock = short_base / "d.sock"
    if len(os.fspath(daemon_sock).encode()) > _AF_UNIX_PATH_MAX:
        daemon_sock = _short_listen_socket(short_base)

    cmd = build_dockerd_command(
        data_root=data_root,
        exec_root=exec_root,
        pidfile=pidfile,
        sock=daemon_sock,
        net=cfg.net,
        fs=cfg.fs,
        project=project,
        runtime_dir=short_base,
        fs_allow=fs_allow,
        storage_driver=cfg.storage_driver,
    )
    # Debian labels /usr/bin/bwrap. Children then run as unpriv_bwrap and lose
    # every capability, including the chown dockerd needs for its socket group.
    if "bwrap" in cmd:
        bwrap_bin = _bwrap_off_apparmor_path(short_base)
        cmd = [str(bwrap_bin) if part == "bwrap" else part for part in cmd]
    log.info("docker-instance starting: %s", " ".join(cmd))
    log_path = (runtime_dir or short_base) / "dockerd.log"
    log_file = log_path.open("wb")
    env = os.environ.copy()
    env["PATH"] = daemon_tool_path(env.get("PATH"))
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=log_file,
        start_new_session=True,
        env=env,
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
            listen = _short_listen_socket(short_base)
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
        try:
            shutil.rmtree(short_base, ignore_errors=True)
        except OSError:
            pass
        if cfg.remove_data_on_teardown:
            from buddelkiste.binds import force_rmtree

            force_rmtree(data_root)
