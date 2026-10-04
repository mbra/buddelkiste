"""Optional sandbox features grouped by topic (cursor, python, ssh, ...)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

import click

from buddelkiste.binds import DevBindConfig, ROBindConfig, RWBindConfig, Tmpfs

env = os.getenv


@dataclass(frozen=True)
class Feature:
    """A named, optionally enabled topic of sandbox permissions."""

    name: str
    description: str
    default: bool = True
    env_vars: tuple[str, ...] = ()
    binds: Callable[[], list] = field(default_factory=lambda: lambda: [])
    setup: Callable[[], AbstractContextManager[Sequence[str]]] | None = None


def _runtime() -> Path:
    value = env("XDG_RUNTIME_DIR")
    if not value:
        raise click.ClickException("XDG_RUNTIME_DIR is not set")
    return Path(value)


def _home() -> Path:
    return Path.home()


def base_binds() -> list:
    """Always-on mounts required for a usable sandbox."""
    runtime = _runtime()
    home = _home()
    return [
        ("--dev", "/dev"),
        ("--proc", "/proc"),
        Tmpfs("/dev/shm"),
        Tmpfs("/run"),
        Tmpfs("/tmp"),
        ("--dir", str(runtime)),
        ("--dir", "/run/dbus"),
        ROBindConfig("/run/dbus/system_bus_socket"),
        ROBindConfig(runtime / "bus"),
        RWBindConfig(runtime / "dbus-1"),
        ROBindConfig("/usr"),
        ROBindConfig("/usr/libexec/flatpak-xdg-utils/xdg-open", "/usr/bin/xdg-open"),
        ROBindConfig("/lib"),
        ROBindConfig("/lib64"),
        ROBindConfig("/bin"),
        ROBindConfig("/etc/resolv.conf"),
        ROBindConfig("/etc/hosts"),
        ROBindConfig("/etc/ssl"),
        ROBindConfig("/etc/passwd"),
        ROBindConfig("/etc/group"),
        ROBindConfig("/etc/alternatives"),
        ROBindConfig("/etc/ca-certificates"),
        ROBindConfig(home / ".local"),
        RWBindConfig(home / ".cache"),
    ]


BASE_ENV_VARS = (
    "COLORTERM",
    "DBUS_SESSION_BUS_ADDRESS",
    "EDITOR",
    "HOME",
    "LANG",
    "LC_NUMERIC",
    "LC_TIME",
    "PATH",
    "SHELL",
    "TERM",
    "TERMINFO",
    "TERM_PROGRAM",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
)


def cursor_binds() -> list:
    home = _home()
    return [
        ROBindConfig("/opt/cursor-agent"),
        ROBindConfig("/usr/share/cursor"),
        ROBindConfig(home / ".agents"),
        ROBindConfig(home / ".config/agents"),
        ROBindConfig(home / ".cursorignore"),
        RWBindConfig(home / ".config/Cursor"),
        RWBindConfig(home / ".config/cursor"),
        RWBindConfig(home / ".cursor"),
        RWBindConfig(home / ".local/share/cursor"),
        RWBindConfig(home / ".local/state/cursor"),
    ]


def python_binds() -> list:
    home = _home()
    return [
        ROBindConfig(home / ".pip"),
        RWBindConfig(env("WORKON_HOME", home / ".virtualenvs")),
    ]


def node_binds() -> list:
    home = _home()
    return [
        ROBindConfig(home / ".bun"),
        ROBindConfig(home / ".npmrc"),
        ROBindConfig(home / ".nvm"),
        RWBindConfig(home / ".npm"),
    ]


def asdf_binds() -> list:
    home = _home()
    return [
        ROBindConfig(home / ".asdf"),
        ROBindConfig(home / ".tool-versions"),
    ]


def docker_binds() -> list:
    res: list = [ROBindConfig(_home() / ".docker")]
    if docker_host := env("DOCKER_HOST"):
        docker_host = docker_host.removeprefix("unix://")
        runtime = env("XDG_RUNTIME_DIR")
        if runtime and docker_host.startswith(runtime):
            res.append(ROBindConfig(docker_host))
    return res


def git_binds() -> list:
    home = _home()
    return [
        ROBindConfig(home / ".config/git"),
        ROBindConfig(home / ".gitconfig"),
    ]


def ssh_binds() -> list:
    return [ROBindConfig(_home() / ".ssh/config")]


def google_binds() -> list:
    return [ROBindConfig("/opt/google")]


def nvim_binds() -> list:
    return [ROBindConfig(_home() / "nvim")]


def java_binds() -> list:
    return [
        ROBindConfig("/etc/java-17-openjdk"),
        ROBindConfig("/etc/java-21-openjdk"),
    ]


def gui_binds() -> list:
    runtime = _runtime()
    res: list = [
        ROBindConfig("/sys/dev/char"),
        ROBindConfig("/sys/devices"),
        ROBindConfig("/sys/class"),
        DevBindConfig("/dev/dri"),
        DevBindConfig("/dev/snd"),
        ROBindConfig("/etc/fonts"),
        ROBindConfig("/tmp/.X11-unix"),
    ]
    if wayland_display := env("WAYLAND_DISPLAY"):
        res.append(ROBindConfig(runtime / wayland_display))
    if xauthority := env("XAUTHORITY"):
        res.append(ROBindConfig(xauthority))
    return res


class SshAgent:
    socket: Path

    def __init__(self):
        self.socket = None
        self._proc = None
        self._agent_dir = None

    def __enter__(self) -> Self:
        agent_dir = Path(tempfile.mkdtemp(prefix="bwrapssh", dir=env("XDG_RUNTIME_DIR")))
        socket = agent_dir / "sock"

        proc = subprocess.Popen(
            ["ssh-agent", "-D", "-a", str(socket)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )

        try:
            for _ in range(50):  # pragma: nobranch
                if socket.is_socket():
                    break
                if proc.poll() is not None:
                    raise click.ClickException("ssh-agent exited during startup.")
                time.sleep(0.1)
            else:  # pragma: nocover
                raise click.ClickException(f"timed out waiting for ssh-agent socket at {socket}.")
        except BaseException:
            proc.terminate()
            raise

        self._proc = proc
        self._agent_dir = agent_dir
        self.socket = socket
        return self

    def add_key(self, path: Path):
        subprocess.run(
            ["ssh-add", "-q", str(path)],
            env={**os.environ, "SSH_AUTH_SOCK": str(self.socket)},
            check=True,
        )

    def __exit__(self, exc_type, exc_value, traceback):
        proc = self._proc
        self._proc = None
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: nocover
            proc.kill()
        shutil.rmtree(self._agent_dir, ignore_errors=True)


def find_sandbox_ssh_key() -> Path | None:
    for path in Path("~/.ssh").expanduser().glob("sandbox_*"):
        if not path.name.endswith(".pub"):
            return path
    return None


@contextmanager
def ssh_setup() -> Iterator[Sequence[str]]:
    with SshAgent() as ssh_agent:
        if ssh_key := find_sandbox_ssh_key():
            ssh_agent.add_key(ssh_key)
        yield [
            *ROBindConfig(ssh_agent.socket),
            "--setenv",
            "SSH_AUTH_SOCK",
            str(ssh_agent.socket),
        ]


FEATURES: dict[str, Feature] = {
    feature.name: feature
    for feature in (
        Feature(
            name="cursor",
            description="Cursor IDE/CLI install paths and state directories",
            binds=cursor_binds,
        ),
        Feature(
            name="python",
            description="pip config, virtualenvs, and Python env vars",
            env_vars=("PIP_REQUIRE_VIRTUALENV", "VIRTUAL_ENV", "WORKON_HOME"),
            binds=python_binds,
        ),
        Feature(
            name="node",
            description="npm, nvm, and bun",
            env_vars=("BUN_INSTALL",),
            binds=node_binds,
        ),
        Feature(
            name="asdf",
            description="asdf version manager",
            env_vars=("ASDF_DIR",),
            binds=asdf_binds,
        ),
        Feature(
            name="docker",
            description="Docker CLI config and user daemon socket",
            env_vars=("DOCKER_HOST",),
            binds=docker_binds,
        ),
        Feature(
            name="git",
            description="Git configuration files",
            binds=git_binds,
        ),
        Feature(
            name="ssh",
            description="SSH config plus a dedicated agent with sandbox_* keys",
            binds=ssh_binds,
            setup=ssh_setup,
        ),
        Feature(
            name="java",
            description="OpenJDK system configuration",
            binds=java_binds,
        ),
        Feature(
            name="nvim",
            description="Neovim config under ~/nvim",
            binds=nvim_binds,
        ),
        Feature(
            name="google",
            description="Google tools under /opt/google",
            binds=google_binds,
        ),
        Feature(
            name="gui",
            description="Graphical apps: display, GPU, audio, fonts",
            env_vars=(
                "DISPLAY",
                "MOZ_ENABLE_WAYLAND",
                "WAYLAND_DISPLAY",
                "XAUTHORITY",
                "XCURSOR_SIZE",
                "XDG_CURRENT_DESKTOP",
                "XDG_SESSION_TYPE",
            ),
            binds=gui_binds,
        ),
    )
}

FEATURE_NAMES = tuple(FEATURES)


def _unknown_feature_message(name: str, where: str = "") -> str:
    if where:
        return f"Unknown feature {where}: {name}"
    return f"Unknown feature: {name}"


def apply_feature_spec(enabled: dict[str, bool], spec, *, where: str) -> None:
    """Apply a config feature spec in place.

    A list sets the enabled set exactly (allowlist). A table applies boolean
    overrides on the current set.
    """
    if isinstance(spec, list):
        unknown = [name for name in spec if name not in FEATURES]
        if unknown:
            raise click.ClickException(_unknown_feature_message(", ".join(unknown), where))
        selected = set(spec)
        for name in FEATURES:
            enabled[name] = name in selected
        return

    if isinstance(spec, dict):
        for name, value in spec.items():
            if name not in FEATURES:
                raise click.ClickException(_unknown_feature_message(name, where))
            enabled[name] = bool(value)
        return

    raise click.ClickException(
        f"Invalid features {where}: expected a list or table, got {type(spec).__name__}"
    )


def lookup_executable_config(config: dict, executable: str | None) -> dict | None:
    """Return the config table for an executable, if any.

    Matches the full executable string first, then its basename.
    """
    if not executable:
        return None

    executables = config.get("executables")
    if not isinstance(executables, dict):
        return None

    if executable in executables:
        entry = executables[executable]
        return entry if isinstance(entry, dict) else None

    basename = Path(executable).name
    if basename in executables:
        entry = executables[basename]
        return entry if isinstance(entry, dict) else None

    return None


def resolve_features(
    config: dict,
    *,
    executable: str | None = None,
    enable: Sequence[str] = (),
    disable: Sequence[str] = (),
) -> dict[str, bool]:
    """Resolve which features are enabled.

    Precedence (later wins for CLI flags):
    1. feature defaults
    2. global config ``features`` (list allowlist or table overrides)
    3. per-executable config ``executables.<name>.features`` when an executable
       is provided
    4. CLI ``--feature`` / ``--no-feature``
    """
    enabled = {name: feature.default for name, feature in FEATURES.items()}

    if "features" in config:
        apply_feature_spec(enabled, config["features"], where="in config")

    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and "features" in exec_cfg:
        apply_feature_spec(
            enabled,
            exec_cfg["features"],
            where=f"for executable {executable!r}",
        )

    for name in enable:
        if name not in FEATURES:
            raise click.ClickException(_unknown_feature_message(name))
        enabled[name] = True

    for name in disable:
        if name not in FEATURES:
            raise click.ClickException(_unknown_feature_message(name))
        enabled[name] = False

    return enabled


def enabled_feature_names(enabled: dict[str, bool]) -> list[str]:
    return [name for name in FEATURE_NAMES if enabled.get(name)]


def feature_binds(enabled: dict[str, bool]) -> list:
    binds = base_binds()
    for name in enabled_feature_names(enabled):
        binds.extend(FEATURES[name].binds())
    return binds


def feature_env_var_names(enabled: dict[str, bool]) -> list[str]:
    names = list(BASE_ENV_VARS)
    for name in enabled_feature_names(enabled):
        names.extend(FEATURES[name].env_vars)
    return names


@contextmanager
def feature_setup(enabled: dict[str, bool]) -> Iterator[list[str]]:
    """Run setup hooks for enabled features; yield extra bwrap args."""
    extra: list[str] = []
    with ExitStack() as stack:
        for name in enabled_feature_names(enabled):
            setup = FEATURES[name].setup
            if setup is not None:
                extra.extend(stack.enter_context(setup()))
        yield extra


def format_features_help() -> str:
    lines = ["Available features (all enabled by default):", ""]
    width = max(len(name) for name in FEATURE_NAMES)
    for name in FEATURE_NAMES:
        feature = FEATURES[name]
        lines.append(f"  {name:<{width}}  {feature.description}")
    return "\n".join(lines)
