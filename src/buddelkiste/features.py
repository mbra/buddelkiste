"""Optional sandbox features grouped by topic (cursor, python, ssh, ...).

Features are discovered via the ``buddelkiste.features`` entry-point group. Packages
can register additional features there. Config may also define pure-TOML
features under ``[feature.<name>]`` with env allowlists and bind mounts.
Bind paths may interpolate ``$VAR`` / ``${VAR}`` from the process environment.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, field, replace
from functools import lru_cache
from importlib.metadata import entry_points
from pathlib import Path
from typing import Self

import click

from buddelkiste.binds import DevBindConfig, ROBindConfig, RWBindConfig, Tmpfs

env = os.getenv

ENTRY_POINT_GROUP = "buddelkiste.features"

_ENV_VAR_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)
_FEATURE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class Feature:
    """A named, optionally enabled topic of sandbox permissions."""

    name: str
    description: str
    default: bool = True
    env_vars: tuple[str, ...] = ()
    binds: Callable[[], list] = field(default_factory=lambda: lambda: [])
    setup: Callable[[], AbstractContextManager[Sequence[str]]] | None = None
    # Module path or config location shown in --list-features.
    origin: str = ""


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
    else:
        res.append(ROBindConfig("/var/run/docker.sock"))
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


CURSOR = Feature(
    name="cursor",
    description="Cursor IDE/CLI install paths and state directories",
    binds=cursor_binds,
    origin="buddelkiste.features:CURSOR",
)
PYTHON = Feature(
    name="python",
    description="pip config, virtualenvs, and Python env vars",
    env_vars=("PIP_REQUIRE_VIRTUALENV", "VIRTUAL_ENV", "WORKON_HOME"),
    binds=python_binds,
    origin="buddelkiste.features:PYTHON",
)
NODE = Feature(
    name="node",
    description="npm, nvm, and bun",
    env_vars=("BUN_INSTALL",),
    binds=node_binds,
    origin="buddelkiste.features:NODE",
)
ASDF = Feature(
    name="asdf",
    description="asdf version manager",
    env_vars=("ASDF_DIR",),
    binds=asdf_binds,
    origin="buddelkiste.features:ASDF",
)
DOCKER = Feature(
    name="docker",
    description="Docker CLI config and user daemon socket",
    env_vars=("DOCKER_HOST",),
    binds=docker_binds,
    origin="buddelkiste.features:DOCKER",
)
GIT = Feature(
    name="git",
    description="Git configuration files",
    binds=git_binds,
    origin="buddelkiste.features:GIT",
)
SSH = Feature(
    name="ssh",
    description="SSH config plus a dedicated agent with sandbox_* keys",
    binds=ssh_binds,
    setup=ssh_setup,
    origin="buddelkiste.features:SSH",
)
JAVA = Feature(
    name="java",
    description="OpenJDK system configuration",
    binds=java_binds,
    origin="buddelkiste.features:JAVA",
)
NVIM = Feature(
    name="nvim",
    description="Neovim config under ~/nvim",
    binds=nvim_binds,
    origin="buddelkiste.features:NVIM",
)
GOOGLE = Feature(
    name="google",
    description="Google tools under /opt/google",
    binds=google_binds,
    origin="buddelkiste.features:GOOGLE",
)
GUI = Feature(
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
    origin="buddelkiste.features:GUI",
)


def _load_entry_point_object(ep) -> Feature:
    try:
        obj = ep.load()
    except Exception as exc:
        raise click.ClickException(
            f"Failed to load feature entry point {ep.name!r} ({ep.value}): {exc}"
        ) from exc

    if isinstance(obj, Feature):
        feature = obj
    elif callable(obj):
        feature = obj()
        if not isinstance(feature, Feature):
            raise click.ClickException(
                f"Feature entry point {ep.name!r} ({ep.value}) did not return a Feature"
            )
    else:
        raise click.ClickException(
            f"Feature entry point {ep.name!r} ({ep.value}) must be a Feature "
            "or a zero-argument callable returning one"
        )
    return replace(feature, name=ep.name, origin=ep.value)


def _builtin_feature_fallback() -> dict[str, Feature]:
    """Built-ins used when entry points are not installed yet (source tree)."""
    return {
        f.name: f
        for f in (
            CURSOR,
            PYTHON,
            NODE,
            ASDF,
            DOCKER,
            GIT,
            SSH,
            JAVA,
            NVIM,
            GOOGLE,
            GUI,
        )
    }


@lru_cache(maxsize=1)
def load_entry_point_features() -> dict[str, Feature]:
    """Load features registered under the ``buddelkiste.features`` entry-point group."""
    selected = entry_points().select(group=ENTRY_POINT_GROUP)
    registry: dict[str, Feature] = {}
    for ep in selected:
        if ep.name in registry:
            raise click.ClickException(
                f"Duplicate feature entry point {ep.name!r}: "
                f"{registry[ep.name].origin} and {ep.value}"
            )
        registry[ep.name] = _load_entry_point_object(ep)
    if not registry:
        return _builtin_feature_fallback()
    return registry


def clear_feature_caches() -> None:
    """Clear cached entry-point features (for tests)."""
    load_entry_point_features.cache_clear()
    _refresh_features_alias()


def _refresh_features_alias() -> None:
    FEATURES.clear()
    FEATURES.update(load_entry_point_features())
    global FEATURE_NAMES
    FEATURE_NAMES = tuple(FEATURES)


# Import compatibility: dict/tuple updated from entry points (or builtin fallback).
FEATURES: dict[str, Feature] = {}
FEATURE_NAMES: tuple[str, ...] = ()
_refresh_features_alias()


def interpolate_env(text: str, environ: Mapping[str, str] | None = None) -> str:
    """Expand ``$VAR`` / ``${VAR}`` using ``environ`` (default: ``os.environ``)."""
    envmap = os.environ if environ is None else environ

    def repl(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in envmap:
            raise click.ClickException(
                f"environment variable {name!r} is not set (in {text!r})"
            )
        return envmap[name]

    return _ENV_VAR_RE.sub(repl, text)


def expand_bind_path(text: str, environ: Mapping[str, str] | None = None) -> str:
    """Interpolate env vars and expand a leading ``~`` in a bind path."""
    return str(Path(interpolate_env(text, environ)).expanduser())


def _toml_binds_factory(
    bind_specs: Sequence[dict],
    *,
    feature_name: str,
) -> Callable[[], list]:
    def binds() -> list:
        result: list = []
        for index, spec in enumerate(bind_specs):
            if "source" not in spec:
                raise click.ClickException(
                    f"feature.{feature_name}.binds[{index}] missing required key 'source'"
                )
            source = expand_bind_path(str(spec["source"]))
            target = (
                expand_bind_path(str(spec["target"])) if "target" in spec else None
            )
            read_only = bool(spec.get("read_only", True))
            cls = ROBindConfig if read_only else RWBindConfig
            if target is None:
                result.append(cls(source))
            else:
                result.append(cls(source, target))
        return result

    return binds


def parse_toml_feature(name: str, data: dict) -> Feature:
    """Parse a ``[feature.<name>]`` table into a :class:`Feature`."""
    if not _FEATURE_NAME_RE.match(name):
        raise click.ClickException(
            f"Invalid feature name {name!r}: use letters, digits, '_' or '-'"
        )
    if not isinstance(data, dict):
        raise click.ClickException(f"feature.{name} must be a table")

    description = str(data.get("description", f"Custom feature {name!r}"))
    default = bool(data.get("default", True))

    env_spec = data.get("env", data.get("env_vars", []))
    if not isinstance(env_spec, list):
        raise click.ClickException(
            f"feature.{name}.env must be a list of environment variable names"
        )
    env_vars = tuple(str(item) for item in env_spec)

    binds_spec = data.get("binds", [])
    if not isinstance(binds_spec, list):
        raise click.ClickException(
            f"feature.{name}.binds must be a list of bind tables"
        )
    for index, item in enumerate(binds_spec):
        if not isinstance(item, dict):
            raise click.ClickException(
                f"feature.{name}.binds[{index}] must be a table with 'source'"
            )

    unknown = set(data) - {"description", "default", "env", "env_vars", "binds"}
    if unknown:
        keys = ", ".join(sorted(unknown))
        raise click.ClickException(f"feature.{name} has unknown keys: {keys}")

    return Feature(
        name=name,
        description=description,
        default=default,
        env_vars=env_vars,
        binds=_toml_binds_factory(binds_spec, feature_name=name),
        origin=f"config:[feature.{name}]",
    )


def load_feature_registry(config: dict) -> dict[str, Feature]:
    """Entry-point features plus optional ``[feature.<name>]`` definitions."""
    registry = dict(load_entry_point_features())
    custom = config.get("feature")
    if custom is None:
        return registry
    if not isinstance(custom, dict):
        raise click.ClickException(
            "feature must be a table of [feature.<name>] definitions"
        )

    for name, data in custom.items():
        key = str(name)
        if key in registry:
            raise click.ClickException(
                f"feature.{key} conflicts with existing feature "
                f"{key!r} ({registry[key].origin})"
            )
        registry[key] = parse_toml_feature(key, data)
    return registry


def feature_names(registry: dict[str, Feature] | None = None) -> list[str]:
    """Stable feature name order: entry-point features first, then config."""
    if registry is None:
        return list(load_entry_point_features())
    ep_names = list(load_entry_point_features())
    config_names = [name for name in registry if name not in load_entry_point_features()]
    return ep_names + config_names


def _unknown_feature_message(
    name: str,
    where: str = "",
    *,
    registry: dict[str, Feature] | None = None,
) -> str:
    known = ", ".join(feature_names(registry))
    if where:
        return f"Unknown feature {where}: {name} (expected {known})"
    return f"Unknown feature: {name} (expected {known})"


def apply_feature_spec(
    enabled: dict[str, bool],
    spec,
    *,
    where: str,
    registry: dict[str, Feature],
) -> None:
    """Apply a config feature spec in place.

    A list sets the enabled set exactly (allowlist). A table applies boolean
    overrides on the current set.
    """
    if isinstance(spec, list):
        unknown = [name for name in spec if name not in registry]
        if unknown:
            raise click.ClickException(
                _unknown_feature_message(
                    ", ".join(unknown), where, registry=registry
                )
            )
        selected = set(spec)
        for name in registry:
            enabled[name] = name in selected
        return

    if isinstance(spec, dict):
        for name, value in spec.items():
            if name not in registry:
                raise click.ClickException(
                    _unknown_feature_message(name, where, registry=registry)
                )
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
    1. feature defaults (built-in + ``[feature.<name>]``)
    2. global config ``features`` (list allowlist or table overrides)
    3. per-executable config ``executables.<name>.features`` when an executable
       is provided
    4. CLI ``--feature`` / ``--no-feature``
    """
    registry = load_feature_registry(config)
    enabled = {name: feature.default for name, feature in registry.items()}

    if "features" in config:
        apply_feature_spec(
            enabled, config["features"], where="in config", registry=registry
        )

    exec_cfg = lookup_executable_config(config, executable)
    if exec_cfg is not None and "features" in exec_cfg:
        apply_feature_spec(
            enabled,
            exec_cfg["features"],
            where=f"for executable {executable!r}",
            registry=registry,
        )

    for name in enable:
        if name not in registry:
            raise click.ClickException(
                _unknown_feature_message(name, registry=registry)
            )
        enabled[name] = True

    for name in disable:
        if name not in registry:
            raise click.ClickException(
                _unknown_feature_message(name, registry=registry)
            )
        enabled[name] = False

    return enabled


def enabled_feature_names(
    enabled: dict[str, bool],
    registry: dict[str, Feature] | None = None,
) -> list[str]:
    return [name for name in feature_names(registry) if enabled.get(name)]


def feature_binds(
    enabled: dict[str, bool],
    config: dict | None = None,
) -> list:
    registry = load_feature_registry(config or {})
    binds = base_binds()
    for name in enabled_feature_names(enabled, registry):
        binds.extend(registry[name].binds())
    return binds


def feature_env_var_names(
    enabled: dict[str, bool],
    config: dict | None = None,
) -> list[str]:
    registry = load_feature_registry(config or {})
    names = list(BASE_ENV_VARS)
    for name in enabled_feature_names(enabled, registry):
        names.extend(registry[name].env_vars)
    return names


@contextmanager
def feature_setup(
    enabled: dict[str, bool],
    config: dict | None = None,
) -> Iterator[list[str]]:
    """Run setup hooks for enabled features; yield extra bwrap args."""
    registry = load_feature_registry(config or {})
    extra: list[str] = []
    with ExitStack() as stack:
        for name in enabled_feature_names(enabled, registry):
            setup = registry[name].setup
            if setup is not None:
                extra.extend(stack.enter_context(setup()))
        yield extra


def format_features_help(config: dict | None = None) -> str:
    registry = load_feature_registry(config or {})
    names = feature_names(registry)
    lines = ["Available features:", ""]
    width = max(len(name) for name in names)
    for name in names:
        feature = registry[name]
        default = "on" if feature.default else "off"
        origin = feature.origin or "unknown"
        lines.append(
            f"  {name:<{width}}  {feature.description} [default: {default}] ({origin})"
        )
    return "\n".join(lines)
