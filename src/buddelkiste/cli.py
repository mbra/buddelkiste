"""Sandbox a command using bubblewrap.

Pass the executable and its arguments on the command line. They are run inside
a bubblewrap sandbox. The wrapper's own option is --debug; everything else is
forwarded as the sandboxed command.

With no command, a login shell is started inside the sandbox so the environment
can be inspected.


# Configuration

Additional configuration is read from ~/.config/buddelkiste/config.toml. The file
supports the following top-level keys:

binds: List of additional bind mounts for the sandbox with "source", "target"
and "read_only" keys. The "source" key is mandatory and gives the host directory
to bind into the sandbox. The "target" key is optional and gives the mountpoint
inside the sandbox; this defaults to the host-side path. The "read_only" key
defaults to true.

envvars: List of additional environment variables for the sandbox. The mandatory
"name" key gives the name of the variable. The value can be specified in the
"value" key. If no value is given, it is taken from the process environment.

## Example for a ~/.config/buddelkiste/config.toml configuration

\b
  [[binds]]
  source = "/path/to/directory"  # path is whitelisted for the sandbox
  read_only = true  # change to false to give the sandbox write access

  [[envvars]]
  name = "MYENVVAR"
  value = "example value"  # delete this line to use the value from the environment


# Working directory

The current working directory must be visible inside the sandbox. If it is not
covered by any bind, the script asks whether to whitelist it for this run only
or permanently. Permanent whitelisting appends a [[binds]] entry to the
configuration file. When running non-interactively the script exits with an
error instead.
"""

from __future__ import annotations

import json
import logging
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Self

import click


@click.command(
    help=__doc__,
    context_settings={
        "ignore_unknown_options": True,
        "help_option_names": [],
    },
)
@click.option(
    "--debug",
    help="Enable debug logging",
    is_flag=True,
    default=False,
)
@click.argument(
    "args",
    nargs=-1,
    callback=lambda ctx, arg, value: list(value),
)
def cli(
    debug: bool,
    args: list[str],
) -> None:
    logging.basicConfig(level="DEBUG" if debug else "WARNING")

    config = load_config()
    binds = get_binds(config)
    env_args = get_env_args(config)
    command = resolve_launch_command(args)

    ensure_cwd_in_sandbox(binds)

    bind_args = get_bind_args(binds)

    with SshAgent() as ssh_agent:
        if ssh_key := find_sandbox_ssh_key():
            ssh_agent.add_key(ssh_key)

        ssh_args = [
            *ROBindConfig(ssh_agent.socket),
            "--setenv",
            "SSH_AUTH_SOCK",
            str(ssh_agent.socket),
        ]

        bwrap_args = [
            "bwrap",
            "--unshare-all",
            "--clearenv",
            "--share-net",
            "--die-with-parent",
            "--chdir",
            str(Path.cwd()),
            *bind_args,
            *env_args,
            *ssh_args,
            "--",
            *command,
        ]

        if debug:
            log_cmdline(bwrap_args)

        exit_code = subprocess.run(bwrap_args, check=False).returncode

    sys.exit(exit_code)


def load_config():
    try:
        fobj = config_path().open("rb")
    except FileNotFoundError:
        return {}
    with fobj:
        return tomllib.load(fobj)


ENV_VARS_TO_SHARE = [
    "ASDF_DIR",
    "BUN_INSTALL",
    "COLORTERM",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "DOCKER_HOST",
    "EDITOR",
    "HOME",
    "LANG",
    "LC_NUMERIC",
    "LC_TIME",
    "MOZ_ENABLE_WAYLAND",
    "PATH",
    "PIP_REQUIRE_VIRTUALENV",
    "SHELL",
    "TERM",
    "TERMINFO",
    "TERM_PROGRAM",
    "VIRTUAL_ENV",
    "WAYLAND_DISPLAY",
    "WORKON_HOME",
    "XAUTHORITY",
    "XCURSOR_SIZE",
    "XDG_CONFIG_HOME",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
]


@dataclass
class BasicBindConfig:
    source: Path | str
    target: Path | str | None = None
    flag: str | None = None

    def __post_init__(self):
        self.source = os.fspath(self.source)
        if self.target is None:
            self.target = self.source
        else:
            self.target = os.fspath(self.target)

    def __iter__(self) -> Iterator[str]:
        if self.flag is None:
            raise TypeError(f"{type(self).__name__} requires a bind flag")
        srcpath = Path(self.source)
        if srcpath.exists():
            yield from [self.flag, self.source, self.target]

    def covers_path(self, path: Path) -> bool:
        source = Path(self.source)
        if not source.exists():
            return False
        path = path.resolve()
        source = source.resolve()
        return path == source or path in source.parents or source in path.parents


@dataclass
class ROBindConfig(BasicBindConfig):
    """Read only binds"""

    flag: str = "--ro-bind"


@dataclass
class RWBindConfig(BasicBindConfig):
    """Read + write binds"""

    flag: str = "--bind"

    def __post_init__(self):
        super().__post_init__()
        srcpath = Path(self.source)
        if not srcpath.exists():
            srcpath.mkdir(parents=True)


@dataclass
class DevBindConfig(BasicBindConfig):
    flag: str = "--dev-bind"


@dataclass
class Tmpfs:
    target: Path | str

    def __iter__(self) -> Iterator[str]:
        return iter(("--tmpfs", os.fspath(self.target)))


env = os.getenv


def get_default_binds():
    RUNTIME = Path(env("XDG_RUNTIME_DIR"))
    HOME = Path.home()
    res = [
        # Basics
        ("--dev", "/dev"),
        ("--proc", "/proc"),
        # tmpfs
        Tmpfs("/dev/shm"),
        Tmpfs("/run"),
        Tmpfs("/tmp"),
        # Sysfs
        ROBindConfig("/sys/dev/char"),
        ROBindConfig("/sys/devices"),
        ROBindConfig("/sys/class"),
        # /run
        ("--dir", "/run/dbus"),
        ROBindConfig("/run/dbus/system_bus_socket"),
        # /dev
        DevBindConfig("/dev/dri"),
        DevBindConfig("/dev/snd"),
        # Runtime dir
        ("--dir", str(RUNTIME)),
        ROBindConfig(RUNTIME / "bus"),
        RWBindConfig(RUNTIME / "dbus-1"),
        # System read only
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
        ROBindConfig("/etc/java-17-openjdk"),
        ROBindConfig("/etc/java-21-openjdk"),
        ROBindConfig("/etc/fonts"),
        ROBindConfig("/opt/cursor-agent"),
        ROBindConfig("/opt/google"),
        ROBindConfig("/tmp/.X11-unix"),
        ROBindConfig("/usr/share/cursor"),
        # Home read only
        ROBindConfig(HOME / ".agents"),
        ROBindConfig(HOME / ".asdf"),
        ROBindConfig(HOME / ".bun"),
        ROBindConfig(HOME / ".config/agents"),
        ROBindConfig(HOME / ".config/git"),
        ROBindConfig(HOME / ".cursorignore"),
        ROBindConfig(HOME / ".docker"),
        ROBindConfig(HOME / ".gitconfig"),
        ROBindConfig(HOME / ".local"),
        ROBindConfig(HOME / ".npmrc"),
        ROBindConfig(HOME / ".nvm"),
        ROBindConfig(HOME / ".pip"),
        ROBindConfig(HOME / ".ssh/config"),
        ROBindConfig(HOME / ".tool-versions"),
        ROBindConfig(HOME / "nvim"),
        # Home read-write
        RWBindConfig(HOME / ".cache"),
        RWBindConfig(HOME / ".config/Cursor"),
        RWBindConfig(HOME / ".config/cursor"),
        RWBindConfig(HOME / ".cursor"),
        RWBindConfig(HOME / ".local/share/cursor"),
        RWBindConfig(HOME / ".local/state/cursor"),
        RWBindConfig(HOME / ".npm"),
        RWBindConfig(env("WORKON_HOME", HOME / ".virtualenvs")),
        # Whiteouts; these must be last
        #Tmpfs(DEV_ROOT / "infrastructure/puppetcfg"),
    ]

    # Hide credentials in the devscripts repo with an empty file.
    empty = Path("/dev/null")
    empty.open("wb").close()

    if wayland_display := env("WAYLAND_DISPLAY"):
        res.append(ROBindConfig(RUNTIME / wayland_display))

    if xauthority := env("XAUTHORITY"):
        res.append(ROBindConfig(xauthority))

    if docker_host := env("DOCKER_HOST"):
        docker_host = docker_host.removeprefix("unix://")
        if docker_host.startswith(env("XDG_RUNTIME_DIR")):  # user-level Docker daemon
            res.append(ROBindConfig(docker_host))

    return res


def get_binds(config: dict) -> list:
    binds = get_default_binds()
    for bind_params in config.get("binds", ()):
        srcpath = Path(bind_params["source"])
        if not srcpath.exists():
            raise FileNotFoundError(srcpath)
        config_cls = ROBindConfig if bind_params.pop("read_only", True) else RWBindConfig
        binds.append(config_cls(**bind_params))
    return binds


def get_bind_args(binds) -> Sequence[str]:
    res = []
    for bind in binds:
        res.extend(bind)
    return res


CONFIG_PATH = Path("~/.config/buddelkiste/config.toml")


def config_path() -> Path:
    return CONFIG_PATH.expanduser()


def is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def ensure_cwd_in_sandbox(binds: list) -> None:
    """Make sure the current directory is visible inside the sandbox.

    If it is not covered by any bind, interactively offer to whitelist it, either for this
    invocation only or permanently by adding it to the configuration file. The new bind is
    appended to `binds`.
    """
    cwd = Path.cwd()
    for bind in binds:
        if hasattr(bind, "covers_path"):
            if bind.covers_path(cwd):
                return

    if not is_interactive():
        raise click.ClickException(
            f"The current directory {cwd} is not available inside the sandbox.\n"
        )

    click.echo(f"The current directory {cwd} is not available inside the sandbox.", err=True)
    choice = click.prompt(
        "Whitelist it for this run only (once), permanently (always), or abort (no)?",
        type=click.Choice(["once", "always", "no"]),
        default="no",
        err=True,
    )
    if choice == "no":
        raise click.Abort()

    read_only = not click.confirm("Allow write access?", default=True, err=True)

    if choice == "always":
        add_bind_to_config(cwd, read_only=read_only)
        click.echo(f"Added {cwd} to {CONFIG_PATH}.", err=True)

    bind_cls = ROBindConfig if read_only else RWBindConfig
    binds.append(bind_cls(cwd))


def add_bind_to_config(source: Path, *, read_only: bool) -> None:
    """Append a `[[binds]]` entry for `source` to the configuration file."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Separate the new entry from existing content with a blank line.
    prefix = ""
    if path.exists() and (content := path.read_bytes()):
        prefix = "\n" if content.endswith(b"\n") else "\n\n"

    # JSON string escaping is a subset of TOML basic string escaping.
    entry = [
        "[[binds]]",
        f"source = {json.dumps(str(source))}",
        f"read_only = {json.dumps(read_only)}",
    ]

    with path.open("a") as fobj:
        fobj.write(prefix + "\n".join(entry) + "\n")


def get_env_args(config: dict) -> Sequence[str]:
    res = []

    for var_name in ENV_VARS_TO_SHARE:
        value = env(var_name)
        if value is not None:
            res.extend(("--setenv", var_name, value))

    for cfg in config.get("envvars", ()):
        var_name = cfg["name"]
        value = cfg.get("value")
        if value is None:
            value = env(var_name)
        res.extend(("--setenv", var_name, value))

    return res


class SshAgent:
    socket: Path
    process: subprocess.Popen
    directory: Path

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


def resolve_launch_command(args: list[str]) -> list[str]:
    """Return the command to run in the sandbox.

    Uses the command-line arguments as the executable and its args. If none are
    given, falls back to an interactive login shell.
    """
    if args in (["--help"], ["-h"]):
        click.echo(click.get_current_context().get_help())
        raise SystemExit(0)

    if args:
        return args

    pwent = pwd.getpwuid(os.getuid())
    return [pwent.pw_shell, "-si", "--"]


def log_cmdline(cmdline):
    logging.debug("Running:")
    group = [cmdline[0]]
    for arg in cmdline[1:]:
        if arg.startswith("-"):
            logging.debug("  %s", " ".join(group))
            group.clear()
        group.append(arg)
    logging.debug("  %s", " ".join(group))
