"""Sandbox a command using bubblewrap.

Pass the executable and its arguments on the command line. They are run inside
a bubblewrap sandbox. Wrapper options are --debug, feature toggles, and network
controls; everything else is forwarded as the sandboxed command.

With no command, a login shell is started inside the sandbox so the environment
can be inspected.


# Features

Optional permission sets are grouped by topic (cursor, python, ssh, ...).
Built-ins default to on. Toggle them with --feature / --no-feature, or in
~/.config/buddelkiste/config.toml. Define extra features under [feature.<name>].
Use --list-features to print the catalog.

Config may set features globally and per executable (matched by path or
basename of the command being started). A list selects exactly those features;
a table applies true/false overrides.


# Network

Modes: host (default, share host network), none (no connectivity), filter
(private netns via pasta or slirp4netns with in-namespace nftables IP/CIDR
allow/deny). Filter mode is selected automatically when allow/deny/policy
options are used, unless --network or config mode says otherwise. Filter mode
needs no root and no reserved host subnets.

In filter mode, nameserver IPs from /etc/resolv.conf are auto-allowed so DNS
keeps working under a default-deny policy. Rules may be IP/CIDR literals or
hostnames (exact or *.suffix); hostnames use a DNS proxy that publishes
resolved A/AAAA addresses into dynamic nft sets. Named deny presets (private,
linklocal, metadata, plus custom names under [network.presets]) expand to
IP/CIDR or hostname denials; see --list-net-presets.


# Configuration

Additional configuration is read from ~/.config/buddelkiste/config.toml. The file
supports the following top-level keys:

features: Global feature selection. Either a list of feature names (allowlist)
or a table of feature name = true/false overrides.

feature: Table of custom feature definitions under [feature.<name>]. Each may
set description, default, env (allowlisted variable names), and binds (list of
source/target/read_only tables). Bind paths may use $VAR or ${VAR}.

executables: Table keyed by executable path or basename. Each entry may contain
a features list or table, and/or a network table, applied when that executable
is started.

network: Global network settings (mode, policy, allow, deny, deny_presets).
Optional [network.presets] defines custom named deny lists. See example.

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
  # Global allowlist (exactly these features)
  features = ["git", "ssh", "python", "rust"]

\b
  [feature.rust]
  description = "Rust toolchain directories"
  env = ["CARGO_HOME", "RUSTUP_HOME"]

\b
  [[feature.rust.binds]]
  source = "$CARGO_HOME"
  read_only = false

\b
  [[feature.rust.binds]]
  source = "${HOME}/.rustup"
  read_only = true

\b
  [network]
  mode = "filter"
  policy = "deny"
  allow = ["1.1.1.1/32", "api.github.com", "*.pypi.org"]
  deny = ["203.0.113.0/24"]
  deny_presets = ["metadata", "linklocal", "corp"]

\b
  [network.presets]
  corp = ["10.50.0.0/16", "*.internal.example.com"]

\b
  [executables.cursor-agent]
  features = ["cursor", "git", "ssh", "gui"]

\b
  [executables.cursor-agent.network]
  mode = "filter"
  policy = "deny"
  allow = ["1.1.1.1/32"]

\b
  [executables.python]
  features = ["python", "git"]

\b
  [[binds]]
  source = "/path/to/directory"  # path is whitelisted for the sandbox
  read_only = true  # change to false to give the sandbox write access

\b
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
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

import click

from buddelkiste.binds import ROBindConfig, RWBindConfig, get_bind_args
from buddelkiste.features import (
    FEATURES,
    expand_bind_path,
    feature_binds,
    feature_env_var_names,
    feature_setup,
    format_features_help,
    resolve_features,
)
from buddelkiste.network import (
    format_deny_presets_help,
    load_deny_preset_registry,
    resolve_network,
    run_bwrap,
)

env = os.getenv

CONFIG_PATH = Path("~/.config/buddelkiste/config.toml")


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
@click.option(
    "--feature",
    "-f",
    "enable_features",
    multiple=True,
    help="Enable a feature (repeatable). See --list-features.",
)
@click.option(
    "--no-feature",
    "disable_features",
    multiple=True,
    help="Disable a feature (repeatable). See --list-features.",
)
@click.option(
    "--list-features",
    is_flag=True,
    default=False,
    help="List available features and exit",
)
@click.option(
    "--network",
    "network_mode",
    type=click.Choice(["host", "none", "filter"], case_sensitive=False),
    default=None,
    help="Network mode: host (default), none, or filter. Filter is implied by "
    "allow/deny/policy options.",
)
@click.option(
    "--net-policy",
    type=click.Choice(["allow", "deny"], case_sensitive=False),
    default=None,
    help="Default verdict for filter mode (allow or deny). Implies --network filter.",
)
@click.option(
    "--net-allow",
    multiple=True,
    help="Allow an IP/CIDR or hostname (implies --network filter; repeatable).",
)
@click.option(
    "--net-deny",
    multiple=True,
    help="Deny an IP/CIDR or hostname (implies --network filter; repeatable).",
)
@click.option(
    "--net-deny-preset",
    multiple=True,
    help="Deny a named preset (built-in or from [network.presets]). "
    "Implies --network filter. Repeatable.",
)
@click.option(
    "--list-net-presets",
    is_flag=True,
    default=False,
    help="List built-in and config network deny presets and exit",
)
@click.argument(
    "args",
    nargs=-1,
    callback=lambda ctx, arg, value: list(value),
)
def cli(
    debug: bool,
    enable_features: tuple[str, ...],
    disable_features: tuple[str, ...],
    list_features: bool,
    network_mode: str | None,
    net_policy: str | None,
    net_allow: tuple[str, ...],
    net_deny: tuple[str, ...],
    net_deny_preset: tuple[str, ...],
    list_net_presets: bool,
    args: list[str],
) -> None:
    logging.basicConfig(level="DEBUG" if debug else "WARNING")

    config = load_config()

    if list_features or args == ["--list-features"]:
        click.echo(format_features_help(config))
        raise SystemExit(0)

    if list_net_presets or args == ["--list-net-presets"]:
        click.echo(format_deny_presets_help(load_deny_preset_registry(config)))
        raise SystemExit(0)
    command = resolve_launch_command(args)
    executable = command_executable(command, args)
    enabled = resolve_features(
        config,
        executable=executable,
        enable=enable_features,
        disable=disable_features,
    )
    net = resolve_network(
        config,
        executable=executable,
        mode=network_mode,
        policy=net_policy,
        allow=net_allow,
        deny=net_deny,
        deny_presets=net_deny_preset,
    )
    binds = get_binds(config, enabled)
    env_args = get_env_args(config, enabled)

    ensure_cwd_in_sandbox(binds)

    bind_args = get_bind_args(binds)

    with feature_setup(enabled, config) as setup_args:
        bwrap_args = [
            "bwrap",
            "--unshare-all",
            "--clearenv",
            "--die-with-parent",
            "--chdir",
            str(Path.cwd()),
            *bind_args,
            *env_args,
            *setup_args,
            "--",
            *command,
        ]

        if debug:
            log_cmdline(bwrap_args)
            logging.debug("network mode=%s policy=%s allow=%s deny=%s",
                          net.mode, net.policy, net.allow, net.deny)

        exit_code = run_bwrap(bwrap_args, net)

    sys.exit(exit_code)


def load_config():
    try:
        fobj = config_path().open("rb")
    except FileNotFoundError:
        return {}
    with fobj:
        return tomllib.load(fobj)


def get_binds(config: dict, enabled: dict[str, bool] | None = None) -> list:
    if enabled is None:
        enabled = resolve_features(config)
    binds = feature_binds(enabled, config)
    for bind_params in config.get("binds", ()):
        params = dict(bind_params)
        params["source"] = expand_bind_path(str(params["source"]))
        if "target" in params:
            params["target"] = expand_bind_path(str(params["target"]))
        srcpath = Path(params["source"])
        if not srcpath.exists():
            raise FileNotFoundError(srcpath)
        read_only = params.pop("read_only", True)
        config_cls = ROBindConfig if read_only else RWBindConfig
        binds.append(config_cls(**params))
    return binds


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


def get_env_args(config: dict, enabled: dict[str, bool] | None = None) -> Sequence[str]:
    if enabled is None:
        enabled = resolve_features(config)

    res = []
    for var_name in feature_env_var_names(enabled, config):
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


def command_executable(command: list[str], args: list[str]) -> str | None:
    """Executable used for per-command feature config, if the user provided one."""
    if not args:
        return None
    return command[0]


def log_cmdline(cmdline):
    logging.debug("Running:")
    group = [cmdline[0]]
    for arg in cmdline[1:]:
        if arg.startswith("-"):
            logging.debug("  %s", " ".join(group))
            group.clear()
        group.append(arg)
    logging.debug("  %s", " ".join(group))


# Re-export bind helpers for tests and callers that imported them from cli.
from buddelkiste.binds import (  # noqa: E402
    BasicBindConfig,
    DevBindConfig,
    Tmpfs,
)
from buddelkiste.features import SshAgent, find_sandbox_ssh_key  # noqa: E402

__all__ = [
    "BasicBindConfig",
    "DevBindConfig",
    "FEATURES",
    "ROBindConfig",
    "RWBindConfig",
    "SshAgent",
    "Tmpfs",
    "add_bind_to_config",
    "cli",
    "ensure_cwd_in_sandbox",
    "find_sandbox_ssh_key",
    "get_bind_args",
    "get_binds",
    "get_env_args",
    "load_config",
    "resolve_features",
    "resolve_launch_command",
    "resolve_network",
]
