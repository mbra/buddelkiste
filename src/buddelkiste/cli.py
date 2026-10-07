"""Bubblewrap sandbox CLI (`bk`)."""

from __future__ import annotations

import json
import logging
import os
import pwd
import sys
import tempfile
import tomllib
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

import click

log = logging.getLogger(__name__)

RUN_HELP = """Run a command inside a bubblewrap sandbox.

Pass the executable and its arguments after any wrapper options. They are run
inside the sandbox. Wrapper options are --debug, feature toggles, and network
controls; everything else is forwarded as the sandboxed command.

With no command, a login shell is started inside the sandbox so the environment
can be inspected.


# Features

Optional permission sets are grouped by topic (home, cursor, python, ssh, ...).
Only ``home`` is on by default; other built-ins are opt-in. Features are
registered via the buddelkiste.features entry-point group (third-party packages
can add more). Toggle with --feature / --no-feature, or in config. Define
pure-TOML features under [feature.<name>]. Use `bk list-features` to print the
catalog (includes module paths).

Config may set features globally and per executable (matched by path or
basename of the command being started). A list selects exactly those features;
a table applies true/false overrides. Per-executable config may also set
network and args (extra arguments appended to the command).

For each configured executable, `bk shims install` can place a PATH wrapper
in $XDG_BIN_HOME (~/.local/bin) that runs the real binary via `bk run`.
Use `bk shims check` to detect originals that shadow those shims on PATH.


# Network

Modes: filter (default; private netns via pasta or slirp4netns with
in-namespace nftables IP/CIDR allow/deny), host (share host network), none
(no connectivity). Filter mode needs no root and no reserved host subnets.
By default filter also applies the ``internal`` and ``localhost`` deny presets
(RFC1918/ULA and loopback). Host loopback is additionally blocked by
pasta/slirp.

In filter mode, nameserver IPs from /etc/resolv.conf are auto-allowed so DNS
keeps working under a default-deny policy. Rules may be IP/CIDR literals or
hostnames (exact or *.suffix); hostnames use a DNS proxy that publishes
resolved A/AAAA addresses into dynamic nft sets. Named deny presets (internal,
private, localhost, linklocal, metadata, plus custom names under
[network.presets]) expand to IP/CIDR or hostname denials; see
`bk list-net-presets`.


# Configuration

Configuration is read from ~/.config/buddelkiste/config.toml, then merged with
a project file `.buddelkiste.toml` found in the current directory or an ancestor
(project values win). The project file is masked inside the sandbox (empty file
over the path) so the command cannot read it. The files support the following
top-level keys:

features: Global feature selection. Either a list of feature names (allowlist)
or a table of feature name = true/false overrides.

feature: Table of custom feature definitions under [feature.<name>]. Each may
set description, default, env (allowlisted variable names), binds (list of
source/target/mode tables), and conflicts_with (other feature names that must
not be enabled at the same time). Bind paths may use $VAR or ${VAR}. Packages
may also register features via the buddelkiste.features entry-point group.
Before starting, bk refuses launches with conflicting mounts, conflicting
--setenv values (host-forwarded or setup-defined), or mutually exclusive
features.

executables: Table keyed by executable path or basename. Each entry may contain
a features list or table, a network table, an args list of extra arguments
appended to the command, and/or a shim boolean (override the global shims
toggle), applied when that executable is started.

shims: Global boolean (default true). When true, `bk shims install` creates
PATH wrappers for configured executables; set false to disable unless an
entry sets shim = true. Per-executable shim overrides this default.

network: Global network settings (mode, policy, allow, deny, deny_presets).
Optional [network.presets] defines custom named deny lists. See example.

binds: List of additional bind mounts for the sandbox with "source", "target"
and "mode" keys. The "source" key is mandatory and gives the host directory
to bind into the sandbox. The "target" key is optional and gives the mountpoint
inside the sandbox; this defaults to the host-side path. The "mode" key defaults
to "ro" (read-only). Other modes: "rw" (read-write bind), "tmp-overlay"
(writable via ephemeral overlayfs; host source unchanged), "overlay"
(writable via overlayfs with a persistent upper under
$XDG_CACHE_HOME/buddelkiste/overlays/<hash-of-source>), or
"overlay:<path>" (explicit persistent upper; <path> may use $VAR / ${VAR}).

envvars: List of additional environment variables for the sandbox. The mandatory
"name" key gives the name of the variable. The value can be specified in the
"value" key. If no value is given, it is taken from the process environment.

docker_proxy: Optional table used by the docker-proxy feature. Declares allowlisted
images (and related policy) for the project. Host enforcement lives under
~/.config/buddelkiste/docker-proxy/; use `bk docker-policy apply` to promote the
declaration. Unknown images hold until `bk docker-policy approve` /
`deny` when approval.on_unknown_image is "session" (the default). Mutually
exclusive with the raw docker and docker-instance features.

docker_instance: Optional table for the docker-instance feature (project-local
rootless dockerd). Keys: data_root (default under XDG_DATA_HOME), fs
(host|project|data), fs_allow, net (host|userspace|none), proxy (default true),
and nested [docker_instance.policy] (same shape as docker_proxy, with instance
defaults that allow build and images=["*"]). Mutually exclusive with docker and
docker-proxy.

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
  mode = "rw"

\b
  [[feature.rust.binds]]
  source = "${HOME}/.rustup"
  mode = "ro"

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
  args = ["--force"]

\b
  [executables.cursor-agent.network]
  mode = "filter"
  policy = "deny"
  allow = ["1.1.1.1/32"]

\b
  [executables.python]
  features = ["python", "git"]
  shim = false

\b
  # shims = false  # disable PATH shims globally (per-entry shim=true still wins)

\b
  [[binds]]
  source = "/path/to/directory"  # path is whitelisted for the sandbox
  mode = "ro"  # or "rw", "tmp-overlay", "overlay", "overlay:$XDG_CACHE_HOME/bk-upper"

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

from buddelkiste.binds import ROBindConfig, RWBindConfig, bind_config, get_bind_args
from buddelkiste.conflicts import check_launch_conflicts
from buddelkiste.features import (
    FEATURES,
    bind_from_spec,
    check_feature_requirements,
    feature_binds,
    feature_env_var_names,
    feature_setup,
    format_features_help,
    lookup_executable_config,
    resolve_features,
)
from buddelkiste.network import (
    format_deny_presets_help,
    load_deny_preset_registry,
    resolve_network,
    run_bwrap,
)
from buddelkiste.shims import (
    check_shims,
    install_shims_from_config,
    shim_decisions_from_config,
    shim_names_from_config,
    xdg_bin_dir,
)

env = os.getenv

CONFIG_PATH = Path("~/.config/buddelkiste/config.toml")
PROJECT_CONFIG_NAME = ".buddelkiste.toml"


@click.group(help=__doc__)
def cli() -> None:
    """Bubblewrap sandbox CLI."""


@cli.command(
    "run",
    help=RUN_HELP,
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
    help="Enable a feature (repeatable). See `bk list-features`.",
)
@click.option(
    "--no-feature",
    "disable_features",
    multiple=True,
    help="Disable a feature (repeatable). See `bk list-features`.",
)
@click.option(
    "--network",
    "network_mode",
    type=click.Choice(["host", "none", "filter"], case_sensitive=False),
    default=None,
    help="Network mode: filter (default), host, or none. Filter is also implied "
    "by allow/deny/policy options when mode is omitted.",
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
    "Implies --network filter. Repeatable. See `bk list-net-presets`.",
)
@click.argument(
    "args",
    nargs=-1,
    callback=lambda ctx, arg, value: list(value),
)
def run(
    debug: bool,
    enable_features: tuple[str, ...],
    disable_features: tuple[str, ...],
    network_mode: str | None,
    net_policy: str | None,
    net_allow: tuple[str, ...],
    net_deny: tuple[str, ...],
    net_deny_preset: tuple[str, ...],
    args: list[str],
) -> None:
    logging.basicConfig(level="DEBUG" if debug else "WARNING")

    config = load_config()
    project_config = find_project_config()
    command = resolve_launch_command(args)
    executable = command_executable(command, args)
    command = append_executable_args(command, config, executable)
    enabled = resolve_features(
        config,
        executable=executable,
        enable=enable_features,
        disable=disable_features,
    )
    check_feature_requirements(enabled, config)
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

    with (
        feature_setup(enabled, config) as setup_parts,
        project_config_hide_args(project_config) as hide_args,
    ):
        setup_args = [arg for _name, part in setup_parts for arg in part]
        check_launch_conflicts(
            enabled=enabled,
            config=config,
            binds=binds,
            setup_parts=setup_parts,
            hide_args=hide_args,
        )
        bwrap_args = [
            "bwrap",
            "--unshare-all",
            "--clearenv",
            "--die-with-parent",
            "--chdir",
            str(Path.cwd()),
            *bind_args,
            *hide_args,
            *env_args,
            *setup_args,
            "--",
            *command,
        ]

        if debug:
            log_cmdline(bwrap_args)
            log.debug("network mode=%s policy=%s allow=%s deny=%s",
                      net.mode, net.policy, net.allow, net.deny)

        exit_code = run_bwrap(bwrap_args, net)

    sys.exit(exit_code)


@cli.command("list-features")
def list_features() -> None:
    """List available features and their origins."""
    click.echo(format_features_help(load_config()))


@cli.command("list-net-presets")
def list_net_presets() -> None:
    """List built-in and config network deny presets."""
    click.echo(format_deny_presets_help(load_deny_preset_registry(load_config())))


@cli.group("docker-policy")
def docker_policy_group() -> None:
    """Show and apply host-side docker-proxy allowlists."""


@docker_policy_group.command("path")
def docker_policy_path() -> None:
    """Print the host policy file path for the current project."""
    from buddelkiste.docker_proxy import host_policy_path, project_policy_key

    key = project_policy_key()
    click.echo(host_policy_path(key))


@docker_policy_group.command("show")
def docker_policy_show() -> None:
    """Show the effective docker-proxy policy for the current project."""
    from buddelkiste.docker_proxy import load_effective_policy, project_policy_key

    policy = load_effective_policy(config=load_config())
    click.echo(f"project: {project_policy_key()}")
    click.echo(f"on_unknown_image: {policy.on_unknown_image}")
    click.echo(f"images ({len(policy.images)}):")
    if not policy.images:
        click.echo("  (none)")
    for ref in policy.images:
        click.echo(f"  - {ref}")


@docker_policy_group.command("apply")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be written without changing the host policy file.",
)
def docker_policy_apply(dry_run: bool) -> None:
    """Write ``[docker_proxy]`` from config into the host enforcement store."""
    from buddelkiste.docker_proxy import (
        declaration_from_config,
        host_policy_path,
        project_policy_key,
        write_policy_file,
    )

    config = load_config()
    declaration = declaration_from_config(config)
    if declaration is None:
        raise click.ClickException(
            "No [docker_proxy] table in config; add images there first"
        )
    key = project_policy_key()
    path = host_policy_path(key)
    if dry_run:
        click.echo(f"Would write {len(declaration.images)} image(s) to {path}")
        for ref in declaration.images:
            click.echo(f"  - {ref}")
        return
    write_policy_file(path, declaration)
    click.echo(f"Wrote {len(declaration.images)} image(s) to {path}")


@docker_policy_group.command("pending")
def docker_policy_pending() -> None:
    """List image approvals currently held by a live docker-proxy.

    Run this on the host (outside the sandbox); the control socket is not
    exposed inside the bubblewrap environment.
    """
    from buddelkiste.docker_proxy import control_request

    resp = control_request({"op": "list"})
    if not resp.get("ok"):
        raise click.ClickException(str(resp.get("error") or "list failed"))
    pending = resp.get("pending") or []
    if not pending:
        click.echo("No pending image approvals.")
        return
    for item in pending:
        click.echo(f"{item.get('id')}\t{item.get('image')}")


@docker_policy_group.command("approve")
@click.argument("target", required=False)
def docker_policy_approve(target: str | None) -> None:
    """Allow a held image for this session (unblocks the waiting Docker client).

    TARGET is a pending id or image reference. When omitted and exactly one
    request is held, that request is approved. Run on the host (outside the
    sandbox).
    """
    from buddelkiste.docker_proxy import control_request

    req: dict = {"op": "approve"}
    if target is not None:
        req["target"] = target
    resp = control_request(req)
    if not resp.get("ok"):
        raise click.ClickException(str(resp.get("error") or "approve failed"))
    click.echo(f"Approved {resp.get('image')} (id={resp.get('id')}) for this session")


@docker_policy_group.command("deny")
@click.argument("target", required=False)
def docker_policy_deny(target: str | None) -> None:
    """Deny a held image request (unblocks the waiting Docker client with 403).

    TARGET is a pending id or image reference. When omitted and exactly one
    request is held, that request is denied. Run on the host (outside the
    sandbox).
    """
    from buddelkiste.docker_proxy import control_request

    req: dict = {"op": "deny"}
    if target is not None:
        req["target"] = target
    resp = control_request(req)
    if not resp.get("ok"):
        raise click.ClickException(str(resp.get("error") or "deny failed"))
    click.echo(f"Denied {resp.get('image')} (id={resp.get('id')})")


@cli.group("shims")
def shims_group() -> None:
    """Install and verify PATH shims for configured executables.

    For each key under ``[executables.<name>]`` with shimming enabled, a small
    ``sh`` wrapper is placed in ``$XDG_BIN_HOME`` (default ``~/.local/bin``)
    that runs ``bk run <real-binary>`` with the caller's arguments. Control
    with top-level ``shims = true/false`` (default true) and per-entry
    ``shim = true/false``. Shims carry a ``# buddelkiste-shim:`` marker so
    ``install`` can refresh or remove our own files without clobbering
    unrelated binaries of the same name.
    """


@shims_group.command("install")
def shims_install() -> None:
    """Create or update PATH shims for configured executables."""
    config = load_config()
    decisions = shim_decisions_from_config(config)
    if not decisions:
        click.echo("No [executables] entries in config; nothing to install.", err=True)
        return

    bin_dir = xdg_bin_dir()
    results = install_shims_from_config(config, bin_dir=bin_dir)
    if not results:
        click.echo("All configured executables have shimming disabled; nothing to do.")
        return
    for result in results:
        click.echo(f"{result.action:9} {result.path}")
    skipped = [r for r in results if r.action == "skipped"]
    if skipped:
        click.echo(
            f"Left {len(skipped)} existing non-shim file(s) untouched "
            "(remove or rename them, then re-run).",
            err=True,
        )


@shims_group.command("check")
def shims_check() -> None:
    """Warn if originals on PATH would bypass installed shims."""
    config = load_config()
    decisions = shim_decisions_from_config(config)
    if not decisions:
        click.echo("No [executables] entries in config; nothing to check.", err=True)
        return

    names = shim_names_from_config(config)
    if not names:
        click.echo("All configured executables have shimming disabled; nothing to check.")
        return

    issues = check_shims(names, bin_dir=xdg_bin_dir())
    if not issues:
        click.echo(f"OK: {len(names)} shim(s) intercept PATH correctly.")
        return

    for issue in issues:
        prefix = "warning" if issue.name == "*" else f"warning ({issue.name})"
        click.echo(f"{prefix}: {issue.message}", err=True)
    raise SystemExit(1)


def load_toml_file(path: Path) -> dict:
    with path.open("rb") as fobj:
        data = tomllib.load(fobj)
    if not isinstance(data, dict):
        raise click.ClickException(f"Config {path} must be a TOML table")
    return data


def find_project_config(start: Path | None = None) -> Path | None:
    """Return `.buddelkiste.toml` in ``start`` or an ancestor, if present."""
    cur = (start or Path.cwd()).resolve()
    for directory in (cur, *cur.parents):
        candidate = directory / PROJECT_CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def _merge_network(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if (
            key == "presets"
            and isinstance(value, dict)
            and isinstance(merged.get("presets"), dict)
        ):
            merged["presets"] = {**merged["presets"], **value}
        else:
            merged[key] = value
    return merged


def _merge_executables(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for name, data in overlay.items():
        existing = merged.get(name)
        if isinstance(data, dict) and isinstance(existing, dict):
            entry = dict(existing)
            for key, value in data.items():
                if (
                    key == "network"
                    and isinstance(value, dict)
                    and isinstance(entry.get("network"), dict)
                ):
                    entry["network"] = _merge_network(entry["network"], value)
                else:
                    entry[key] = value
            merged[name] = entry
        else:
            merged[name] = data
    return merged


def merge_config(base: dict, overlay: dict) -> dict:
    """Merge project config over user config.

    ``binds`` / ``envvars`` lists are concatenated. Nested ``feature``,
    ``executables``, and ``network`` tables are merged (project wins on
    conflicts). Other keys are replaced by the overlay value.
    """
    result = dict(base)
    for key, value in overlay.items():
        if key in {"binds", "envvars"} and isinstance(value, list):
            result[key] = [*result.get(key, []), *value]
        elif key == "feature" and isinstance(value, dict):
            merged = dict(result.get("feature") or {})
            merged.update(value)
            result["feature"] = merged
        elif key == "executables" and isinstance(value, dict):
            existing = result.get("executables")
            result["executables"] = (
                _merge_executables(existing, value)
                if isinstance(existing, dict)
                else value
            )
        elif key == "network" and isinstance(value, dict):
            existing = result.get("network")
            result["network"] = (
                _merge_network(existing, value) if isinstance(existing, dict) else value
            )
        else:
            result[key] = value
    return result


@contextmanager
def project_config_hide_args(
    project_config: Path | None,
) -> Iterator[list[str]]:
    """Yield bwrap args that mask the project config with an empty file."""
    if project_config is None:
        yield []
        return
    # Prefer an empty regular file over /dev/null: in a user namespace,
    # binding the null device often yields an unreadable character device.
    with tempfile.NamedTemporaryFile(prefix="bk-mask-", suffix=".toml") as mask:
        yield ["--ro-bind", mask.name, str(project_config.resolve())]


def load_config() -> dict:
    config: dict = {}
    user_path = config_path()
    if user_path.is_file():
        config = load_toml_file(user_path)
    project_path = find_project_config()
    if project_path is not None:
        config = merge_config(config, load_toml_file(project_path))
    return config


def get_binds(config: dict, enabled: dict[str, bool] | None = None) -> list:
    if enabled is None:
        enabled = resolve_features(config)
    binds = feature_binds(enabled, config)
    for index, bind_params in enumerate(config.get("binds", ())):
        bind = bind_from_spec(dict(bind_params), where=f"binds[{index}]")
        if not Path(bind.source).exists():
            raise FileNotFoundError(bind.source)
        binds.append(bind)
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
        if hasattr(bind, "covers_path") and bind.covers_path(cwd):
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

    mode = "rw" if click.confirm("Allow write access?", default=True, err=True) else "ro"

    if choice == "always":
        add_bind_to_config(cwd, mode=mode)
        click.echo(f"Added {cwd} to {CONFIG_PATH}.", err=True)

    binds.append(bind_config(cwd, mode=mode))


def add_bind_to_config(source: Path, *, mode: str = "ro") -> None:
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
        f"mode = {json.dumps(mode)}",
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
        if value is not None:
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


def append_executable_args(
    command: list[str],
    config: dict,
    executable: str | None,
) -> list[str]:
    """Append ``executables.<name>.args`` to the command, if configured."""
    exec_cfg = lookup_executable_config(config, executable)
    if not exec_cfg or "args" not in exec_cfg:
        return command

    extra = exec_cfg["args"]
    if not isinstance(extra, list) or not all(isinstance(arg, str) for arg in extra):
        raise click.ClickException(
            f"executables args for {executable!r} must be a list of strings"
        )
    return [*command, *extra]


def log_cmdline(cmdline):
    log.debug("Running:")
    group = [cmdline[0]]
    for arg in cmdline[1:]:
        if arg.startswith("-"):
            log.debug("  %s", " ".join(group))
            group.clear()
        group.append(arg)
    log.debug("  %s", " ".join(group))


# Re-export bind helpers for tests and callers that imported them from cli.
from buddelkiste.binds import (
    BasicBindConfig,
    DevBindConfig,
    OverlayBindConfig,
    Tmpfs,
    TmpOverlayBindConfig,
)
from buddelkiste.features import SshAgent, find_sandbox_ssh_key

__all__ = [
    "FEATURES",
    "BasicBindConfig",
    "DevBindConfig",
    "OverlayBindConfig",
    "ROBindConfig",
    "RWBindConfig",
    "SshAgent",
    "TmpOverlayBindConfig",
    "Tmpfs",
    "add_bind_to_config",
    "append_executable_args",
    "bind_config",
    "cli",
    "ensure_cwd_in_sandbox",
    "find_project_config",
    "find_sandbox_ssh_key",
    "get_bind_args",
    "get_binds",
    "get_env_args",
    "list_features",
    "list_net_presets",
    "load_config",
    "merge_config",
    "project_config_hide_args",
    "resolve_features",
    "resolve_launch_command",
    "resolve_network",
    "run",
]
