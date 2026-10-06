"""Detect conflicting sandbox mounts and environment assignments before launch."""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import click

from buddelkiste.binds import (
    BasicBindConfig,
    OverlayBindConfig,
    Tmpfs,
    TmpOverlayBindConfig,
)
from buddelkiste.features import (
    BASE_ENV_VARS,
    bind_from_spec,
    enabled_feature_names,
    load_feature_registry,
)


@dataclass(frozen=True)
class MountClaim:
    """A filesystem mount that will appear at ``target`` inside the sandbox."""

    target: str
    kind: str
    source: str | None
    origin: str

    @property
    def identity(self) -> tuple[str, str | None]:
        return (self.kind, self.source)

    def describe(self) -> str:
        if self.source is None:
            return f"{self.kind} ({self.origin})"
        if self.source == self.target:
            return f"{self.kind} {self.source} ({self.origin})"
        return f"{self.kind} {self.source} -> {self.target} ({self.origin})"


@dataclass(frozen=True)
class EnvClaim:
    """An environment variable that will be set inside the sandbox."""

    name: str
    value: str
    origin: str

    def describe(self) -> str:
        return f"{self.name}={self.value!r} ({self.origin})"


_BIND_FLAG_KIND = {
    "--ro-bind": "ro-bind",
    "--bind": "bind",
    "--dev-bind": "dev-bind",
    "--ro-bind-try": "ro-bind-try",
    "--bind-try": "bind-try",
    "--dev-bind-try": "dev-bind-try",
}


def _norm_target(path: Path | str) -> str:
    return os.path.normpath(os.fspath(path))


def _kind_for_bind(bind: BasicBindConfig) -> str:
    if isinstance(bind, TmpOverlayBindConfig):
        return "tmp-overlay"
    if isinstance(bind, OverlayBindConfig):
        return "overlay"
    flag = bind.flag or ""
    return _BIND_FLAG_KIND.get(flag, flag.lstrip("-") or "bind")


def _source_for_bind(bind: BasicBindConfig) -> str:
    if isinstance(bind, OverlayBindConfig):
        return f"{os.fspath(bind.source)} (upper={os.fspath(bind.upper)})"
    return os.fspath(bind.source)


def claims_from_bind(bind: object, origin: str) -> list[MountClaim]:
    """Return mount claims emitted by a bind object (if it will be applied)."""
    from buddelkiste.binds import RWBindConfig

    if isinstance(bind, Tmpfs):
        return [
            MountClaim(
                target=_norm_target(bind.target),
                kind="tmpfs",
                source=None,
                origin=origin,
            )
        ]

    if isinstance(bind, BasicBindConfig):
        source = Path(os.fspath(bind.source))
        # Match bind ``__iter__``: missing sources are skipped. RW / overlay
        # binds create paths in ``__post_init__``, so they normally exist.
        if not source.exists() and not isinstance(
            bind, (RWBindConfig, OverlayBindConfig)
        ):
            return []

        target = bind.target if bind.target is not None else bind.source
        return [
            MountClaim(
                target=_norm_target(target),
                kind=_kind_for_bind(bind),
                source=_source_for_bind(bind),
                origin=origin,
            )
        ]

    if isinstance(bind, tuple):
        return list(claims_from_bwrap_args(bind, origin))

    return []


def claims_from_bwrap_args(
    args: Sequence[str],
    origin: str,
) -> Iterator[MountClaim]:
    """Parse mount-related flags from a flat bwrap argv fragment."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _BIND_FLAG_KIND and i + 2 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 2]),
                kind=_BIND_FLAG_KIND[arg],
                source=os.fspath(args[i + 1]),
                origin=origin,
            )
            i += 3
            continue
        if arg == "--tmpfs" and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind="tmpfs",
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg == "--dir" and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind="dir",
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg in {"--proc", "--dev"} and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind=arg.lstrip("-"),
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg == "--overlay-src" and i + 1 < len(args):
            # Handled with following --tmp-overlay / --overlay; skip source alone.
            i += 2
            continue
        if arg == "--tmp-overlay" and i + 1 < len(args):
            yield MountClaim(
                target=_norm_target(args[i + 1]),
                kind="tmp-overlay",
                source=None,
                origin=origin,
            )
            i += 2
            continue
        if arg == "--overlay" and i + 3 < len(args):
            upper, _work, target = args[i + 1], args[i + 2], args[i + 3]
            yield MountClaim(
                target=_norm_target(target),
                kind="overlay",
                source=f"(upper={upper})",
                origin=origin,
            )
            i += 4
            continue
        i += 1


def env_claims_from_bwrap_args(
    args: Sequence[str],
    origin: str,
) -> Iterator[EnvClaim]:
    """Parse ``--setenv`` assignments from a flat bwrap argv fragment."""
    i = 0
    while i < len(args):
        if args[i] == "--setenv" and i + 2 < len(args):
            yield EnvClaim(name=args[i + 1], value=args[i + 2], origin=origin)
            i += 3
            continue
        i += 1


def iter_bind_claims(
    config: Mapping,
    enabled: Mapping[str, bool],
) -> Iterator[MountClaim]:
    """Yield mount claims for base + enabled features + config binds."""
    from buddelkiste.features import base_binds

    registry = load_feature_registry(dict(config))
    for bind in base_binds():
        yield from claims_from_bind(bind, "base")
    for name in enabled_feature_names(dict(enabled), registry):
        for bind in registry[name].binds():
            yield from claims_from_bind(bind, f"feature {name!r}")
    for index, bind_params in enumerate(config.get("binds", ())):
        bind = bind_from_spec(dict(bind_params), where=f"binds[{index}]")
        yield from claims_from_bind(bind, f"config binds[{index}]")


def iter_env_claims(
    config: Mapping,
    enabled: Mapping[str, bool],
    *,
    environ: Mapping[str, str] | None = None,
) -> Iterator[EnvClaim]:
    """Yield env claims that ``get_env_args`` would forward or set."""
    envmap = os.environ if environ is None else environ
    registry = load_feature_registry(dict(config))

    for var_name in BASE_ENV_VARS:
        value = envmap.get(var_name)
        if value is not None:
            yield EnvClaim(var_name, value, "base (host environment)")

    for name in enabled_feature_names(dict(enabled), registry):
        for var_name in registry[name].env_vars:
            value = envmap.get(var_name)
            if value is not None:
                yield EnvClaim(
                    var_name,
                    value,
                    f"feature {name!r} (host environment)",
                )

    for index, cfg in enumerate(config.get("envvars", ())):
        var_name = str(cfg["name"])
        if "value" in cfg and cfg["value"] is not None:
            yield EnvClaim(
                var_name,
                str(cfg["value"]),
                f"config envvars[{index}] (explicit value)",
            )
        else:
            value = envmap.get(var_name)
            if value is not None:
                yield EnvClaim(
                    var_name,
                    value,
                    f"config envvars[{index}] (host environment)",
                )


def check_feature_mutex(
    enabled: Mapping[str, bool],
    config: Mapping | None = None,
) -> list[str]:
    """Return human-readable errors for incompatible enabled features."""
    registry = load_feature_registry(dict(config or {}))
    names = enabled_feature_names(dict(enabled), registry)
    active = set(names)
    errors: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()

    for name in names:
        for other in registry[name].conflicts_with:
            if other not in active:
                continue
            pair = (name, other) if name < other else (other, name)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            errors.append(
                f"Features {name!r} and {other!r} cannot be enabled together. "
                f"Disable one with --no-feature {name} or --no-feature {other}."
            )
    return errors


def find_mount_conflicts(claims: Iterable[MountClaim]) -> list[str]:
    """Return errors for the same target claimed incompatibly."""
    by_target: dict[str, list[MountClaim]] = defaultdict(list)
    for claim in claims:
        by_target[claim.target].append(claim)

    errors: list[str] = []
    for target, group in sorted(by_target.items()):
        identities = {claim.identity for claim in group}
        if len(identities) <= 1:
            continue
        lines = [f"Mount target {target}:"]
        # Deduplicate identical claims when listing.
        seen: set[tuple[str, str | None, str]] = set()
        for claim in group:
            key = (*claim.identity, claim.origin)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  - {claim.describe()}")
        errors.append("\n".join(lines))
    return errors


def find_env_conflicts(claims: Iterable[EnvClaim]) -> list[str]:
    """Return errors for the same variable set to different values."""
    by_name: dict[str, list[EnvClaim]] = defaultdict(list)
    for claim in claims:
        by_name[claim.name].append(claim)

    errors: list[str] = []
    for name, group in sorted(by_name.items()):
        values = {claim.value for claim in group}
        if len(values) <= 1:
            continue
        lines = [f"Environment variable {name}:"]
        seen: set[tuple[str, str]] = set()
        for claim in group:
            key = (claim.value, claim.origin)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"  - {claim.describe()}")
        errors.append("\n".join(lines))
    return errors


def check_launch_conflicts(
    *,
    enabled: Mapping[str, bool],
    config: Mapping,
    binds: Sequence[object] = (),
    setup_parts: Sequence[tuple[str, Sequence[str]]] = (),
    hide_args: Sequence[str] = (),
    environ: Mapping[str, str] | None = None,
) -> None:
    """Raise ``ClickException`` if features, mounts, or env assignments conflict.

    Mount and env claims are derived from ``config`` / ``enabled`` with feature
    provenance. ``binds`` may include extras (e.g. cwd whitelist) not present in
    config. Setup fragments and project-config hide args are merged when given.
    """
    errors = check_feature_mutex(enabled, config)

    mount_claims = list(iter_bind_claims(config, enabled))
    known_mounts = {(c.target, c.identity) for c in mount_claims}
    for bind in binds:
        for claim in claims_from_bind(bind, "working-directory / extra bind"):
            key = (claim.target, claim.identity)
            if key not in known_mounts:
                mount_claims.append(claim)
                known_mounts.add(key)

    for name, part in setup_parts:
        mount_claims.extend(claims_from_bwrap_args(part, f"feature {name!r} setup"))
    if hide_args:
        mount_claims.extend(
            claims_from_bwrap_args(hide_args, "project-config mask")
        )
    errors.extend(find_mount_conflicts(mount_claims))

    env_claims = list(iter_env_claims(config, enabled, environ=environ))
    for name, part in setup_parts:
        env_claims.extend(
            env_claims_from_bwrap_args(part, f"feature {name!r} setup")
        )
    errors.extend(find_env_conflicts(env_claims))

    if errors:
        body = "\n\n".join(errors)
        raise click.ClickException(
            "Sandbox configuration conflicts detected; refusing to start.\n\n"
            f"{body}"
        )
