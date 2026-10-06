"""PATH shims that wrap configured executables with ``bk run``."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

import click

SHIM_VERSION = 1
SHIM_MARKER_PREFIX = "# buddelkiste-shim:"
SHIM_MARKER = f"{SHIM_MARKER_PREFIX}{SHIM_VERSION}"


def xdg_bin_dir(*, environ: dict[str, str] | None = None) -> Path:
    """Return the user executable directory (``XDG_BIN_HOME`` or ``~/.local/bin``)."""
    env = environ if environ is not None else os.environ
    override = env.get("XDG_BIN_HOME")
    if override:
        return Path(override).expanduser()
    home = env.get("HOME") or str(Path.home())
    return Path(home) / ".local" / "bin"


def global_shims_enabled(config: dict) -> bool:
    """Return the global ``shims`` toggle (default ``True``)."""
    if "shims" not in config:
        return True
    value = config["shims"]
    if not isinstance(value, bool):
        raise click.ClickException("config 'shims' must be a boolean")
    return value


def executable_shim_enabled(config: dict, entry: dict | None) -> bool:
    """Whether an executable entry should get a PATH shim.

    Precedence: per-entry ``shim`` boolean overrides the global ``shims`` default.
    """
    if isinstance(entry, dict) and "shim" in entry:
        value = entry["shim"]
        if not isinstance(value, bool):
            raise click.ClickException("executables.*.shim must be a boolean")
        return value
    return global_shims_enabled(config)


def shim_decisions_from_config(config: dict) -> dict[str, bool]:
    """Map shim basenames to whether they should be installed.

    Duplicate basenames keep the first decision encountered.
    """
    executables = config.get("executables")
    if not isinstance(executables, dict):
        return {}

    decisions: dict[str, bool] = {}
    for key, entry in executables.items():
        name = Path(str(key)).name
        if not name or name in {".", ".."} or name in decisions:
            continue
        table = entry if isinstance(entry, dict) else None
        decisions[name] = executable_shim_enabled(config, table)
    return decisions


def shim_names_from_config(config: dict) -> list[str]:
    """Basenames that should have PATH shims, stable and de-duplicated."""
    return [name for name, enabled in shim_decisions_from_config(config).items() if enabled]


def render_shim() -> str:
    """Return the shell script body for a buddelkiste PATH shim."""
    return f"""\
#!/bin/sh
{SHIM_MARKER}
# Managed by buddelkiste (`bk shims install`). Do not edit.
set -eu
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
name=$(basename -- "$0")
bk=$(command -v bk) || {{
  printf '%s\\n' "buddelkiste: bk not found on PATH" >&2
  exit 127
}}
# Walk PATH (skipping this shim directory) for a real executable file.
# Avoid `command -v`, which may report shell builtins.
real=
old_ifs=$IFS
IFS=:
for p in $PATH; do
  [ -n "$p" ] || continue
  [ "$p" = "$dir" ] && continue
  candidate=$p/$name
  if [ -f "$candidate" ] && [ -x "$candidate" ]; then
    real=$candidate
    break
  fi
done
IFS=$old_ifs
[ -n "$real" ] || {{
  printf '%s\\n' "buddelkiste: $name not found on PATH outside $dir" >&2
  exit 127
}}
exec "$bk" run "$real" "$@"
"""


def is_our_shim(path: Path) -> bool:
    """True if ``path`` is a buddelkiste-managed shim (any marker version)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    for line in text.splitlines()[:8]:
        if line.startswith(SHIM_MARKER_PREFIX):
            return True
    return False


def _path_entries(path_value: str | None = None) -> list[Path]:
    raw = path_value if path_value is not None else os.environ.get("PATH", "")
    return [Path(part) for part in raw.split(":") if part]


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def _is_executable(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


@dataclass(frozen=True)
class ShimInstallResult:
    name: str
    path: Path
    action: str  # created | updated | unchanged | skipped | removed


def install_shims(
    names: list[str],
    *,
    bin_dir: Path | None = None,
    remove: list[str] | None = None,
) -> list[ShimInstallResult]:
    """Create or refresh shims for ``names`` under the XDG bin directory.

    Existing non-shim files are left alone (``skipped``). Our own shims are
    rewritten when their contents differ from the current template. Names in
    ``remove`` delete a managed shim if present.
    """
    target_dir = bin_dir if bin_dir is not None else xdg_bin_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    body = render_shim()
    results: list[ShimInstallResult] = []

    for name in remove or ():
        path = target_dir / name
        if path.exists() and is_our_shim(path):
            path.unlink()
            results.append(ShimInstallResult(name, path, "removed"))
        elif path.exists():
            results.append(ShimInstallResult(name, path, "skipped"))

    for name in names:
        path = target_dir / name
        if path.exists() and not is_our_shim(path):
            results.append(ShimInstallResult(name, path, "skipped"))
            continue

        existed = path.exists()
        previous = path.read_text(encoding="utf-8") if existed else None
        if previous == body:
            results.append(ShimInstallResult(name, path, "unchanged"))
            continue

        path.write_text(body, encoding="utf-8")
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        action = "updated" if existed else "created"
        results.append(ShimInstallResult(name, path, action))

    return results


def install_shims_from_config(
    config: dict,
    *,
    bin_dir: Path | None = None,
) -> list[ShimInstallResult]:
    """Install/update enabled shims and remove managed shims that are disabled."""
    decisions = shim_decisions_from_config(config)
    enabled = [name for name, on in decisions.items() if on]
    disabled = [name for name, on in decisions.items() if not on]
    return install_shims(enabled, bin_dir=bin_dir, remove=disabled)


@dataclass(frozen=True)
class ShimCheckIssue:
    name: str
    message: str


def check_shims(
    names: list[str],
    *,
    bin_dir: Path | None = None,
    path_value: str | None = None,
) -> list[ShimCheckIssue]:
    """Return issues where a non-shim executable would win over our shim on PATH."""
    target_dir = bin_dir if bin_dir is not None else xdg_bin_dir()
    path_dirs = _path_entries(path_value)
    issues: list[ShimCheckIssue] = []

    bin_on_path = any(_same_path(entry, target_dir) for entry in path_dirs)
    if names and not bin_on_path:
        issues.append(
            ShimCheckIssue(
                "*",
                f"shim directory {target_dir} is not on PATH; "
                "installed shims will not intercept commands",
            )
        )

    for name in names:
        shim_path = target_dir / name
        first: Path | None = None
        for directory in path_dirs:
            candidate = directory / name
            if not _is_executable(candidate):
                continue
            first = candidate
            break

        if first is None:
            if shim_path.exists() and is_our_shim(shim_path):
                issues.append(
                    ShimCheckIssue(
                        name,
                        f"shim exists at {shim_path} but is not reachable via PATH",
                    )
                )
            else:
                issues.append(
                    ShimCheckIssue(
                        name,
                        f"no shim installed for {name!r} "
                        f"(expected {shim_path}); run `bk shims install`",
                    )
                )
            continue

        if is_our_shim(first) and _same_path(first, shim_path):
            continue

        if is_our_shim(first):
            # Another buddelkiste shim earlier on PATH — unusual but safe.
            continue

        issues.append(
            ShimCheckIssue(
                name,
                f"{first} is found on PATH before the buddelkiste shim "
                f"at {shim_path}; calls to {name!r} will bypass the sandbox",
            )
        )

    return issues
