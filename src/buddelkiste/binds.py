"""Bubblewrap bind-mount helpers."""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path


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
        source = os.fspath(self.source)
        target = os.fspath(self.target) if self.target is not None else source
        if Path(source).exists():
            yield from (self.flag, source, target)

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
class TmpOverlayBindConfig(BasicBindConfig):
    """Read from source; sandbox writes go to an ephemeral tmpfs overlay."""

    def __iter__(self) -> Iterator[str]:
        source = os.fspath(self.source)
        target = os.fspath(self.target) if self.target is not None else source
        if Path(source).exists():
            yield from ("--overlay-src", source, "--tmp-overlay", target)


@dataclass(kw_only=True)
class OverlayBindConfig(BasicBindConfig):
    """Read from source; sandbox writes persist in a host upper directory."""

    upper: Path | str
    work: Path | str | None = None

    def __post_init__(self):
        super().__post_init__()
        upper_path = Path(os.fspath(self.upper))
        upper_path.mkdir(parents=True, exist_ok=True)
        self.upper = os.fspath(upper_path)

        if self.work is None:
            work_path = upper_path.parent / f".{upper_path.name}.work"
        else:
            work_path = Path(os.fspath(self.work))
        if work_path.exists():
            shutil.rmtree(work_path)
        work_path.mkdir(parents=True)
        self.work = os.fspath(work_path)

    def __iter__(self) -> Iterator[str]:
        source = os.fspath(self.source)
        target = os.fspath(self.target) if self.target is not None else source
        work = self.work
        if work is None:
            raise TypeError("OverlayBindConfig.work was not initialized")
        if Path(source).exists():
            yield from (
                "--overlay-src",
                source,
                "--overlay",
                os.fspath(self.upper),
                os.fspath(work),
                target,
            )


@dataclass
class Tmpfs:
    target: Path | str

    def __iter__(self) -> Iterator[str]:
        return iter(("--tmpfs", os.fspath(self.target)))


def overlay_cache_upper(source: Path | str) -> Path:
    """Return a unique cache upper dir for ``source`` under XDG cache."""
    resolved = str(Path(source).expanduser().resolve())
    digest = hashlib.sha256(resolved.encode()).hexdigest()
    cache_home = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_home / "buddelkiste" / "overlays" / digest


def bind_config(
    source: Path | str,
    target: Path | str | None = None,
    *,
    mode: str = "ro",
):
    """Build a bind config from a mode string.

    Allowed modes: ``ro`` (default), ``rw``, ``tmp-overlay``, ``overlay``
    (persistent upper under the cache dir, named by a hash of the source
    path), or ``overlay:<path>`` for an explicit upper directory.
    """
    if mode == "ro":
        return ROBindConfig(source, target)
    if mode == "rw":
        return RWBindConfig(source, target)
    if mode == "tmp-overlay":
        return TmpOverlayBindConfig(source, target)
    if mode == "overlay":
        return OverlayBindConfig(source, target, upper=overlay_cache_upper(source))

    if mode.startswith("overlay:"):
        upper = mode.removeprefix("overlay:")
        if not upper:
            raise ValueError(
                "Invalid bind mode 'overlay:': use 'overlay' for an automatic "
                "cache upper, or 'overlay:<path>' for an explicit path"
            )
        return OverlayBindConfig(source, target, upper=upper)

    raise ValueError(
        f"Invalid bind mode {mode!r}: expected 'ro', 'rw', "
        "'tmp-overlay', 'overlay', or 'overlay:<path>'"
    )


def get_bind_args(binds) -> Sequence[str]:
    res = []
    for bind in binds:
        res.extend(bind)
    return res
