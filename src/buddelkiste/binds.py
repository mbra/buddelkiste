"""Bubblewrap bind-mount helpers."""

from __future__ import annotations

import os
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


def get_bind_args(binds) -> Sequence[str]:
    res = []
    for bind in binds:
        res.extend(bind)
    return res
