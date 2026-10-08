"""Cleanup for docker-instance e2e tmp dirs."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _unlock_containerd_overlay_tmp(tmp_path: Path) -> Iterator[None]:
    """Remove containerd overlayfs work dirs so pytest can delete the basetemp.

    Rootless dockerd writes layers under ``data_root/.../overlayfs/snapshots/N``.
    After the daemon exits the kernel leaves ``work/work`` as mode ``000`` with
    whiteout character devices. pytest ``rm_rf`` then fails with ``ENOTEMPTY``
    and relocates the tree to ``garbage-*``.
    """
    yield
    from buddelkiste.binds import force_rmtree

    for child in list(tmp_path.iterdir()):
        if child.is_dir():
            force_rmtree(child)
        else:
            try:
                child.unlink()
            except OSError:
                pass
