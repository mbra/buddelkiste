"""Executable lookup that also searches sbin directories.

Arch merges ``/usr/sbin`` into ``/usr/bin``, so a user ``PATH`` already finds
``iptables``. Debian keeps ``iptables``, ``nft``, and ``sysctl`` in
``/usr/sbin``, which that ``PATH`` often omits. Callers should use :func:`which`
instead of :func:`shutil.which`.
"""

from __future__ import annotations

import os
import shutil

# Not on a typical user PATH. Searched after PATH so an earlier match wins.
SBIN_DIRS = ("/usr/local/sbin", "/usr/sbin", "/sbin")


def which(
    cmd: str,
    mode: int = os.F_OK | os.X_OK,
    path: str | None = None,
) -> str | None:
    """Return the path to ``cmd``, searching ``PATH`` and then sbin directories."""
    search = os.environ.get("PATH", "") if path is None else path
    parts = [part for part in search.split(os.pathsep) if part]
    for directory in SBIN_DIRS:
        if directory not in parts:
            parts.append(directory)
    return shutil.which(cmd, mode=mode, path=os.pathsep.join(parts))
