"""Trusted-binary resolution shared by gpg, gpgconf and zenity."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from .errors import GpgMcpError


def secure_binary(name: str, *, required: bool = True) -> str | None:
    """Resolve an executable and refuse unsafe ownership/permissions.

    The same trust checks apply to every executable the server launches,
    including the local approval dialog. ``PATH`` is searched once, then the
    resolved path is checked as a regular file, not group/world writable and
    owned by root or the current user.
    """
    found = shutil.which(name)
    if not found:
        if required:
            raise GpgMcpError(f"required binary not found: {name}")
        return None
    path = Path(found).resolve()
    try:
        st = path.stat()
    except OSError as exc:
        raise GpgMcpError(f"cannot stat {path}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise GpgMcpError(f"{path} is not a regular file")
    if st.st_mode & 0o022:
        raise GpgMcpError(f"{path} is group/world writable; refusing to execute it")
    if st.st_uid not in (0, os.getuid()):
        raise GpgMcpError(f"{path} is not owned by root or the current user")
    return str(path)
