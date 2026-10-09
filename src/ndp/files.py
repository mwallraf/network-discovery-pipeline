"""Safe file writes, latest links, permissions and retention."""

from __future__ import annotations

import grp
import os
import pwd
import tempfile
from datetime import datetime
from pathlib import Path

from ndp.config import Housekeeping

# dated files that housekeeping may delete, relative to the output folder
DATED_PATTERNS = (
    "nmap/scan-2*.xml",
    "nmap/scan-2*.txt",
    "discovery.csv.2*",
    "devices-2*.json",
    "services-2*.csv",
    "run-2*.json",
)


def write_text_atomic(path: Path, text: str) -> None:
    """Write to a temp file in the same folder, then rename over the target."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", newline="") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def atomic_symlink(target_name: str, link: Path) -> None:
    """Point link at target_name (same folder) without a moment where it is missing."""
    link = Path(link)
    tmp = link.with_name(f".{link.name}.tmp")
    tmp.unlink(missing_ok=True)
    os.symlink(target_name, tmp)
    os.replace(tmp, link)


def _resolve_id(value: int | str | None, lookup, attr: str) -> int:
    if value is None:
        return -1
    if isinstance(value, int) or str(value).isdigit():
        return int(value)
    return getattr(lookup(str(value)), attr)


def apply_perms(path: Path, hk: Housekeeping) -> list[str]:
    """Apply mode and owner/group; problems become warnings."""
    path = Path(path)
    warnings: list[str] = []
    mode = int(hk.dir_mode if path.is_dir() else hk.file_mode, 8)
    try:
        os.chmod(path, mode)
    except OSError as exc:
        warnings.append(f"chmod {path}: {exc.strerror}")
    if hk.owner is None and hk.group is None:
        return warnings
    try:
        uid = _resolve_id(hk.owner, pwd.getpwnam, "pw_uid")
        gid = _resolve_id(hk.group, grp.getgrnam, "gr_gid")
        os.chown(path, uid, gid)
    except (KeyError, OSError) as exc:
        warnings.append(f"chown {path} to {hk.owner}:{hk.group} failed: {exc}")
    return warnings


def housekeeping(output: Path, keep_days: int, now: datetime) -> list[Path]:
    """Delete dated files older than keep_days, except targets of *-latest* links."""
    output = Path(output)
    cutoff = now.timestamp() - keep_days * 86400
    protected = {p.resolve() for p in output.rglob("*-latest*") if p.is_symlink()}
    deleted: list[Path] = []
    for pattern in DATED_PATTERNS:
        for path in sorted(output.glob(pattern)):
            if path.is_symlink() or not path.is_file() or path.resolve() in protected:
                continue
            if path.stat().st_mtime < cutoff:
                path.unlink()
                deleted.append(path)
    return deleted
