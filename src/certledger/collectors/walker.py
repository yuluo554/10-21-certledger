"""Deterministic filesystem traversal.

Ordering is a correctness property, not cosmetics: the report is compared
byte-for-byte across runs, so the candidate stream must be identical on the
second run. Two rules make that true:

* **sort by a normalised key** — Unicode NFC plus casefold. Raw byte order
  differs between filesystems (``A`` vs ``a`` sorts differently on ext4 and
  NTFS), and an NFD filename from macOS would sort as a different name than the
  same NFC name elsewhere;
* **never rely on ``os.walk`` order** — it is filesystem order, which is not
  promised to be stable even on one machine.

Every skip produces a record. A walker that silently drops what it cannot read
turns "we could not look" into "there is nothing there", which is the failure
mode this project exists to rule out (plan/03 §⑥).
"""

from __future__ import annotations

import os
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path

SKIP_BINARY = "SKIP_BINARY"
SKIP_PERMISSION_DENIED = "SKIP_PERMISSION_DENIED"
SKIP_TOO_LARGE = "SKIP_TOO_LARGE"
SKIP_SYMLINK = "SKIP_SYMLINK"
SKIP_UNKNOWN_FORMAT = "SKIP_UNKNOWN_FORMAT"
SKIP_UNREADABLE = "SKIP_UNREADABLE"

SKIP_CODES = (
    SKIP_BINARY,
    SKIP_PERMISSION_DENIED,
    SKIP_TOO_LARGE,
    SKIP_SYMLINK,
    SKIP_UNKNOWN_FORMAT,
    SKIP_UNREADABLE,
)


def normalize_path(path: str) -> str:
    """Canonical display form: NFC, forward slashes, no trailing separator.

    Case is **not** folded away here — the real name is kept so the user can
    find the file. Case-folding is used for the *sort key* only.
    """
    text = unicodedata.normalize("NFC", path)
    text = text.replace("\\", "/")
    if len(text) > 1 and text.endswith("/"):
        text = text.rstrip("/") or "/"
    return text


def sort_key(path: str) -> tuple[str, str]:
    """Stable ordering key: case-folded first, exact form second.

    The second component breaks ties deterministically between ``A`` and ``a``,
    which casefold alone would leave to filesystem order.
    """
    normal = normalize_path(path)
    return (normal.casefold(), normal)


@dataclass(frozen=True, slots=True)
class Candidate:
    """One file the walk decided is worth opening."""

    path: str
    size: int


@dataclass(frozen=True, slots=True)
class Skip:
    """One file or directory the walk declined, with the reason."""

    path: str
    code: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class WalkResult:
    candidates: tuple[Candidate, ...]
    skips: tuple[Skip, ...]
    #: Files the walk saw at all (candidates + skips). The invariant
    #: ``visited == len(candidates) + len(skips)`` is what makes the summary
    #: auditable: no file may be counted in neither bucket.
    visited: int
    directories: int
    #: Directories reached a second time through another route (a junction and
    #: its target, a bind mount, two ``--roots`` overlapping). Their files were
    #: scanned once already, so rescanning would double-count every candidate.
    #: Counted here rather than dropped, so the reduction stays visible.
    deduplicated: int = 0


def walk(
    roots: list[str],
    files: list[str],
    *,
    follow_symlinks: bool,
    max_size: int,
) -> WalkResult:
    """Collect candidate files from ``roots`` (recursive) and ``files`` (explicit).

    Symlinks are skipped unless ``follow_symlinks`` is set. Following them by
    default risks an unbounded walk (``/proc``-style loops) and reading outside
    the tree the user named.
    """
    candidates: list[Candidate] = []
    skips: list[Skip] = []

    for explicit in files:
        _consider_file(explicit, candidates, skips, max_size=max_size)

    seen_dirs: set[str] = set()
    deduplicated: list[int] = [0]
    for root in roots:
        _walk_root(
            root,
            candidates,
            skips,
            follow_symlinks=follow_symlinks,
            max_size=max_size,
            seen_dirs=seen_dirs,
            deduplicated=deduplicated,
            ancestors=(),
            depth=0,
        )

    ordered_candidates = tuple(sorted(candidates, key=lambda item: sort_key(item.path)))
    ordered_skips = tuple(
        sorted(skips, key=lambda item: (sort_key(item.path), item.code))
    )
    return WalkResult(
        candidates=ordered_candidates,
        skips=ordered_skips,
        visited=len(ordered_candidates) + len(ordered_skips),
        directories=len(seen_dirs),
        deduplicated=deduplicated[0],
    )


def _walk_root(
    root: str,
    candidates: list[Candidate],
    skips: list[Skip],
    *,
    follow_symlinks: bool,
    max_size: int,
    seen_dirs: set[str],
    deduplicated: list[int],
    ancestors: tuple[str, ...],
    depth: int,
) -> None:
    """Depth-first, sorted at every level. ``depth`` guards the recursion limit.

    Loop detection uses ``ancestors`` — the identity chain from the root down to
    here — rather than a global "seen" set. A global set cannot tell a cycle
    from a legitimate second route to the same directory (a junction and its
    target both reachable from the root); rejecting the second route would drop
    real files and report a phantom cycle. ``seen_dirs`` is still used, but only
    to *avoid scanning the same directory twice*, which is a dedupe decision,
    not a loop claim.
    """
    if depth > 200:  # a symlink loop that slipped past the ancestor check
        skips.append(Skip(path=normalize_path(root), code=SKIP_SYMLINK, detail="目录嵌套过深"))
        return

    path = Path(root)
    try:
        info = path.stat() if follow_symlinks else path.lstat()
    except PermissionError:
        skips.append(
            Skip(path=normalize_path(root), code=SKIP_PERMISSION_DENIED, detail="无法读取目录属性")
        )
        return
    except OSError as error:
        skips.append(
            Skip(path=normalize_path(root), code=SKIP_UNREADABLE, detail=_os_detail(error))
        )
        return

    if not follow_symlinks and _is_link_like(info):
        skips.append(Skip(path=normalize_path(root), code=SKIP_SYMLINK, detail="符号链接"))
        return

    if not stat.S_ISDIR(info.st_mode):
        _consider_file(root, candidates, skips, max_size=max_size, known_stat=info)
        return

    identity = _identity(path)
    if identity in ancestors:
        skips.append(
            Skip(path=normalize_path(root), code=SKIP_SYMLINK, detail="目录已访问（疑似环）")
        )
        return
    if identity in seen_dirs:
        # Already scanned via another route. Not an error and not a cycle; the
        # files were collected once already, so rescanning would double-count
        # every one of them. Counted, never silently dropped.
        deduplicated[0] += 1
        return
    seen_dirs.add(identity)
    chain = ancestors + (identity,)

    try:
        entries = sorted(os.scandir(path), key=lambda entry: sort_key(entry.name))
    except PermissionError:
        skips.append(
            Skip(path=normalize_path(root), code=SKIP_PERMISSION_DENIED, detail="目录不可读")
        )
        return
    except OSError as error:
        skips.append(
            Skip(path=normalize_path(root), code=SKIP_UNREADABLE, detail=_os_detail(error))
        )
        return

    for entry in entries:
        child = str(Path(root) / entry.name)
        try:
            entry_is_link = entry.is_symlink() or _is_link_like(entry.stat(follow_symlinks=False))
        except OSError:
            entry_is_link = False
        if entry_is_link and not follow_symlinks:
            skips.append(Skip(path=normalize_path(child), code=SKIP_SYMLINK, detail="符号链接"))
            continue
        try:
            is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
        except OSError:
            is_dir = False
        if is_dir:
            _walk_root(
                child,
                candidates,
                skips,
                follow_symlinks=follow_symlinks,
                max_size=max_size,
                seen_dirs=seen_dirs,
                deduplicated=deduplicated,
                ancestors=chain,
                depth=depth + 1,
            )
        else:
            try:
                stat_result = entry.stat(follow_symlinks=follow_symlinks)
            except PermissionError:
                skips.append(
                    Skip(path=normalize_path(child), code=SKIP_PERMISSION_DENIED, detail="无读取权限")
                )
                continue
            except OSError as error:
                skips.append(
                    Skip(path=normalize_path(child), code=SKIP_UNREADABLE, detail=_os_detail(error))
                )
                continue
            _consider_file(child, candidates, skips, max_size=max_size, known_stat=stat_result)


def _consider_file(
    path: str,
    candidates: list[Candidate],
    skips: list[Skip],
    *,
    max_size: int,
    known_stat: os.stat_result | None = None,
) -> None:
    info = known_stat
    if info is None:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            skips.append(Skip(path=normalize_path(path), code=SKIP_UNREADABLE, detail="文件不存在"))
            return
        except PermissionError:
            skips.append(
                Skip(path=normalize_path(path), code=SKIP_PERMISSION_DENIED, detail="无读取权限")
            )
            return
        except OSError as error:
            skips.append(
                Skip(path=normalize_path(path), code=SKIP_UNREADABLE, detail=_os_detail(error))
            )
            return

    if _is_link_like(info):
        skips.append(Skip(path=normalize_path(path), code=SKIP_SYMLINK, detail="符号链接"))
        return
    if not stat.S_ISREG(info.st_mode):
        skips.append(
            Skip(path=normalize_path(path), code=SKIP_UNREADABLE, detail="不是普通文件")
        )
        return
    if info.st_size > max_size:
        skips.append(
            Skip(
                path=normalize_path(path),
                code=SKIP_TOO_LARGE,
                detail=f"{info.st_size} 字节，上限 {max_size}",
            )
        )
        return

    candidates.append(Candidate(path=normalize_path(path), size=info.st_size))


def _is_link_like(info: os.stat_result) -> bool:
    """True for a symlink **or** a Windows reparse point (junction/mount point).

    Python reports a directory junction as a plain directory: ``is_symlink()``
    is False and ``lstat`` gives ``S_IFDIR``. Following one by default would
    leave the tree the user named, exactly like a symlink. The reparse tag is
    the only signal available, so it is read from ``st_reparse_tag`` when the
    platform provides it.
    """
    if stat.S_ISLNK(info.st_mode):
        return True
    tag = getattr(info, "st_reparse_tag", None)
    if tag is not None:
        # IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003 (junction / volume mount)
        # IO_REPARSE_TAG_SYMLINK     = 0xA000000C (handled above as well)
        return tag in (0xA0000003, 0xA000000C)
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _identity(path: Path) -> str:
    """Identity used for loop detection: inode when available, else the real path."""
    try:
        info = path.stat()
    except OSError:
        return normalize_path(str(path))
    if info.st_ino:
        return f"{info.st_dev}:{info.st_ino}"
    try:
        return normalize_path(str(path.resolve()))
    except OSError:
        return normalize_path(str(path))


def _os_detail(error: OSError) -> str:
    """Error text without the path, which is already a separate field."""
    return error.strerror or type(error).__name__


__all__ = [
    "Candidate",
    "SKIP_BINARY",
    "SKIP_CODES",
    "SKIP_PERMISSION_DENIED",
    "SKIP_SYMLINK",
    "SKIP_TOO_LARGE",
    "SKIP_UNKNOWN_FORMAT",
    "SKIP_UNREADABLE",
    "Skip",
    "WalkResult",
    "normalize_path",
    "sort_key",
    "walk",
]
