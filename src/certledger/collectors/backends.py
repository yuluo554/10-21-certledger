"""System certificate store backends (``--source``).

Three platforms, three different levels of certainty — and the difference is
recorded, never smoothed over:

* **linux** — read ``/etc/ssl/certs/ca-certificates.crt``, a PEM bundle. A
  normal file read; no subprocess.
* **windows** — ``certutil``, because ``openssl storeutl 'org.openssl.winstore:'``
  returns an empty list on this machine (D5) and an empty ledger is
  indistinguishable from "this machine has no certificates".
* **macos** — always ``SOURCE_UNAVAILABLE`` with ``unverified_backend: true``.
  ``security find-certificate`` has never been run here, and a backend that has
  never been executed must not be advertised as working (D4).

A missing backend is a **record**, never a failure: ``SOURCE_UNAVAILABLE`` is
INFO and the exit code does not move (D11/K6). The one thing that must not
happen is reporting an empty store when the truth is "we could not look".

### The Windows store subtlety (measured, not assumed)

``certutil -store Root`` lists 18 certificates on this machine while
``Cert:\\LocalMachine\\Root`` (and .NET's ``X509Store``) list 76. The gap is not
a bug in either: ``certutil`` reads the *physical* ``Root`` hive, while the
CryptoAPI provider merges the ``AuthRoot`` auto-update hive into the Root view.
Counting only ``Root`` would under-report by 58 roots — a silently incomplete
ledger.

So the backend reads ``Root``, ``AuthRoot`` and ``CA`` and reports each store's
own count, leaving the merge decision to the caller instead of inventing a
"total". ``AuthRoot`` is named as its own store in the report rather than being
folded into ``Root``, because folding is what makes a number unexplainable
later.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"

#: Linux CA bundle locations, in probe order. The first that exists wins.
LINUX_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/etc/ssl/cert.pem",  # Alpine/BSD
)

#: Windows stores to read. ``Root`` and ``CA`` are the two the plan names;
#: ``AuthRoot`` is added because the Root *view* includes it (see module note).
WINDOWS_STORES = ("Root", "AuthRoot", "CA")

#: A backend may be a subprocess; bound it so one wedged call cannot hang a scan.
BACKEND_TIMEOUT_SECONDS = 20


@dataclass(frozen=True, slots=True)
class StoreItem:
    """One certificate read from a system store."""

    store_name: str
    der: bytes
    #: Stable identifier inside the store (Windows thumbprint, or a counter for
    #: the Linux bundle where entries have no alias).
    alias: str | None = None


@dataclass(frozen=True, slots=True)
class StoreUnavailable:
    """A backend that could not be read, with a machine-readable reason."""

    backend: str
    reason: str
    #: True when the backend has never been verified on real hardware.
    unverified_backend: bool = False


@dataclass(frozen=True, slots=True)
class StoreResult:
    backend: str
    items: tuple[StoreItem, ...] = ()
    unavailable: tuple[StoreUnavailable, ...] = ()
    #: Per-store counts, in the order the stores were read. Kept separate from
    #: ``items`` so "store X held N" stays explainable.
    store_counts: tuple[tuple[str, int], ...] = ()

    @property
    def empty(self) -> bool:
        return not self.items and not self.unavailable


def resolve_source(source: str) -> str:
    """Turn ``auto`` into a concrete backend name.

    ``auto`` never falls back across platforms: guessing that "we are on Linux
    so read the bundle" when the bundle is missing would produce exactly the
    empty-looking result the plan forbids. It picks the platform's own backend
    and lets that backend report itself unavailable.
    """
    if source != "auto":
        return source
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def read_store(source: str, *, runner=None, linux_bundles=None) -> StoreResult:
    """Read the named backend. ``none`` reads nothing and reports nothing."""
    backend = resolve_source(source)
    if backend == "none":
        return StoreResult(backend="none")
    if backend == "linux":
        return _read_linux(linux_bundles)
    if backend == "windows":
        return _read_windows(runner=runner)
    if backend == "macos":
        return StoreResult(
            backend="macos",
            unavailable=(
                StoreUnavailable(
                    backend="macos",
                    reason="macOS 后端未在真机验证，不对外承诺",
                    unverified_backend=True,
                ),
            ),
        )
    return StoreResult(
        backend=backend,
        unavailable=(StoreUnavailable(backend=backend, reason="未知后端"),),
    )


# ── linux ───────────────────────────────────────────────────────────────────


def _read_linux(bundles: tuple[str, ...] | None = None) -> StoreResult:
    """Read the first CA bundle that exists.

    ``bundles`` is injectable so the *file-reading and PEM-splitting* code path
    can be exercised on a machine that has no Linux CA bundle (this
    development machine is Windows). Injecting a path tests the code that runs;
    it does not pretend the real location was verified, and the caller's
    summary still distinguishes the two.
    """
    for candidate in bundles or LINUX_BUNDLES:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except PermissionError:
            return StoreResult(
                backend="linux",
                unavailable=(
                    StoreUnavailable(backend="linux", reason=f"{candidate}: 无读取权限"),
                ),
            )
        except OSError as error:
            return StoreResult(
                backend="linux",
                unavailable=(
                    StoreUnavailable(backend="linux", reason=f"{candidate}: {error.strerror}"),
                ),
            )
        from certledger.parsing.pem import split_pem_blocks

        blocks, _errors = split_pem_blocks(raw)
        items = tuple(
            StoreItem(store_name="system", der=block.der, alias=f"#{block.offset}")
            for block in blocks
            if block.kind == "cert"
        )
        return StoreResult(
            backend="linux", items=items, store_counts=(("system", len(items)),)
        )

    tried = bundles or LINUX_BUNDLES
    return StoreResult(
        backend="linux",
        unavailable=(
            StoreUnavailable(
                backend="linux",
                reason="未找到 CA bundle（已试 " + "、".join(tried) + "）",
            ),
        ),
    )


# ── windows ─────────────────────────────────────────────────────────────────


def _read_windows(*, runner=None) -> StoreResult:
    """Read Windows stores via ``certutil -split -store``.

    ``-split`` writes one DER file per certificate into the working directory,
    which gives **raw DER** (needed for K1) without parsing localized console
    text. The alternative — scraping ``certutil -store`` output — is both
    locale-dependent and, as measured, incomplete for the Root view.
    """
    import tempfile

    run = runner or _run_certutil
    items: list[StoreItem] = []
    counts: list[tuple[str, int]] = []
    unavailable: list[StoreUnavailable] = []

    for store in WINDOWS_STORES:
        with tempfile.TemporaryDirectory(prefix="certledger-store-") as scratch:
            try:
                code, stderr = run(store, scratch)
            except FileNotFoundError:
                return StoreResult(
                    backend="windows",
                    unavailable=(
                        StoreUnavailable(backend="windows", reason="找不到 certutil"),
                    ),
                )
            except subprocess.TimeoutExpired:
                unavailable.append(
                    StoreUnavailable(
                        backend="windows", reason=f"{store}: certutil 超时（{BACKEND_TIMEOUT_SECONDS}s）"
                    )
                )
                continue

            if code != 0:
                # A missing store is not a failure of the backend: an empty `My`
                # store is normal on a fresh machine. Distinguish the two.
                reason = _first_line(stderr) or f"certutil 退出码 {code}"
                unavailable.append(StoreUnavailable(backend="windows", reason=f"{store}: {reason}"))
                continue

            found = 0
            for entry in sorted(Path(scratch).glob("*.crt"), key=lambda p: p.name):
                try:
                    der = entry.read_bytes()
                except OSError:
                    continue
                items.append(StoreItem(store_name=store, der=der, alias=entry.stem))
                found += 1
            counts.append((store, found))

    if not items and unavailable:
        return StoreResult(backend="windows", unavailable=tuple(unavailable), store_counts=tuple(counts))
    return StoreResult(
        backend="windows",
        items=tuple(items),
        unavailable=tuple(unavailable),
        store_counts=tuple(counts),
    )


def _run_certutil(store: str, cwd: str) -> tuple[int, str]:
    result = subprocess.run(
        ["certutil", "-split", "-store", store],
        cwd=cwd,
        capture_output=True,
        timeout=BACKEND_TIMEOUT_SECONDS,
        check=False,
    )
    return result.returncode, _decode_console(result.stderr)


def _decode_console(raw: bytes) -> str:
    """Decode Windows console output.

    ``certutil`` writes in the OEM code page (``mbcs`` on this machine), not
    UTF-8; decoding as UTF-8 raises and would turn a readable error into a
    traceback. The fallback chain keeps the message, which is the point.
    """
    for encoding in ("utf-8", "mbcs" if os.name == "nt" else "utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace")


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return ""


__all__ = [
    "BACKEND_TIMEOUT_SECONDS",
    "LINUX_BUNDLES",
    "SOURCE_UNAVAILABLE",
    "StoreItem",
    "StoreResult",
    "StoreUnavailable",
    "WINDOWS_STORES",
    "read_store",
    "resolve_source",
]
