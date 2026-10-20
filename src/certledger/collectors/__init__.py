"""Collector: walk the filesystem and the system stores into one candidate stream.

The output is a **stream of candidates**, not a ledger. A candidate says "this
file, at this PEM block offset, looks like a certificate" — it does not merge,
pair or judge. That belongs to ``inventory`` and ``hygiene``, and keeping the
layers apart is what lets a candidate stream be replayed against a different
rule set later.

Three counters, never two (plan/03 §⑥):

* ``summary.visited``  — files the walk saw;
* ``summary.scanned``  — files it opened and classified;
* ``summary.skipped``  — files it declined, each with a ``SKIP_*`` record.

``visited == scanned + skipped`` is asserted by the tests. Without it a run can
quietly shrink — one unreadable directory and the ledger looks complete while
being partial, which is the failure mode that makes an inventory worse than no
inventory.

Thresholds come from the policy file only; there are no default literals here
(K3). ``policy=None`` is an input error, not "use the built-in values".
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from certledger.collectors.backends import StoreResult, read_store
from certledger.collectors.walker import (
    SKIP_BINARY,
    SKIP_PERMISSION_DENIED,
    SKIP_UNKNOWN_FORMAT,
    SKIP_UNREADABLE,
    WalkResult,
    normalize_path,
    walk,
)
from certledger.errors import CliError
from certledger.model import SCHEMA_VERSION, Diagnostic
from certledger.parsing.fingerprint import der_sha256
from certledger.parsing.sniff import (
    NEEDS_FULL,
    UNKNOWN,
    UNRECOGNISED,
    Item,
    SniffResult,
    classify_prefix,
    looks_binary,
    sniff_bytes,
)

PARSE_FAILED = "PARSE_FAILED"
PARSE_UNSUPPORTED = "PARSE_UNSUPPORTED"
PARSE_OK = "ok"

#: Formats this milestone names but does not read. They are reported, never
#: silently dropped: a PKCS#7 bundle in the tree is a fact about the tree.
UNREAD_FORMATS = frozenset({"pkcs7", "pem-pkcs7", "pkcs12", "jks", "jceks"})


def collect(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    source: str,
    follow_symlinks: bool | None,
    max_size: int | None,
    policy,
) -> dict:
    """Walk ``roots``/``files`` plus the system store; return the candidate stream."""
    if policy is None:
        raise CliError("策略缺失", "collect 需要已加载的策略文件（阈值不设代码默认值）")

    max_bytes = max_size if max_size is not None else policy.require("collect.max_file_bytes")
    sniff_window = policy.require("collect.sniff_bytes")
    follow = (
        follow_symlinks
        if follow_symlinks is not None
        else bool(policy.require("collect.follow_symlinks_default"))
    )

    walked = walk(
        list(roots),
        list(files),
        follow_symlinks=follow,
        max_size=max_bytes,
    )

    candidates: list[dict] = []
    diagnostics: list[Diagnostic] = []
    scanned = 0
    read_failures = 0

    for candidate in walked.candidates:
        records, failures, opened = _scan_file(
            candidate.path, sniff_window=sniff_window
        )
        if opened:
            scanned += 1
        else:
            # The walk could stat it but the read failed. That is a skip, not a
            # scan: counting it as scanned would make the file look examined.
            read_failures += 1
        candidates.extend(records)
        diagnostics.extend(failures)

    for skip in walked.skips:
        diagnostics.append(Diagnostic(code=skip.code, path=skip.path, detail=skip.detail))

    store = read_store(source)
    store_candidates, store_diagnostics = _scan_store(store)
    candidates.extend(store_candidates)
    diagnostics.extend(store_diagnostics)

    ordered = sorted(candidates, key=_candidate_sort_key)
    ordered_diagnostics = sorted(
        diagnostics, key=lambda item: (item.code, item.path, item.stage, item.detail)
    )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": "collect",
        "candidates": ordered,
        "diagnostics": [item.to_dict() for item in ordered_diagnostics],
        "backends": _backend_report(store),
        "summary": _summary(
            walked,
            store,
            scanned=scanned,
            read_failures=read_failures,
            candidates=ordered,
            diagnostics=ordered_diagnostics,
        ),
    }
    return payload


# ── one file ────────────────────────────────────────────────────────────────


def _scan_file(path: str, *, sniff_window: int) -> tuple[list[dict], list[Diagnostic], bool]:
    """Classify one file. Returns ``(candidates, diagnostics, opened)``.

    ``opened`` is False when the file could not be read at all — that is a skip,
    not a scan, and the distinction is what keeps the summary honest.

    Reading is staged (plan/03 §① 嗅探策略): the prefix window is read first and
    used to *classify*. Only a file whose prefix says "this is a certificate or
    key structure" is read to the end. A tree full of logs and binaries
    therefore costs 4096 bytes each, not a full read — which is what makes a
    10k-file directory tolerable (plan/06 R10).
    """
    target = Path(path)
    # Only ``NEEDS_FULL`` reads past the window; containers and unrecognised
    # files stop at the prefix (plan/03 §① 嗅探策略, plan/06 R10).
    tail = b""
    try:
        with target.open("rb") as handle:
            window = handle.read(sniff_window)
            verdict = classify_prefix(window)
            if verdict == NEEDS_FULL:
                tail = handle.read()
    except PermissionError:
        return [], [Diagnostic(code=SKIP_PERMISSION_DENIED, path=path, detail="无读取权限")], False
    except OSError as error:
        return (
            [],
            [Diagnostic(code=SKIP_UNREADABLE, path=path, detail=error.strerror or type(error).__name__)],
            False,
        )

    if verdict == UNRECOGNISED:
        binary = looks_binary(window)
        code = SKIP_BINARY if binary else SKIP_UNKNOWN_FORMAT
        return [], [Diagnostic(code=code, path=path, detail="内容不是已知的证书/密钥格式")], True

    data = window + tail
    file_hash = der_sha256(data)
    result = sniff_bytes(data[:sniff_window], full=data)

    if result.unknown:
        code = SKIP_BINARY if result.binary else SKIP_UNKNOWN_FORMAT
        return [], [Diagnostic(code=code, path=path, detail="内容不是已知的证书/密钥格式")], True

    records: list[dict] = []
    diagnostics: list[Diagnostic] = []

    for item in result.items:
        records.append(
            _candidate_record(
                path=path,
                item=item,
                file_hash=file_hash,
                source_kind="file",
            )
        )

    for failure in result.failures:
        diagnostics.append(
            Diagnostic(
                code=PARSE_FAILED,
                path=path,
                stage=failure.stage,
                detail=f"块 {failure.offset}: {failure.detail}",
            )
        )

    if not records and not diagnostics:
        diagnostics.append(
            Diagnostic(code=SKIP_UNKNOWN_FORMAT, path=path, detail="未识别出任何可用块")
        )

    return records, diagnostics, True


def _candidate_record(
    *,
    path: str,
    item: Item,
    file_hash: str,
    source_kind: str,
    store_name: str | None = None,
    container_alias: str | None = None,
) -> dict:
    """One candidate. Key order is declared here and never sorted later."""
    status = _parse_status(item)
    return {
        "path": path,
        "offset": item.offset,
        "detected_format": item.detected_format,
        "container_alias": container_alias,
        "file_sha256": file_hash,
        "parse_status": status,
        "source_kind": source_kind,
        "store_name": store_name,
        "encrypted": item.key_encrypted,
        "der_sha256": der_sha256(item.der) if item.der else None,
    }


def _parse_status(item: Item) -> str:
    if item.detected_format == UNKNOWN:
        return PARSE_UNSUPPORTED
    if item.detected_format in UNREAD_FORMATS:
        return PARSE_UNSUPPORTED
    if item.key_locked:
        # Encrypted key with no password: the file is understood, its content is
        # not. Not a failure — a documented state (plan/03 §② 失败路径).
        return PARSE_OK
    return PARSE_OK


def _candidate_sort_key(record: dict) -> tuple:
    return (
        normalize_path(record["path"]).casefold(),
        normalize_path(record["path"]),
        record["offset"],
        record["source_kind"],
    )


# ── system store ────────────────────────────────────────────────────────────


def _scan_store(store: StoreResult) -> tuple[list[dict], list[Diagnostic]]:
    records: list[dict] = []
    diagnostics: list[Diagnostic] = []

    for item in store.items:
        result = sniff_bytes(item.der[:4096], full=item.der)
        for sniffed in result.items:
            if sniffed.cert is None:
                continue
            records.append(
                _candidate_record(
                    path=f"store:{item.store_name}",
                    item=sniffed,
                    file_hash=der_sha256(item.der),
                    source_kind="store",
                    store_name=item.store_name,
                    container_alias=item.alias,
                )
            )
        for failure in result.failures:
            diagnostics.append(
                Diagnostic(
                    code=PARSE_FAILED,
                    path=f"store:{item.store_name}",
                    stage=failure.stage,
                    detail=f"{item.alias or '?'}: {failure.detail}",
                )
            )

    for missing in store.unavailable:
        diagnostics.append(
            Diagnostic(
                code="SOURCE_UNAVAILABLE",
                path=f"store:{missing.backend}",
                stage="backend",
                detail=missing.reason,
            )
        )

    return records, diagnostics


def _backend_report(store: StoreResult) -> list[dict]:
    """One row per backend, with per-store counts kept visible.

    ``unverified_backend`` rides along on every row so a reader cannot mistake
    an unverified backend's silence for a verified empty result (D4).
    """
    rows: list[dict] = []
    for name, count in store.store_counts:
        rows.append(
            {
                "backend": store.backend,
                "store": name,
                "count": count,
                "unverified_backend": any(u.unverified_backend for u in store.unavailable),
                "unavailable_reason": None,
            }
        )
    for missing in store.unavailable:
        rows.append(
            {
                "backend": missing.backend,
                "store": None,
                "count": 0,
                "unverified_backend": missing.unverified_backend,
                "unavailable_reason": missing.reason,
            }
        )
    if not rows:
        rows.append(
            {
                "backend": store.backend,
                "store": None,
                "count": 0,
                "unverified_backend": False,
                "unavailable_reason": None,
            }
        )
    return rows


def _summary(
    walked: WalkResult,
    store: StoreResult,
    *,
    scanned: int,
    read_failures: int,
    candidates: list[dict],
    diagnostics: list[Diagnostic],
) -> dict:
    """Counters that make "not looked at" distinguishable from "not there".

    The counters are separate units, and each answers a different question:

    * ``visited``  — files the walk saw at all;
    * ``scanned``  — files that were opened and read;
    * ``skipped``  — files that were **never opened** (declined by the walk, or
      the read itself failed).

    ``visited == scanned + skipped`` holds by construction. That is the point: a
    run cannot quietly shrink, because a file that vanished from the ledger has
    to appear in one of the two buckets.

    ``skip_records`` counts ``SKIP_*`` **diagnostics**, a different unit: a file
    that was read and found to be unknown text is *scanned* and also carries a
    ``SKIP_UNKNOWN_FORMAT`` record. Folding that into ``skipped`` would break
    the identity above, and would make "we read it, it was not a certificate"
    indistinguishable from "we never read it".
    """
    file_candidates = [item for item in candidates if item["source_kind"] == "file"]
    store_candidates = [item for item in candidates if item["source_kind"] == "store"]
    skip_records = sum(1 for item in diagnostics if item.code.startswith("SKIP_"))
    return {
        "visited": walked.visited,
        "scanned": scanned,
        "skipped": len(walked.skips) + read_failures,
        "skip_records": skip_records,
        "directories": walked.directories,
        "deduplicated": walked.deduplicated,
        "candidates": len(candidates),
        "file_candidates": len(file_candidates),
        "store_candidates": len(store_candidates),
        "unavailable": len(store.unavailable),
        "stores": [{"name": name, "count": count} for name, count in store.store_counts],
    }


__all__ = [
    "PARSE_FAILED",
    "PARSE_OK",
    "PARSE_UNSUPPORTED",
    "UNREAD_FORMATS",
    "collect",
]
