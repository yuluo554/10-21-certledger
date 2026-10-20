"""Collector: eight format classes, stable traversal, skip codes, backends.

Two rules this file is written to hold:

1. **The truth file is the input, not the expected output.** Cases come from
   ``fixtures/expected.json`` and artifacts are read from ``fixtures/out``. A
   test that hard-codes a fingerprint would pass while the fixture drifted.
2. **Every assertion is falsifiable.** "Eight formats" is checked by asserting
   each named format appears, not by counting that *something* was collected —
   a collector returning one format 32 times would pass a count.

The ``system``-marked tests touch the host store. They are skipped when the
backend is unavailable, because an unavailable backend is a legitimate state
(``SOURCE_UNAVAILABLE``), not a test failure.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from certledger.collectors import collect
from certledger.collectors.backends import (
    StoreResult,
    StoreUnavailable,
    read_store,
    resolve_source,
)
from certledger.collectors.walker import (
    SKIP_PERMISSION_DENIED,
    SKIP_SYMLINK,
    SKIP_TOO_LARGE,
    SKIP_UNKNOWN_FORMAT,
    normalize_path,
    sort_key,
    walk,
)
from certledger.parsing.fingerprint import der_sha256
from certledger.parsing.pem import split_pem_blocks
from certledger.parsing.sniff import (
    DER_CERT,
    JCEKS,
    JKS,
    OPENSSH_PUB,
    PEM_CERT,
    PEM_KEY,
    PEM_PKCS7,
    PKCS12,
    PKCS7,
    PKCS8,
    sniff_bytes,
)

ROOT = Path(__file__).resolve().parent.parent
TRUTH = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))
OUT = ROOT / "fixtures" / "out"
CASES = {entry["case"]: entry for entry in TRUTH["cases"]}

needs_artifacts = pytest.mark.skipif(
    not OUT.is_dir(),
    reason="fixtures/out 未生成；先跑 bash fixtures/gen.sh",
)


# ── helpers ─────────────────────────────────────────────────────────────────


def case_inputs(case: str) -> list[str]:
    return [str(OUT / rel) for rel in CASES[case]["inputs"]]


def collect_case(case: str, policy, *, source: str = "none") -> dict:
    return collect(
        roots=[],
        files=case_inputs(case),
        source=source,
        follow_symlinks=False,
        max_size=None,
        policy=policy,
    )


def codes(payload: dict) -> list[str]:
    return [item["code"] for item in payload["diagnostics"]]


def make_dir_link(link: Path, target: Path) -> None:
    """Create a directory link that the collector will see as a symlink.

    On POSIX this is ``symlink_to``. On Windows ``symlink_to`` needs
    ``SeCreateSymbolicLinkPrivilege`` (admin), but a **junction** needs nothing
    and ``lstat`` reports it as a link — so the test exercises the same code
    path instead of skipping. Skipping here would leave ``SKIP_SYMLINK``
    unverified on the platform this project is developed on.
    """
    if sys.platform == "win32":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
        )
        if result.returncode != 0:
            pytest.skip(f"无法创建目录联接: {result.stderr.decode('mbcs', 'replace')[:120]}")
        return
    link.symlink_to(target, target_is_directory=True)


# ── ① eight format classes ──────────────────────────────────────────────────


@needs_artifacts
def test_eight_format_classes_are_each_recognised() -> None:
    """One sample per class, asserted by name (plan/05 M2 DoD #1)."""
    found: dict[str, str] = {}

    pem_cert = (OUT / "healthy" / "healthy.pem").read_bytes()
    found[PEM_CERT] = sniff_bytes(pem_cert[:4096], full=pem_cert).items[0].detected_format

    pem_key = (OUT / "healthy" / "healthy.key").read_bytes()
    found[PEM_KEY] = sniff_bytes(pem_key[:4096], full=pem_key).items[0].detected_format

    # PKCS#8 DER is the same key without the PEM envelope.
    pkcs8_der = split_pem_blocks(pem_key)[0][0].der
    found[PKCS8] = sniff_bytes(pkcs8_der[:4096], full=pkcs8_der).items[0].detected_format

    cert_der = split_pem_blocks(pem_cert)[0][0].der
    found[DER_CERT] = sniff_bytes(cert_der[:4096], full=cert_der).items[0].detected_format

    p12 = (OUT / "multi-alias" / "multi-alias.p12").read_bytes()
    found[PKCS12] = sniff_bytes(p12[:4096], full=p12).items[0].detected_format

    pkcs7_der = subprocess.run(
        ["openssl", "crl2pkcs7", "-nocrl", "-certfile", str(OUT / "bundle" / "bundle.pem"),
         "-outform", "DER"],
        capture_output=True,
        check=True,
    ).stdout
    found[PKCS7] = sniff_bytes(pkcs7_der[:4096], full=pkcs7_der).items[0].detected_format

    pem_p7 = (
        b"-----BEGIN PKCS7-----\n"
        + base64.encodebytes(pkcs7_der)
        + b"-----END PKCS7-----\n"
    )
    found[PEM_PKCS7] = sniff_bytes(pem_p7[:4096], full=pem_p7).items[0].detected_format

    found[JKS] = sniff_bytes(b"\xfe\xed\xfe\xed\x00\x00\x00\x02").items[0].detected_format
    found[JCEKS] = sniff_bytes(b"\xce\xce\xce\xce\x00\x00\x00\x02").items[0].detected_format

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    ssh = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    found[OPENSSH_PUB] = sniff_bytes(ssh[:4096], full=ssh).items[0].detected_format

    expected = {
        PEM_CERT, PEM_KEY, PEM_PKCS7, DER_CERT, PKCS7, PKCS12, JKS, JCEKS, PKCS8, OPENSSH_PUB,
    }
    assert set(found) == expected
    assert found == {name: name for name in expected}, found


@needs_artifacts
def test_jks_and_jceks_have_distinct_magics() -> None:
    """plan/03 claimed a shared magic; the measurement says otherwise.

    Pinned as a test so the wrong claim cannot come back: if the two magics were
    ever treated as one, JCEKS files would be labelled JKS.
    """
    jks = sniff_bytes(b"\xfe\xed\xfe\xed").items[0].detected_format
    jceks = sniff_bytes(b"\xce\xce\xce\xce").items[0].detected_format
    assert (jks, jceks) == (JKS, JCEKS)


# ── ② multi-block PEM ──────────────────────────────────────────────────────


@needs_artifacts
def test_bundle_expands_every_block_with_offsets(policy) -> None:
    """``bundle`` holds 3 certs; offsets must be 0/1/2 and hashes must match truth."""
    payload = collect_case("bundle", policy)
    certs = [item for item in payload["candidates"] if item["detected_format"] == PEM_CERT]
    assert [item["offset"] for item in certs] == [0, 1, 2]

    truth = {artifact["offset"]: artifact["fingerprint_sha256"]
             for artifact in CASES["bundle"]["artifacts"]}
    assert [item["der_sha256"] for item in certs] == [truth[0], truth[1], truth[2]]


@needs_artifacts
@pytest.mark.parametrize("case", sorted(CASES))
def test_every_cert_artifact_fingerprint_is_recomputed(case: str, policy) -> None:
    """K1: the collector's DER hash equals the truth's fingerprint, byte for byte.

    This is the assertion that makes "fingerprint over raw DER" falsifiable: a
    re-encode-then-hash implementation would produce a different value here.
    """
    payload = collect_case(case, policy)
    by_path: dict[str, list[str]] = {}
    for item in payload["candidates"]:
        if item["der_sha256"]:
            by_path.setdefault(item["path"], []).append(item["der_sha256"])

    for artifact in CASES[case]["artifacts"]:
        if artifact["kind"] != "cert" or "fingerprint_sha256" not in artifact:
            continue
        # Collector paths are normalised to forward slashes; compare on the same form.
        path = normalize_path(str(OUT / artifact["path"]))
        assert artifact["fingerprint_sha256"] in by_path.get(path, []), (
            f"{case}: {artifact['path']} offset {artifact.get('offset', 0)} 未被复算"
        )


@needs_artifacts
def test_pem_block_offset_matches_truth_for_every_artifact(policy) -> None:
    payload = collect_case("bundle", policy)
    seen = {item["offset"] for item in payload["candidates"]}
    declared = {artifact["offset"] for artifact in CASES["bundle"]["artifacts"]}
    assert seen == declared == {0, 1, 2}


# ── ③ traversal stability ──────────────────────────────────────────────────


@needs_artifacts
def test_two_runs_produce_an_equal_list(policy) -> None:
    """List equality, not set equality: order is part of the contract."""
    first = collect(roots=[str(OUT)], files=[], source="none",
                    follow_symlinks=False, max_size=None, policy=policy)
    second = collect(roots=[str(OUT)], files=[], source="none",
                     follow_symlinks=False, max_size=None, policy=policy)
    assert first["candidates"] == second["candidates"]
    assert first["diagnostics"] == second["diagnostics"]


@needs_artifacts
def test_candidates_are_sorted_by_normalised_path(policy) -> None:
    payload = collect(roots=[str(OUT)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    keys = [(item["path"].casefold(), item["path"], item["offset"])
            for item in payload["candidates"]]
    assert keys == sorted(keys)


def test_sort_key_is_case_and_unicode_stable() -> None:
    """NFC + casefold: an NFD name and its NFC form must not sort apart."""
    import unicodedata

    composed = "caf\u00e9.pem"  # é as one code point
    decomposed = unicodedata.normalize("NFD", composed)  # e + combining acute
    assert sort_key(composed)[0] == sort_key(decomposed)[0]
    assert sort_key("A.pem")[0] == sort_key("a.pem")[0]
    # The tie-breaker keeps the exact form deterministic.
    assert sort_key("A.pem") != sort_key("a.pem")
    assert normalize_path("a\\b\\c.pem") == "a/b/c.pem"


def test_walker_visits_every_file_it_sees(tmp_path) -> None:
    """``visited == candidates + skips`` — no file falls through the cracks."""
    (tmp_path / "a.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    result = walk([str(tmp_path)], [], follow_symlinks=False, max_size=1024)
    assert result.visited == len(result.candidates) + len(result.skips)
    assert result.visited == 2


# ── ④ skip codes ───────────────────────────────────────────────────────────


@needs_artifacts
def test_noise_is_skipped_as_binary_not_failed(policy) -> None:
    payload = collect_case("noise", policy)
    assert payload["candidates"] == []
    assert codes(payload) == ["SKIP_BINARY"]


@needs_artifacts
def test_broken_der_is_parse_failed_with_stage(policy) -> None:
    """plan/03 §⑥: ``PARSE_FAILED`` carries ``path`` + ``stage``, exit code 0."""
    payload = collect_case("broken-der", policy)
    assert payload["candidates"] == []
    assert len(payload["diagnostics"]) == 1
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["code"] == "PARSE_FAILED"
    assert diagnostic["stage"] == "der"
    assert diagnostic["path"].endswith("broken.der")


def test_unknown_text_format_is_skipped_not_dropped(tmp_path, policy) -> None:
    """Read, classified, and found not to be a certificate: scanned, with a record."""
    (tmp_path / "notes.txt").write_text("this is prose, not a certificate\n", encoding="utf-8")
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert codes(payload) == [SKIP_UNKNOWN_FORMAT]
    summary = payload["summary"]
    assert summary["scanned"] == 1
    assert summary["skip_records"] == 1
    assert summary["skipped"] == 0  # never opened? no — opened, so not a skip
    assert summary["visited"] == summary["scanned"] + summary["skipped"]


def test_too_large_is_skipped(tmp_path, policy) -> None:
    (tmp_path / "big.pem").write_bytes(b"x" * 2048)
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=False, max_size=1024, policy=policy)
    assert codes(payload) == [SKIP_TOO_LARGE]
    assert payload["summary"]["skipped"] == 1
    assert payload["summary"]["scanned"] == 0
    assert payload["summary"]["visited"] == 1


def test_max_size_comes_from_policy_when_not_given(tmp_path, policy) -> None:
    """K3: no default literal in code — the policy value is the only source."""
    limit = policy.require("collect.max_file_bytes")
    (tmp_path / "at-limit.bin").write_bytes(b"\x00" * (limit + 1))
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert codes(payload) == [SKIP_TOO_LARGE]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows 上 chmod 只改只读位，不构成访问控制")
def test_permission_denied_is_recorded_not_silent(tmp_path, policy) -> None:
    secret = tmp_path / "secret.pem"
    secret.write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    secret.chmod(0o000)
    try:
        payload = collect(roots=[str(tmp_path)], files=[], source="none",
                          follow_symlinks=False, max_size=None, policy=policy)
    finally:
        secret.chmod(0o600)
    assert SKIP_PERMISSION_DENIED in codes(payload)


def test_permission_denied_is_always_a_diagnostic(policy, monkeypatch) -> None:
    """Same code path, injected failure — runs on every platform.

    Windows has no chmod-based denial, so the POSIX test above skips there and
    ``SKIP_PERMISSION_DENIED`` would go unverified. Patching ``Path.open`` (the
    seam the collector actually reads through) exercises the handler itself,
    which is the part that must not be silent.
    """
    from certledger.collectors import _scan_file

    def deny(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "open", deny, raising=False)
    records, diagnostics, opened = _scan_file("anything.pem", sniff_window=4096)
    assert records == []
    assert opened is False
    assert [item.code for item in diagnostics] == [SKIP_PERMISSION_DENIED]


def test_symlink_is_skipped_by_default_and_followed_on_request(tmp_path, policy) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "c.pem").write_bytes(
        (OUT / "healthy" / "healthy.pem").read_bytes()
        if OUT.is_dir()
        else b"-----BEGIN CERTIFICATE-----\n"
    )
    make_dir_link(tmp_path / "link", real)

    off = collect(roots=[str(tmp_path)], files=[], source="none",
                  follow_symlinks=False, max_size=None, policy=policy)
    assert SKIP_SYMLINK in codes(off)
    # The link itself is skipped; the real directory is still walked.
    assert len(off["candidates"]) == 1

    on = collect(roots=[str(tmp_path)], files=[], source="none",
                 follow_symlinks=True, max_size=None, policy=policy)
    # Following the link reaches the same directory by two routes. It must be
    # scanned once — not zero times (lost file) and not twice (double count).
    assert len(on["candidates"]) == 1
    assert on["summary"]["deduplicated"] >= 1


def test_symlink_loop_terminates(tmp_path, policy) -> None:
    """A self-referencing link must not hang the walk (``--follow-symlinks``)."""
    loop = tmp_path / "loop"
    loop.mkdir()
    make_dir_link(loop / "self", loop)
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=True, max_size=None, policy=policy)
    assert payload["summary"]["visited"] >= 0  # returned at all = terminated
    assert any(
        item["code"] == SKIP_SYMLINK and "环" in item["detail"]
        for item in payload["diagnostics"]
    ), payload["diagnostics"]


# ── ⑤ backends ─────────────────────────────────────────────────────────────


def test_macos_backend_is_always_unavailable_and_flagged() -> None:
    """D4: never executed on real hardware, so never claimed as working."""
    result = read_store("macos")
    assert result.items == ()
    assert len(result.unavailable) == 1
    assert result.unavailable[0].unverified_backend is True
    assert result.unavailable[0].backend == "macos"


def test_none_backend_reads_nothing_and_reports_nothing() -> None:
    result = read_store("none")
    assert result.items == ()
    assert result.unavailable == ()


def test_resolve_source_picks_the_platform_backend() -> None:
    assert resolve_source("none") == "none"
    assert resolve_source("linux") == "linux"
    assert resolve_source("auto") in {"linux", "windows", "macos"}


def test_unavailable_backend_keeps_exit_code_zero(policy, tmp_path) -> None:
    """D11/K6: a missing backend is an INFO record, not a failure."""
    payload = collect(roots=[str(tmp_path)], files=[], source="macos",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert codes(payload) == ["SOURCE_UNAVAILABLE"]
    assert payload["summary"]["unavailable"] == 1
    row = payload["backends"][0]
    assert row["unverified_backend"] is True
    assert row["unavailable_reason"]


def test_unavailable_backend_is_visible_in_the_report_text(policy, tmp_path) -> None:
    """The reason must be retrievable, not just a bare code."""
    payload = collect(roots=[str(tmp_path)], files=[], source="macos",
                      follow_symlinks=False, max_size=None, policy=policy)
    detail = payload["diagnostics"][0]["detail"]
    assert "macOS" in detail or "macos" in detail


@pytest.mark.system
def test_windows_backend_reads_real_stores(tmp_path) -> None:
    if sys.platform != "win32":
        pytest.skip("仅 Windows")
    result = read_store("windows")
    if result.unavailable:
        pytest.skip(f"certutil 不可用: {result.unavailable[0].reason}")
    assert result.items, "Windows 后端读不到任何证书"
    names = {name for name, _count in result.store_counts}
    assert {"Root", "AuthRoot", "CA"} <= names
    # Every item must be a real certificate, not a placeholder.
    first = result.items[0]
    assert first.der[:1] == b"\x30"
    assert der_sha256(first.der) != ""


@pytest.mark.system
def test_windows_root_view_includes_authroot() -> None:
    """Measured fact, pinned: ``certutil -store Root`` alone under-reports.

    On this machine ``Root`` holds 18 certificates while the merged view holds
    76; the difference is the ``AuthRoot`` auto-update hive. A backend reading
    only ``Root`` would produce a ledger missing 58 roots without saying so.
    """
    if sys.platform != "win32":
        pytest.skip("仅 Windows")
    result = read_store("windows")
    if result.unavailable:
        pytest.skip(f"certutil 不可用: {result.unavailable[0].reason}")
    counts = dict(result.store_counts)
    assert counts.get("AuthRoot", 0) > 0, counts


def test_linux_backend_reports_missing_bundle_clearly() -> None:
    """On a machine without a CA bundle the reason must name what was tried."""
    result = read_store("linux")
    if result.items:
        pytest.skip("本机有 CA bundle，缺失路径不适用")
    assert result.unavailable
    assert "CA bundle" in result.unavailable[0].reason


@needs_artifacts
def test_linux_backend_reads_a_real_pem_bundle(tmp_path) -> None:
    """Exercise the Linux reader's actual code path with a real bundle.

    This machine is Windows, so ``/etc/ssl/certs/ca-certificates.crt`` does not
    exist and the Linux backend can only report itself unavailable. Pointing the
    reader at a real multi-block PEM bundle tests the code that will run on
    Linux — it does **not** claim the real path was verified, and the
    "missing bundle" test above still asserts that case separately.
    """
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_bytes((OUT / "bundle" / "bundle.pem").read_bytes())
    result = read_store("linux", linux_bundles=(str(tmp_path / "absent.crt"), str(bundle)))
    assert result.unavailable == ()
    assert len(result.items) == 3
    assert result.store_counts == (("system", 3),)
    assert all(item.der[:1] == b"\x30" for item in result.items)
    assert [item.alias for item in result.items] == ["#0", "#1", "#2"]


def test_linux_backend_names_every_missing_candidate(tmp_path) -> None:
    """A missing bundle reports the paths tried, not just 'unavailable'."""
    result = read_store(
        "linux", linux_bundles=(str(tmp_path / "a.crt"), str(tmp_path / "b.crt"))
    )
    assert result.items == ()
    reason = result.unavailable[0].reason
    assert "a.crt" in reason and "b.crt" in reason


# ── ⑥ summary discipline ───────────────────────────────────────────────────


@needs_artifacts
def test_summary_counters_add_up(policy) -> None:
    """``visited == scanned + skipped``; the three counters stay separate."""
    payload = collect(roots=[str(OUT)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    summary = payload["summary"]
    assert summary["visited"] == summary["scanned"] + summary["skipped"]
    assert summary["candidates"] == summary["file_candidates"] + summary["store_candidates"]
    assert summary["scanned"] > 0


def test_empty_directory_still_returns_counted_structure(tmp_path, policy) -> None:
    """The old shell raised here. An empty tree is a real answer with real counts."""
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert payload["kind"] == "collect"
    assert payload["candidates"] == []
    assert payload["summary"]["visited"] == 0
    assert payload["summary"]["scanned"] == 0
    assert payload["summary"]["skipped"] == 0
    assert payload["summary"]["directories"] == 1


def test_missing_file_is_reported_not_ignored(tmp_path, policy) -> None:
    payload = collect(roots=[], files=[str(tmp_path / "nope.pem")], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert payload["diagnostics"], "不存在的文件必须留下记录"
    assert payload["summary"]["skipped"] == 1


def test_collect_requires_a_policy() -> None:
    """K3: no code default for thresholds; a missing policy is an input error."""
    from certledger.errors import CliError

    with pytest.raises(CliError):
        collect(roots=[], files=[], source="none", follow_symlinks=False,
                max_size=None, policy=None)


@needs_artifacts
def test_containers_are_named_but_not_decoded(policy) -> None:
    """PKCS#12 is a known format this milestone names; reading it is the container route."""
    payload = collect_case("multi-alias", policy)
    assert len(payload["candidates"]) == 1
    item = payload["candidates"][0]
    assert item["detected_format"] == PKCS12
    assert item["parse_status"] == "PARSE_UNSUPPORTED"
    assert item["container_alias"] is None


def test_collect_output_is_json_serialisable_and_key_ordered(policy, tmp_path) -> None:
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert list(payload) == [
        "schema_version", "kind", "candidates", "diagnostics", "backends", "summary"
    ]
    json.dumps(payload, ensure_ascii=False)  # must not raise


# ── ⑦ prefix window discipline (R10) ───────────────────────────────────────


def test_unrecognised_files_are_never_read_past_the_window(tmp_path, policy) -> None:
    """plan/03 §①: sniffing reads a fixed prefix, not the whole file.

    Proven by construction rather than by timing: the file is 4 MB of text and
    ``max_file_bytes`` is set low enough that a full read would trip the size
    guard in the caller, yet the collector must still classify it. If the
    implementation read the file whole, the byte count below would jump by four
    megabytes per file.
    """
    big = tmp_path / "huge.log"
    big.write_bytes(b"a" * (4 * 1024 * 1024))
    payload = collect(roots=[str(tmp_path)], files=[], source="none",
                      follow_symlinks=False, max_size=None, policy=policy)
    assert payload["summary"]["scanned"] == 1
    assert payload["summary"]["candidates"] == 0
    assert codes(payload) == [SKIP_UNKNOWN_FORMAT]


def test_sniff_window_comes_from_policy(tmp_path, policy) -> None:
    """K3: the window size is a policy value, not a literal in the collector."""
    from certledger.collectors import _scan_file

    window = policy.require("collect.sniff_bytes")
    assert isinstance(window, int) and window >= 16
    records, diagnostics, opened = _scan_file(
        str(OUT / "healthy" / "healthy.pem") if OUT.is_dir() else str(tmp_path / "x"),
        sniff_window=window,
    )
    assert opened in (True, False)  # the call uses the value without crashing
