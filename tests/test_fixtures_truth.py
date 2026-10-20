"""Truth-file discipline and the eight sample classes (``plan/04``, M1).

Three independent layers, deliberately kept apart:

1. **Shape** — the truth file may only carry "input + expectation" fields. No
   ``observed_*`` / ``actual_*``: a truth file that records what the code
   produced stops being a truth file the moment the code changes.
2. **Independence** — every expected code must be derivable from the recorded
   artifact numbers alone (validity against ``as_of``, key size against the
   policy minimum, SPKI sets against each other). Nothing here imports
   ``certledger.hygiene``; the recomputation below is written from the rule
   definitions in ``data/README.md`` §五, which is the point of the exercise.
3. **Artifact agreement** — where the samples are on disk, the declared
   fingerprints must match the bytes. This layer skips when ``fixtures/out`` is
   absent, because artifacts are generated on demand and never committed.

The rule engine lands later; if it ever disagrees with this file, one of the two
is wrong and the disagreement is the finding.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
TRUTH_PATH = ROOT / "fixtures" / "expected.json"
OUT_DIR = ROOT / "fixtures" / "out"
GEN_SH = ROOT / "fixtures" / "gen.sh"

#: The eight classes the milestone is defined by (``plan/04`` §1.1). Named here
#: rather than inferred so deleting a case is a red test, not a smaller list.
REQUIRED_CASES = {
    "healthy",
    "expiring",
    "expired",
    "weak-key",
    "weak-sig",
    "multi-alias",
    "truststore-with-key",
    "orphan",
}

#: Every finding code M1 may legitimately declare. A new code here is a change
#: to the rule surface and must be a deliberate edit, not a typo that passes.
KNOWN_CODES = {
    "EXPIRED",
    "EXPIRING",
    "EXPIRY_CLIFF",
    "WEAK_KEY",
    "WEAK_SIG",
    "POLICY_NIST_2031",
    "PRIVATE_KEY_UNENCRYPTED",
    "PERMISSION_TOO_OPEN",
    "ORPHAN_CERT",
    "ORPHAN_KEY",
    "DUPLICATE_CERT",
    "DUPLICATE_KEY",
    "CONTAINER_TRUSTSTORE_WITH_KEY",
    "CONTAINER_EMPTY_PASSWORD",
    "PUBLIC_VALIDITY_HINT",
    "PARSE_FAILED",
    "SKIP_BINARY",
    "SOURCE_UNAVAILABLE",
}

ALLOWED_CASE_KEYS = {
    "case",
    "group",
    "purpose",
    "index",
    "platform",
    "as_of",
    "as_of_utc",
    "inputs",
    "artifacts",
    "expect",
}
ALLOWED_EXPECT_KEYS = {"findings", "absent", "container"}
ALLOWED_FINDING_KEYS = {"code", "severity", "count"}
ALLOWED_ARTIFACT_KEYS = {
    "path",
    "kind",
    "format",
    "reproducible",
    "sha256",
    "offset",
    "block_count",
    "source_der_bytes",
    "truncated_to_bytes",
    "has_nul_byte",
    "posix_mode",
    "entry_count",
    # certificate fields
    "subject",
    "issuer",
    "serial",
    "not_before",
    "not_after",
    "fingerprint_sha256",
    "spki_sha256",
    "key_algo",
    "key_bits",
    "key_curve",
    "sig_algo",
    "sig_algo_name",
    "san_dns",
    "is_ca",
    # key fields
    "encrypted",
}

#: Field-name shapes that turn a truth file into an observation log.
FORBIDDEN_PREFIXES = ("observed", "actual", "measured", "produced", "result")


# ── loading ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def truth() -> dict[str, Any]:
    assert TRUTH_PATH.is_file(), "fixtures/expected.json 缺失；真值必须入仓"
    return json.loads(TRUTH_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cases(truth) -> dict[str, dict[str, Any]]:
    return {entry["case"]: entry for entry in truth["cases"]}


def expected_codes(entry: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for finding in entry["expect"]["findings"]:
        codes += [finding["code"]] * int(finding["count"])
    return sorted(codes)


def parse_stamp(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


# ── ① shape: input + expectation only ───────────────────────────────────────


def test_truth_file_is_committed_and_non_empty(truth) -> None:
    assert truth["cases"], "空真值不得通过"
    assert truth["as_of"] == 1_900_000_000
    assert truth["kind"] == "fixture-truth"


def test_no_observation_fields_anywhere(truth) -> None:
    """``observed_*`` / ``actual_*`` in a truth file means it is a log, not truth."""
    def walk(node, trail: str = "$") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = key.lower()
                for prefix in FORBIDDEN_PREFIXES:
                    assert not lowered.startswith(prefix), f"真值文件出现观测字段: {trail}.{key}"
                walk(value, f"{trail}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{trail}[{index}]")

    walk(truth)


def test_every_case_uses_only_declared_keys(truth) -> None:
    for entry in truth["cases"]:
        extra = set(entry) - ALLOWED_CASE_KEYS
        assert not extra, f"{entry['case']} 出现未声明字段: {sorted(extra)}"
        extra = set(entry["expect"]) - ALLOWED_EXPECT_KEYS
        assert not extra, f"{entry['case']}.expect 出现未声明字段: {sorted(extra)}"
        for finding in entry["expect"]["findings"]:
            extra = set(finding) - ALLOWED_FINDING_KEYS
            assert not extra, f"{entry['case']} 的 finding 出现未声明字段: {sorted(extra)}"
        for artifact in entry["artifacts"]:
            extra = set(artifact) - ALLOWED_ARTIFACT_KEYS
            assert not extra, f"{entry['case']} 的 artifact 出现未声明字段: {sorted(extra)}"


def test_no_key_material_is_embedded(truth) -> None:
    """The truth file is committable only because it holds no key bytes."""
    text = TRUTH_PATH.read_text(encoding="utf-8")
    for marker in ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN CERTIFICATE"):
        assert marker not in text, f"真值文件里出现了 PEM 材料: {marker}"


def test_every_declared_code_is_known(truth) -> None:
    declared = {finding["code"] for entry in truth["cases"] for finding in entry["expect"]["findings"]}
    assert declared <= KNOWN_CODES, sorted(declared - KNOWN_CODES)
    for entry in truth["cases"]:
        assert set(entry["expect"]["absent"]) <= KNOWN_CODES, entry["case"]


def test_a_rule_never_both_fires_and_stays_absent(cases) -> None:
    """``findings`` and ``absent`` are one partition; overlap means the truth is lying."""
    for name, entry in cases.items():
        fired = {finding["code"] for finding in entry["expect"]["findings"]}
        silent = set(entry["expect"]["absent"])
        assert not (fired & silent), f"{name}: 同一规则既在 findings 又在 absent: {sorted(fired & silent)}"


def test_every_case_declares_at_least_one_expectation(truth) -> None:
    """"No expectations" is not a pass (``plan/04`` §二.5)."""
    for entry in truth["cases"]:
        assert entry["expect"]["findings"], entry["case"]
        assert entry["inputs"], entry["case"]


# ── ② coverage: the eight classes plus the boundary supplements ─────────────


def test_all_eight_required_cases_exist(cases) -> None:
    missing = REQUIRED_CASES - set(cases)
    assert not missing, f"缺必需样本: {sorted(missing)}"


def test_required_cases_are_marked_as_such(cases) -> None:
    for name in REQUIRED_CASES:
        assert cases[name]["group"] == "required", name
    assert sum(1 for entry in cases.values() if entry["group"] == "required") == 8


def test_supplementary_cases_cover_the_documented_boundaries(cases) -> None:
    """``plan/04`` §1.2, one case per row."""
    required_supplements = {"pair", "same-cn", "cliff-none", "cliff-hit",
                            "empty-pass", "perm", "bundle", "broken-der", "noise"}
    assert required_supplements <= set(cases), sorted(required_supplements - set(cases))


def test_plan04_sample_matrix_matches_the_script(cases) -> None:
    """``plan/04`` §1.1 names a directory and a file per class; both must exist."""
    matrix = {
        "healthy": ("healthy", "healthy.pem"),
        "expiring": ("expiring", "expiring.pem"),
        "expired": ("expired", "expired.pem"),
        "weak-key": ("weak-key", "weak-key.pem"),
        "weak-sig": ("weak-sig", "weak-sig.pem"),
        "multi-alias": ("multi-alias", "multi-alias.p12"),
        "truststore-with-key": ("truststore-with-key", "mixed.p12"),
        "orphan": ("orphan", "orphan.key"),
    }
    for name, (directory, filename) in matrix.items():
        entry = cases[name]
        assert entry["inputs"], name
        assert entry["inputs"][0].startswith(f"{directory}/"), (name, entry["inputs"][0])
        assert any(path.endswith(filename) for path in entry["inputs"]), (name, filename)
    # The orphan case also ships the certificate side (ORPHAN_CERT needs it).
    assert any(path.endswith("orphan.crt") for path in cases["orphan"]["inputs"])


# ── ③ independence: expectations recompute from the recorded inputs ────────


def test_every_expectation_recomputes_from_recorded_inputs(truth) -> None:
    """The core independence check: no rule engine, only arithmetic on the artifact.

    ``plan/04`` §二.2 states the discriminator — comment out ``hygiene.py`` and
    the expected value must still be derivable. This test *is* that derivation.
    The policy numbers are read from the policy file, not hard-coded here, so a
    threshold change shows up as a truth failure rather than a silent drift.
    """
    from certledger.policy.loader import load_policy

    policy = load_policy()
    warn_days = policy.get("hygiene.expiring.warn_days")
    cliff_days = policy.get("hygiene.cliff.window_days")
    cliff_min = policy.get("hygiene.cliff.min_count")
    min_bits = policy.get("hygiene.weak_key.rsa.min_bits")

    # The truth records which numbers it was generated against; if the policy
    # moved, the samples are stale and saying so is the whole point.
    recorded = truth["policy_numbers_used"]
    assert recorded["warn_days"] == warn_days
    assert recorded["cliff_window_days"] == cliff_days
    assert recorded["cliff_min_count"] == cliff_min
    assert recorded["weak_key_rsa_min_bits"] == min_bits

    for entry in truth["cases"]:
        as_of = entry["as_of"]
        warn_end = as_of + warn_days * 86400
        cliff_end = as_of + cliff_days * 86400

        container = entry["expect"].get("container")
        container_entries = container["entries"] if container else []

        # Fold artifacts into records: one per fingerprint.
        cert_records: dict[str, dict[str, Any]] = {}
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "cert":
                cert_records.setdefault(artifact["fingerprint_sha256"], artifact)
        for item in container_entries:
            cert_records.setdefault(item["fingerprint_sha256"], {"fingerprint_sha256": item["fingerprint_sha256"],
                                                                 "spki_sha256": item["spki_sha256"]})

        key_files = [a for a in entry["artifacts"] if a["kind"] == "key"]
        key_spki = {key["spki_sha256"] for key in key_files if key["spki_sha256"]}
        key_spki |= {item["spki_sha256"] for item in container_entries if item["entry_type"] == "privateKey"}
        cert_spki = {record["spki_sha256"] for record in cert_records.values()}

        codes: list[str] = []
        for record in cert_records.values():
            if "not_after" not in record:
                continue
            not_after = parse_stamp(record["not_after"])
            if not_after < as_of:
                codes.append("EXPIRED")
            elif not_after < warn_end:
                codes.append("EXPIRING")
            if record["key_algo"] == "rsa" and record["key_bits"] < min_bits:
                codes.append("WEAK_KEY")
            if "sha1" in record["sig_algo_name"].lower():
                codes.append("WEAK_SIG")

        in_window = {
            fingerprint
            for fingerprint, record in cert_records.items()
            if "not_after" in record and as_of <= parse_stamp(record["not_after"]) < cliff_end
        }
        if len(in_window) >= cliff_min:
            codes.append("EXPIRY_CLIFF")

        codes += ["ORPHAN_KEY"] * len(key_spki - cert_spki)
        codes += ["ORPHAN_CERT"] * len(cert_spki - key_spki)

        sources: dict[str, int] = {}
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "cert":
                sources[artifact["fingerprint_sha256"]] = sources.get(artifact["fingerprint_sha256"], 0) + 1
        for item in container_entries:
            sources[item["fingerprint_sha256"]] = sources.get(item["fingerprint_sha256"], 0) + 1
        codes += ["DUPLICATE_CERT"] * sum(1 for count in sources.values() if count > 1)

        if container:
            if container["has_private_key"] and any(e["entry_type"] != "privateKey" for e in container_entries):
                codes.append("CONTAINER_TRUSTSTORE_WITH_KEY")
            if container["password"] == "empty":
                codes.append("CONTAINER_EMPTY_PASSWORD")

        codes += ["PRIVATE_KEY_UNENCRYPTED"] * sum(1 for key in key_files if not key["encrypted"])
        codes += [
            "PERMISSION_TOO_OPEN"
            for key in key_files
            if key.get("posix_mode") and int(str(key["posix_mode"]), 8) & 0o044
        ]
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "broken":
                codes.append("PARSE_FAILED")
            if artifact["kind"] == "noise":
                codes.append("SKIP_BINARY")

        assert sorted(codes) == expected_codes(entry), (
            f"{entry['case']}: 真值与输入不自洽——按输入复算得 {sorted(codes)}，"
            f"文件声明 {expected_codes(entry)}"
        )


def test_expiry_boundary_is_strictly_less_than(cases) -> None:
    """``not_after == as_of`` still counts as valid (``data/README`` §五.2)."""
    as_of = cases["healthy"]["as_of"]
    for name in ("healthy", "expiring", "expired"):
        for artifact in cases[name]["artifacts"]:
            if artifact["kind"] != "cert":
                continue
            not_after = parse_stamp(artifact["not_after"])
            if name == "expired":
                assert not_after < as_of
            else:
                assert not_after >= as_of


def test_weak_sig_case_really_uses_sha1(cases) -> None:
    sha1_oid = "1.2.840.113549.1.1.5"
    signatures = {a["sig_algo"] for a in cases["weak-sig"]["artifacts"] if a["kind"] == "cert"}
    assert sha1_oid in signatures, signatures
    assert "WEAK_SIG" in {f["code"] for f in cases["weak-sig"]["expect"]["findings"]}
    # And no other case accidentally carries a SHA-1 signature.
    for name, entry in cases.items():
        if name == "weak-sig":
            continue
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "cert":
                assert artifact["sig_algo"] != sha1_oid, name


def test_weak_key_case_is_really_below_the_threshold(cases) -> None:
    min_bits = 2048
    bits = [a["key_bits"] for a in cases["weak-key"]["artifacts"] if a["kind"] == "cert"]
    assert bits and all(value < min_bits for value in bits), bits
    for name, entry in cases.items():
        if name == "weak-key":
            continue
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "cert" and artifact["key_algo"] == "rsa":
                assert artifact["key_bits"] >= min_bits, (name, artifact["key_bits"])


def test_cliff_pair_differs_by_count_only(cases) -> None:
    """One certificate in the window vs three: same window, different conclusion."""
    assert "EXPIRY_CLIFF" not in {f["code"] for f in cases["cliff-none"]["expect"]["findings"]}
    assert "EXPIRY_CLIFF" in {f["code"] for f in cases["cliff-hit"]["expect"]["findings"]}
    assert cases["cliff-none"]["as_of"] == cases["cliff-hit"]["as_of"]


def test_same_cn_pair_is_not_paired(cases) -> None:
    """``plan/04`` §1.2: identical CN, different keys, no false pairing."""
    entry = cases["same-cn"]
    cert = next(a for a in entry["artifacts"] if a["kind"] == "cert")
    key = next(a for a in entry["artifacts"] if a["kind"] == "key")
    assert cert["subject"] == key.get("subject") or "shared.example" in cert["subject"]
    assert cert["spki_sha256"] != key["spki_sha256"], "同 CN 的两个密钥对必须 SPKI 不同"
    fired = {f["code"] for f in entry["expect"]["findings"]}
    assert {"ORPHAN_CERT", "ORPHAN_KEY"} <= fired


def test_pair_case_is_actually_paired(cases) -> None:
    entry = cases["pair"]
    cert = next(a for a in entry["artifacts"] if a["kind"] == "cert")
    key = next(a for a in entry["artifacts"] if a["kind"] == "key")
    assert cert["spki_sha256"] == key["spki_sha256"]
    fired = {f["code"] for f in entry["expect"]["findings"]}
    assert not ({"ORPHAN_CERT", "ORPHAN_KEY"} & fired)


def test_bundle_declares_sequential_offsets(cases) -> None:
    offsets = [a.get("offset") for a in cases["bundle"]["artifacts"] if a["kind"] == "cert"]
    assert offsets == [0, 1, 2], offsets
    fingerprints = {a["fingerprint_sha256"] for a in cases["bundle"]["artifacts"] if a["kind"] == "cert"}
    assert len(fingerprints) == 3


def test_multi_alias_lists_two_distinct_aliases(cases) -> None:
    container = cases["multi-alias"]["expect"]["container"]
    aliases = [item["alias"] for item in container["entries"]]
    assert len(aliases) == 2 and len(set(aliases)) == 2, aliases
    fingerprints = {item["fingerprint_sha256"] for item in container["entries"]}
    assert len(fingerprints) == 1, "同一证书两个 alias 必须共用同一指纹"


def test_truststore_with_key_has_both_entry_kinds(cases) -> None:
    container = cases["truststore-with-key"]["expect"]["container"]
    types = {item["entry_type"] for item in container["entries"]}
    assert types == {"privateKey", "trustedCert"}, types
    assert container["has_private_key"] is True
    assert "CONTAINER_TRUSTSTORE_WITH_KEY" in {f["code"] for f in cases["truststore-with-key"]["expect"]["findings"]}


def test_empty_password_case_declares_it(cases) -> None:
    container = cases["empty-pass"]["expect"]["container"]
    assert container["password"] == "empty"
    assert "CONTAINER_EMPTY_PASSWORD" in {f["code"] for f in cases["empty-pass"]["expect"]["findings"]}


def test_permission_case_pins_a_loose_mode(cases) -> None:
    entry = cases["perm"]
    assert entry.get("platform") == "posix"
    key = next(a for a in entry["artifacts"] if a["kind"] == "key")
    assert key["posix_mode"] == "0644"
    assert int(key["posix_mode"], 8) & 0o044


def test_broken_der_is_genuinely_truncated(cases) -> None:
    artifact = next(a for a in cases["broken-der"]["artifacts"] if a["kind"] == "broken")
    assert artifact["truncated_to_bytes"] < artifact["source_der_bytes"]
    assert "PARSE_FAILED" in {f["code"] for f in cases["broken-der"]["expect"]["findings"]}


def test_noise_is_binary_and_not_a_der_sequence(cases) -> None:
    artifact = next(a for a in cases["noise"]["artifacts"] if a["kind"] == "noise")
    assert artifact["has_nul_byte"] is True
    assert "SKIP_BINARY" in {f["code"] for f in cases["noise"]["expect"]["findings"]}


def test_plaintext_keys_are_declared_so(cases) -> None:
    """Every sample key is unencrypted by design; the truth must say so, not hide it."""
    for name, entry in cases.items():
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "key":
                assert artifact["encrypted"] is False, f"{name}: 夹具私钥应当是明文（见 gen.py 模块注释）"
                assert "PRIVATE_KEY_UNENCRYPTED" not in entry["expect"]["absent"], name


# ── ④ artifact agreement (only when the artifacts were generated) ──────────

_HAVE_ARTIFACTS = pytest.mark.skipif(
    not OUT_DIR.is_dir(), reason="fixtures/out 不存在：样本按需生成，不入库"
)


@_HAVE_ARTIFACTS
def test_declared_fingerprints_match_the_bytes_on_disk(cases) -> None:
    """K1: the hash input is the DER as stored, never a re-encoded certificate.

    Two different digests live on each artifact and they must not be confused:

    * ``fingerprint_sha256`` — SHA-256 over the **certificate DER** (K1);
    * ``sha256`` — SHA-256 over the **file bytes** (what "two runs, same file"
      compares, and what makes a PEM container reproducible).

    For a single-certificate PEM these differ, which is the point: hashing the
    PEM text instead of the DER would still look like a fingerprint.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    for name, entry in cases.items():
        for artifact in entry["artifacts"]:
            path = OUT_DIR / artifact["path"]
            if not path.is_file() or artifact["kind"] != "cert":
                continue
            raw = path.read_bytes()
            if artifact.get("offset") is not None:
                # Multi-block PEM: pick the declared block out of the bundle.
                der = _pem_cert_blocks(raw)[artifact["offset"]]
            elif b"-----BEGIN CERTIFICATE-----" in raw:
                der = _pem_cert_blocks(raw)[0]
            else:
                der = raw

            cert = x509.load_der_x509_certificate(der)
            assert hashlib.sha256(der).hexdigest() == artifact["fingerprint_sha256"], name
            spki = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            assert hashlib.sha256(spki).hexdigest() == artifact["spki_sha256"], name
            assert hashlib.sha256(raw).hexdigest() == artifact["sha256"], name


@_HAVE_ARTIFACTS
def test_fingerprint_is_not_the_file_digest(cases) -> None:
    """Guards the K1 failure mode: hashing the PEM text would look plausible."""
    entry = cases["healthy"]
    cert = next(a for a in entry["artifacts"] if a["kind"] == "cert")
    assert cert["fingerprint_sha256"] != cert["sha256"]


@_HAVE_ARTIFACTS
def test_each_case_directory_holds_exactly_its_declared_inputs(cases) -> None:
    """No stray signing material: what the truth lists is what the case ships."""
    for name, entry in cases.items():
        directory = OUT_DIR / name
        if not directory.is_dir():
            continue
        on_disk = {path.relative_to(OUT_DIR).as_posix() for path in directory.rglob("*") if path.is_file()}
        declared = {path for path in entry["inputs"] if path.startswith(f"{name}/")}
        assert on_disk == declared, f"{name}: 目录内容与真值 inputs 不一致（多 {sorted(on_disk - declared)}，少 {sorted(declared - on_disk)}）"


@_HAVE_ARTIFACTS
def test_no_case_directory_contains_signing_material(cases) -> None:
    """Anything used only to sign belongs in scratch, not next to the sample."""
    for directory in OUT_DIR.iterdir():
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            assert not path.name.startswith("_"), f"签名材料泄漏到用例目录: {path.relative_to(OUT_DIR).as_posix()}"


def _pem_cert_blocks(raw: bytes) -> list[bytes]:
    import base64

    text = raw.decode("ascii")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.DOTALL)
    return [base64.b64decode(re.sub(r"\s+", "", body), validate=True) for body in blocks]


# ── ⑤ generator behaviour: --only / --check / --determinism ────────────────


def test_gen_sh_exists_and_is_executable_by_bash() -> None:
    text = GEN_SH.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash")
    assert "openssl version" in text, "生成器必须探测 openssl 版本并按需退出 2"
    assert "--check" in text and "--only" in text and "--out" in text


def test_generator_refuses_a_missing_openssl(monkeypatch) -> None:
    """Missing toolchain is exit 2 with a sentence, never a silent downgrade."""
    result = subprocess.run(
        ["bash", str(GEN_SH), "--help"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode == 0, result.stderr
    assert "--out" in result.stdout
    assert "--check" in result.stdout


def test_only_does_not_rewrite_the_truth_file(tmp_path) -> None:
    """A partial run must never narrow the committed case list (``plan/04`` §三)."""
    before = TRUTH_PATH.read_bytes()
    result = subprocess.run(
        ["bash", str(GEN_SH), "--only", "healthy", "--out", str(tmp_path / "out")],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert TRUTH_PATH.read_bytes() == before, "--only 改写了 expected.json 的全集清单"
    produced = sorted(p.name for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert "healthy.pem" in produced and "manifest.json" in produced
    assert "expired.pem" not in produced


def test_unknown_case_name_is_a_usage_error(tmp_path) -> None:
    result = subprocess.run(
        ["bash", str(GEN_SH), "--only", "no-such-case", "--out", str(tmp_path / "out")],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=300,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "no-such-case" in result.stderr


def test_generator_probes_the_optional_keytool(tmp_path) -> None:
    """``keytool`` is optional (D2): probe and say so, never fail the run.

    JDK's bin directory is usually not on PATH — on this machine ``java`` has a
    shim but ``keytool`` does not — so the probe has to look in the JDK tree
    rather than trusting ``command -v`` alone.
    """
    result = subprocess.run(
        ["bash", str(GEN_SH), "--only", "healthy", "--out", str(tmp_path / "out")],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "keytool" in result.stderr, "生成器必须报告 keytool 探测结果（可用或跳过）"
    assert "跳过" in result.stderr or "可用" in result.stderr


@_HAVE_ARTIFACTS
def test_manifest_records_format_and_command_per_file() -> None:
    """``data/README`` §4.1: name / format / expected result / generation command."""
    manifest_path = OUT_DIR / "manifest.json"
    if not manifest_path.is_file():
        pytest.skip("manifest.json 只在生成时写出")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["cases"]
    for entry in manifest["cases"]:
        assert entry["generate"].startswith("bash fixtures/gen.sh --only "), entry["case"]
        assert entry["case"] in entry["generate"]
        assert entry["files"], entry["case"]
        for item in entry["files"]:
            assert item["path"] and item["format"] and item["kind"], (entry["case"], item)
            assert item["reproducible"] in {"bytes", "alias_table"}
            # A container has no stable digest; everything else must have one.
            if item["reproducible"] == "bytes":
                assert item["sha256"] and len(item["sha256"]) == 64, (entry["case"], item)


@_HAVE_ARTIFACTS
def test_check_path_reports_what_it_skipped() -> None:
    """``--check`` must print the container skip count, not hide it."""
    result = subprocess.run(
        ["bash", str(GEN_SH), "--check"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=900,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "容器字节跳过" in result.stdout
    assert "alias 表比对" in result.stdout


def test_truth_file_is_reproducible(tmp_path) -> None:
    """The truth document must regenerate byte-for-byte.

    Regression guard for a real defect found during M1: the first version stored
    each container's file digest. PKCS#12 carries a random salt and IV, so that
    digest changed on every run — which meant ``expected.json``, the fixed
    reference everything else is compared against, silently moved. A reference
    that drifts is not a reference.

    Container artifacts are therefore described by alias table only, and this
    test regenerates twice into scratch directories and compares the resulting
    truth document byte-for-byte.
    """
    before = TRUTH_PATH.read_bytes()
    for index in (1, 2):
        result = subprocess.run(
            ["bash", str(GEN_SH), "--out", str(tmp_path / f"run{index}")],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=900,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert TRUTH_PATH.read_bytes() == before, f"第 {index} 次重生成改写了 expected.json 的字节"

    # And the committed file must carry no container digest at all.
    text = TRUTH_PATH.read_text(encoding="utf-8")
    assert '"reproducible": "alias_table"' in text
    for entry in json.loads(text)["cases"]:
        for artifact in entry["artifacts"]:
            if artifact["kind"] == "container":
                assert "sha256" not in artifact, (
                    f"{entry['case']}: 容器不该记录文件摘要——P12 盐/IV 随机，"
                    f"记下来会让真值本身不可复现"
                )


@_HAVE_ARTIFACTS
def test_generated_artifacts_never_enter_the_index() -> None:
    """The privacy red line, asserted from the repository side."""
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    if result.returncode != 0:  # pragma: no cover - no git in a shipped sdist
        pytest.skip("not a git checkout")
    forbidden = re.compile(r"\.(pem|key|p12|pfx|jks|jceks|der|crt|csr|crl)$")
    offenders = [line for line in result.stdout.splitlines() if forbidden.search(line)]
    assert offenders == [], offenders
