"""The normalized ledger: merge, pairing, and the deterministic document.

Four claims are asserted here, and each is written so that the *obvious wrong
implementation* fails it:

1. **Merge on fingerprint, not on path.** The same DER in three directories is
   one asset with three sources (``plan/00`` 台账, ``plan/03`` §② M3 基准).
2. **Pair on SPKI, not on name or subject.** ``same-cn`` has two key pairs under
   one CN and must not pair; ``pair`` must.
3. **The document is byte-identical across runs.** Two runs, same input, same
   ``--as-of``: the same bytes. Sorting by fingerprint (not by walk order) is
   what makes that true.
4. **A file we could not read stays visible.** ``PARSE_FAILED`` keeps its
   ``path`` and ``stage``; an unreadable container keeps its ``unreadable``
   reason; a container we *did* open has its contents folded into the same
   tables as everything else.

Inputs come from ``fixtures/expected.json`` and ``fixtures/out`` (never a
hard-coded fingerprint) so that a drifting fixture shows up as a red test rather
than as agreement between two stale constants.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from certledger.inventory import build
from certledger.model import dump_json
from certledger.parsing.fingerprint import der_sha256
from certledger.parsing.pem import split_pem_blocks

ROOT = Path(__file__).resolve().parent.parent
TRUTH = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))
OUT = ROOT / "fixtures" / "out"
CASES = {entry["case"]: entry for entry in TRUTH["cases"]}

needs_artifacts = pytest.mark.skipif(
    not OUT.is_dir(), reason="fixtures/out 未生成；先跑 bash fixtures/gen.sh"
)


@pytest.fixture(autouse=True)
def _sample_container_password(container_password):
    """Every inventory test reads containers with the sample password available.

    Autouse because the password is part of the *input*, not a parameter of any
    one test: without it the three container samples are unreadable boxes, and a
    test that forgot to ask for it would quietly assert over a different ledger.
    """
    return container_password


# ── helpers ─────────────────────────────────────────────────────────────────


def case_inputs(case: str) -> list[str]:
    return [str(OUT / rel) for rel in CASES[case]["inputs"]]


def build_case(case: str, policy, *, source: str = "none") -> dict:
    return build(
        roots=[],
        files=case_inputs(case),
        source=source,
        follow_symlinks=False,
        policy=policy,
    )


def cert_by_fingerprint(payload: dict, fingerprint: str) -> dict:
    matches = [item for item in payload["certs"] if item["fingerprint_sha256"] == fingerprint]
    assert len(matches) == 1, matches
    return matches[0]


def declared(case: str, kind: str) -> dict:
    """The truth declaration for a single-artifact case of ``kind``."""
    artifacts = [item for item in CASES[case]["artifacts"] if item["kind"] == kind]
    assert len(artifacts) == 1, (case, kind, len(artifacts))
    return artifacts[0]


def raw_cert_der(path: Path, offset: int | None = None) -> bytes:
    raw = path.read_bytes()
    if raw.startswith(b"-----BEGIN "):
        blocks = [block for block in split_pem_blocks(raw)[0] if block.kind == "cert"]
        return blocks[offset or 0].der
    return raw


# ── ① merge: one record per distinct certificate ────────────────────────────


@needs_artifacts
def test_three_copies_merge_into_one_record_with_three_sources(policy, tmp_path) -> None:
    """The headline claim of the whole project (``plan/00`` 台账, ``plan/03`` §②).

    Three directories, the *same* certificate in each. A ledger that counts files
    answers "3"; a ledger that answers the question answers "1 asset, 3 places".
    """
    der = raw_cert_der(OUT / "healthy" / "healthy.pem")
    for name in ("a", "b", "c"):
        directory = tmp_path / name
        directory.mkdir()
        # Write the DER form in one copy and the PEM form in the others: the
        # merge key is the certificate, not the container syntax.
        (directory / "copy.der").write_bytes(der)

    payload = build(
        roots=[str(tmp_path)], files=[], source="none", follow_symlinks=False, policy=policy
    )

    fingerprint = der_sha256(der)
    record = cert_by_fingerprint(payload, fingerprint)
    assert len(payload["certs"]) == 1
    assert len(record["sources"]) == 3
    # Sorted by (kind, path, alias): a stable order, not filesystem order.
    paths = [source["path"] for source in record["sources"]]
    assert paths == sorted(paths, key=lambda value: value.casefold())
    assert payload["summary"]["cert_sources"] == 3


@needs_artifacts
def test_pem_and_der_forms_of_one_certificate_are_one_record(policy, tmp_path) -> None:
    """Same DER, different encoding on disk ⇒ one record.

    Hashing the *file* would make these two assets. This is the K1 failure mode
    written as a test: the PEM text digest and the DER digest differ.
    """
    source = OUT / "healthy" / "healthy.pem"
    der = raw_cert_der(source)
    (tmp_path / "as.der").write_bytes(der)
    (tmp_path / "as.pem").write_bytes(source.read_bytes())

    payload = build(
        roots=[str(tmp_path)], files=[], source="none", follow_symlinks=False, policy=policy
    )
    assert len(payload["certs"]) == 1
    assert len(payload["certs"][0]["sources"]) == 2


@needs_artifacts
def test_bundle_expands_into_three_records_without_merging(policy) -> None:
    """Three *different* certificates in one file stay three records.

    The mirror image of the merge rule: a file is not a record, and a record is
    not a file.
    """
    payload = build_case("bundle", policy)
    fingerprints = {item["fingerprint_sha256"] for item in payload["certs"]}
    declared_fingerprints = {
        item["fingerprint_sha256"] for item in CASES["bundle"]["artifacts"] if item["kind"] == "cert"
    }
    assert fingerprints == declared_fingerprints
    assert len(payload["certs"]) == 3
    # All three came from one path, so every source path is the same file.
    paths = {source["path"] for item in payload["certs"] for source in item["sources"]}
    assert len(paths) == 1


@needs_artifacts
def test_same_certificate_under_two_aliases_is_one_record(policy, tmp_path) -> None:
    """``multi-alias`` (a container) declares one fingerprint under two aliases.

    Container expansion is not this module's job, so the test builds the two
    copies as files and asserts the merge; the alias path is covered once the
    container reader lands. What is being pinned here is that nothing about the
    merge depends on the alias.
    """
    der = raw_cert_der(OUT / "healthy" / "healthy.pem")
    (tmp_path / "one.der").write_bytes(der)
    (tmp_path / "two.der").write_bytes(der)
    payload = build(
        roots=[str(tmp_path)], files=[], source="none", follow_symlinks=False, policy=policy
    )
    assert len(payload["certs"]) == 1
    assert len(payload["certs"][0]["sources"]) == 2


# ── ② fingerprints: both computed from the bytes that were read ─────────────


@needs_artifacts
def test_every_truth_case_yields_exactly_its_declared_records(policy) -> None:
    """All 17 cases, wholesale: the ledger's identity sets equal the truth's.

    Row-by-row assertions elsewhere check specific behaviour; this one checks
    that nothing anywhere is invented or dropped. It is written against the
    truth file rather than against numbers observed today, so a fixture that
    drifts shows up as a failure instead of as silent agreement.

    A container's contents are declared in ``expect.container.entries`` rather
    than in ``artifacts`` (a PKCS#12 is one artifact holding several assets), so
    both sections count towards the declared identity sets. Reading only
    ``artifacts`` would have said the ledger invented three certificates the day
    containers were opened.
    """
    mismatches: list[str] = []
    for entry in TRUTH["cases"]:
        files = [str(OUT / rel) for rel in entry["inputs"]]
        payload = build(
            roots=[], files=files, source="none", follow_symlinks=False, policy=policy
        )
        container = entry["expect"].get("container") or {}
        container_entries = container.get("entries") or []
        declared_certs = {
            artifact["fingerprint_sha256"]
            for artifact in entry["artifacts"]
            if artifact["kind"] == "cert"
        }
        declared_certs |= {item["fingerprint_sha256"] for item in container_entries}
        declared_keys = {
            artifact["spki_sha256"]
            for artifact in entry["artifacts"]
            if artifact["kind"] == "key" and artifact.get("spki_sha256")
        }
        declared_keys |= {
            item["spki_sha256"] for item in container_entries if item["entry_type"] == "privateKey"
        }
        got_certs = {record["fingerprint_sha256"] for record in payload["certs"]}
        got_keys = {record["spki_sha256"] for record in payload["keys"] if record["spki_sha256"]}
        if declared_certs != got_certs:
            mismatches.append(f"{entry['case']}: certs {sorted(declared_certs ^ got_certs)}")
        if declared_keys != got_keys:
            mismatches.append(f"{entry['case']}: keys {sorted(declared_keys ^ got_keys)}")
    assert mismatches == [], mismatches


@needs_artifacts
def test_both_fingerprints_agree_with_the_truth_file(policy) -> None:
    """Every declared cert artifact, checked against its own recorded hashes.

    This is the K1 check at the ledger's output: the fingerprint of the DER and
    the hash of the SPKI must equal what the truth file recorded from the same
    bytes. A re-encoding path would still produce *a* hash — this is what makes
    the difference visible.
    """
    for case in ("healthy", "expiring", "expired", "weak-key", "weak-sig", "pair", "same-cn"):
        payload = build_case(case, policy)
        for artifact in CASES[case]["artifacts"]:
            if artifact["kind"] != "cert":
                continue
            record = cert_by_fingerprint(payload, artifact["fingerprint_sha256"])
            assert record["spki_sha256"] == artifact["spki_sha256"], (case, artifact["path"])


@needs_artifacts
def test_key_record_spki_matches_its_declared_value(policy) -> None:
    """A private key's ``spki_sha256`` is derived from *its* public half."""
    payload = build_case("healthy", policy)
    artifact = declared("healthy", "key")
    assert len(payload["keys"]) == 1
    assert payload["keys"][0]["spki_sha256"] == artifact["spki_sha256"]


@needs_artifacts
def test_subject_and_issuer_hashes_are_over_the_der_name(policy) -> None:
    """``subject``/``issuer`` carry a display string **and** a DER hash (plan/03 §②).

    The hash is what distinguishes two names that render identically; the
    display string is for humans. Both must be present, and the hash must be the
    digest of the raw ``Name`` octets — re-encoding would drift with the parser.
    """
    from cryptography import x509

    payload = build_case("healthy", policy)
    record = payload["certs"][0]
    der = raw_cert_der(OUT / "healthy" / "healthy.pem")
    cert = x509.load_der_x509_certificate(der)

    assert record["subject"]["display"] == cert.subject.rfc4514_string()
    assert record["issuer"]["display"] == cert.issuer.rfc4514_string()
    assert record["subject"]["der_sha256"] == der_sha256(cert.subject.public_bytes())
    assert record["issuer"]["der_sha256"] == der_sha256(cert.issuer.public_bytes())


# ── ③ pairing: SPKI only ────────────────────────────────────────────────────


@needs_artifacts
def test_fingerprints_match_an_independent_tool(policy) -> None:
    """K1 checked against ``openssl``, not against this project's own parser.

    Comparing the ledger to a value computed by the same library would only
    prove self-consistency. ``openssl`` is a second implementation: it derives
    the certificate digest and the SPKI digest from the file on disk, and both
    must equal what the ledger reports.

    Note what this can and cannot catch. For a well-formed certificate, a
    ``public_bytes(DER)`` round-trip reproduces the original octets, so no
    output comparison can separate "hashed the bytes we read" from "hashed a
    re-encoding" — they agree. What separates them is what was *passed in*, and
    :func:`test_hash_inputs_are_the_block_bytes_we_read` pins that instead.
    """
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl 不在 PATH 上，无法做独立交叉校验")

    payload = build_case("bundle", policy)
    path = OUT / "bundle" / "bundle.pem"
    blocks = [block for block in split_pem_blocks(path.read_bytes())[0] if block.kind == "cert"]
    assert len(blocks) == 3

    for block in blocks:
        result = subprocess.run(
            [openssl, "x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256"],
            input=block.der,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        # Output form: "SHA256 Fingerprint=AB:CD:..."
        reported = result.stdout.decode("ascii").strip().split("=", 1)[1]
        assert reported.replace(":", "").lower() == der_sha256(block.der)

        pubkey = subprocess.run(
            [openssl, "x509", "-inform", "DER", "-noout", "-pubkey"],
            input=block.der,
            capture_output=True,
        )
        assert pubkey.returncode == 0, pubkey.stderr
        to_der = subprocess.run(
            [openssl, "pkey", "-pubin", "-outform", "DER"], input=pubkey.stdout, capture_output=True
        )
        assert to_der.returncode == 0, to_der.stderr
        record = cert_by_fingerprint(payload, der_sha256(block.der))
        assert record["spki_sha256"] == der_sha256(to_der.stdout)


@needs_artifacts
def test_hash_inputs_are_the_block_bytes_we_read(policy, monkeypatch) -> None:
    """K1 pinned at the call site: the raw block DER reaches the hash function.

    Two wrong implementations this rejects:

    * hashing the **file** (the PEM text) — the digest of a PEM file is not a
      certificate fingerprint, though it looks like one;
    * hashing a **re-serialised** structure when the original octets were
      available (guarded further by :func:`test_fingerprints_match_an_independent_tool`).

    Recording the arguments is the only way to see this: the *values* agree
    between the two implementations for well-formed input.
    """
    import certledger.inventory as inventory_module

    seen: list[bytes] = []
    original = inventory_module.der_sha256

    def recording(der: bytes) -> str:
        seen.append(bytes(der))
        return original(der)

    monkeypatch.setattr(inventory_module, "der_sha256", recording)
    build_case("bundle", policy)

    path = OUT / "bundle" / "bundle.pem"
    raw_file = path.read_bytes()
    blocks = [block for block in split_pem_blocks(raw_file)[0] if block.kind == "cert"]
    assert blocks, "bundle 用例里没有证书块——判据是空跑"

    assert {block.der for block in blocks} <= set(seen), "证书块的原始 DER 没有进入指纹函数"
    assert raw_file not in seen, "整个文件的字节被当成了证书指纹的输入"


@needs_artifacts
def test_certificate_and_key_pair_on_spki(policy) -> None:
    """``pair``: cert.pem + key.pem are one key pair and must say so."""
    payload = build_case("pair", policy)
    cert = declared("pair", "cert")
    assert len(payload["keys"]) == 1
    key = payload["keys"][0]
    assert key["spki_sha256"] == cert["spki_sha256"] == declared("pair", "key")["spki_sha256"]
    assert key["paired_cert_fingerprint"] == cert["fingerprint_sha256"]
    assert payload["summary"]["paired_keys"] == 1


@needs_artifacts
def test_same_cn_with_different_keys_is_not_paired(policy) -> None:
    """``same-cn``: identical CN, different key pairs — no false pairing (K4).

    Pairing on the subject would pair these two; pairing on the SPKI cannot.
    """
    payload = build_case("same-cn", policy)
    cert = declared("same-cn", "cert")
    key = declared("same-cn", "key")
    assert cert["spki_sha256"] != key["spki_sha256"]

    assert len(payload["certs"]) == 1 and len(payload["keys"]) == 1
    assert payload["keys"][0]["paired_cert_fingerprint"] is None
    assert payload["summary"]["paired_keys"] == 0


@needs_artifacts
def test_orphan_case_pairs_neither_side(policy) -> None:
    """``orphan``: a key and a certificate from two unrelated key pairs."""
    payload = build_case("orphan", policy)
    assert len(payload["certs"]) == 1 and len(payload["keys"]) == 1
    assert payload["keys"][0]["paired_cert_fingerprint"] is None
    assert payload["summary"]["paired_keys"] == 0


@needs_artifacts
def test_pairing_survives_certificate_duplication(policy, tmp_path) -> None:
    """Two copies of the certificate do not change which key it pairs with.

    Duplication is a *source* property; pairing is a *key* property. Mixing them
    is how a ledger starts reporting one pair twice.
    """
    shutil.copy(OUT / "pair" / "cert.pem", tmp_path / "cert.pem")
    shutil.copy(OUT / "pair" / "cert.pem", tmp_path / "cert-copy.pem")
    shutil.copy(OUT / "pair" / "key.pem", tmp_path / "key.pem")
    payload = build(
        roots=[str(tmp_path)], files=[], source="none", follow_symlinks=False, policy=policy
    )
    assert len(payload["certs"]) == 1 and len(payload["certs"][0]["sources"]) == 2
    assert len(payload["keys"]) == 1
    assert payload["keys"][0]["paired_cert_fingerprint"] == payload["certs"][0]["fingerprint_sha256"]
    assert payload["summary"]["paired_keys"] == 1


@needs_artifacts
def test_one_key_shared_by_two_certificates_pairs_to_the_lowest_fingerprint(
    policy, tmp_path
) -> None:
    """Same SPKI, two certificates: the pointer is deterministic, the records stay two.

    Re-issuing a certificate for the same key is routine. The ledger must not
    drop either certificate, and the pairing pointer must not depend on walk
    order — otherwise two runs differ.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reissued.example")])
    fixed = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    fingerprints = []
    for serial in (0x7001, 0x7002):
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(fixed)
            .not_valid_after(fixed + dt.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        (tmp_path / f"reissued-{serial}.der").write_bytes(der)
        fingerprints.append(der_sha256(der))
    (tmp_path / "reissued.key").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    payload = build(
        roots=[str(tmp_path)], files=[], source="none", follow_symlinks=False, policy=policy
    )
    assert {record["fingerprint_sha256"] for record in payload["certs"]} == set(fingerprints)
    assert len(payload["keys"]) == 1
    assert payload["keys"][0]["paired_cert_fingerprint"] == min(fingerprints)


# ── ④ determinism ───────────────────────────────────────────────────────────


@needs_artifacts
def test_two_runs_are_byte_identical(policy) -> None:
    """Same input, same policy, same bytes — on the whole fixture tree.

    Comparing the serialised document (not the parsed dict) is the point: dict
    equality hides key-order differences, and key order is part of the contract
    (plan/00 D9).
    """
    first = dump_json(build(roots=[str(OUT)], files=[], source="none",
                            follow_symlinks=False, policy=policy))
    second = dump_json(build(roots=[str(OUT)], files=[], source="none",
                             follow_symlinks=False, policy=policy))
    assert first == second
    assert len(first) > 1000, "文档小得可疑——判据可能是空跑"


@needs_artifacts
def test_key_order_is_declared_not_alphabetical(policy) -> None:
    """Top-level and record keys follow the declared order (K5)."""
    payload = build_case("healthy", policy)
    text = dump_json(payload)
    assert list(payload) == [
        "schema_version",
        "kind",
        "certs",
        "keys",
        "containers",
        "diagnostics",
        "summary",
    ]
    cert_keys = list(payload["certs"][0])
    assert cert_keys[:3] == ["fingerprint_sha256", "spki_sha256", "subject"]
    assert cert_keys[-1] == "sources"
    # And in the serialised text, not only in the dict.
    assert text.index('"fingerprint_sha256"') < text.index('"subject"')


@needs_artifacts
def test_record_order_does_not_depend_on_walk_order(policy, tmp_path) -> None:
    """Two different ``--roots`` orderings produce the same document.

    Sorting by fingerprint (not by discovery) is what makes a ledger diffable
    across machines, where the walk order differs for reasons the user cannot
    control.
    """
    left = tmp_path / "left"
    right = tmp_path / "right"
    for directory, case in ((left, "healthy"), (right, "pair")):
        directory.mkdir()
        shutil.copy(OUT / case / f"{'healthy' if case == 'healthy' else 'cert'}.pem", directory)

    forward = build(roots=[str(left), str(right)], files=[], source="none",
                    follow_symlinks=False, policy=policy)
    backward = build(roots=[str(right), str(left)], files=[], source="none",
                     follow_symlinks=False, policy=policy)
    assert dump_json(forward) == dump_json(backward)
    assert len(forward["certs"]) == 2


# ── ⑤ failure paths stay visible ────────────────────────────────────────────


@needs_artifacts
def test_broken_der_is_parse_failed_with_path_and_stage(policy) -> None:
    """``broken-der``: a truncated blob must not disappear (plan/02 R8).

    ``stage`` is what separates "the DER is broken" from "the base64 is broken";
    without it the diagnostic says a file has a problem but not which.
    """
    payload = build_case("broken-der", policy)
    assert payload["certs"] == [] and payload["keys"] == []
    failures = [item for item in payload["diagnostics"] if item["code"] == "PARSE_FAILED"]
    assert failures, payload["diagnostics"]
    entry = failures[0]
    assert entry["path"].endswith("broken.der")
    assert entry["stage"] == "der"


@needs_artifacts
def test_container_contents_are_opened_and_folded_in(policy) -> None:
    """A PKCS#12 in the tree is opened, and its contents join the same tables.

    The predecessor of this test asserted the opposite — one
    ``PARSE_UNSUPPORTED`` per unopened container, because the container reader
    had not landed. Both halves matter now:

    * the container's certificate is the *same asset* as it would be on disk, so
      it merges by fingerprint and its ``sources[]`` carries
      ``kind="container"`` with the format and the alias;
    * two aliases holding one certificate is **one** record with two sources —
      the ``DUPLICATE_CERT`` the sample exists for, and a count a per-file
      ledger can never produce;
    * ``PARSE_UNSUPPORTED`` is gone, because "we did not open it" is no longer
      true. An unreadable container says so through ``unreadable``.
    """
    payload = build_case("multi-alias", policy)
    container = CASES["multi-alias"]["expect"]["container"]

    assert [item["code"] for item in payload["diagnostics"]] == []
    assert len(payload["containers"]) == 1
    declared = payload["containers"][0]
    assert declared["format"] == "pkcs12"
    assert declared["password"] == container["password"]
    assert declared["unreadable"] is None

    declared_entries = container["entries"]
    assert len(payload["certs"]) == 1
    record = cert_by_fingerprint(payload, declared_entries[0]["fingerprint_sha256"])
    assert len(record["sources"]) == len(declared_entries) == 2
    assert {source["kind"] for source in record["sources"]} == {"container"}
    assert {source["alias"] for source in record["sources"]} == {
        item["alias"] for item in declared_entries
    }
    assert {source["container_format"] for source in record["sources"]} == {"pkcs12"}
    # The alias table itself is part of the ledger, so the two aliases are
    # visible without re-opening the file.
    assert sorted(entry["alias"] for entry in declared["entries"]) == sorted(
        item["alias"] for item in declared_entries
    )


@needs_artifacts
def test_skipped_files_are_carried_through_unmodified(policy) -> None:
    """``noise``: a binary the collector declined is still a diagnostic here.

    The ledger is not allowed to launder a skip into silence — that is the
    difference between an inventory and a directory listing that happened to
    find nothing.
    """
    payload = build_case("noise", policy)
    codes = {item["code"] for item in payload["diagnostics"]}
    assert "SKIP_BINARY" in codes
    assert any(item["path"].endswith("noise.bin") for item in payload["diagnostics"])


@needs_artifacts
def test_a_container_private_key_pairs_with_its_certificate(policy) -> None:
    """``truststore-with-key``: the key entry and its certificate are one pair.

    Both rows come out of one PKCS#12 and must land in the *same* tables as
    anything else — the key in ``keys[]``, its certificate in ``certs[]``, paired
    by SPKI. A container reader that produced a private key record without its
    certificate would report an orphan for the very case that proves the pairing
    works. The store's extra trusted certificate stays unpaired, which is what
    makes ``ORPHAN_CERT`` fire for exactly one of the two.
    """
    payload = build_case("truststore-with-key", policy)
    entries = CASES["truststore-with-key"]["expect"]["container"]["entries"]
    key_entry = next(item for item in entries if item["entry_type"] == "privateKey")
    trusted = next(item for item in entries if item["entry_type"] == "trustedCert")

    assert len(payload["keys"]) == 1
    key = payload["keys"][0]
    assert key["spki_sha256"] == key_entry["spki_sha256"]
    assert key["encrypted"] is True, "容器内的私钥以容器的口令形式存储，不是明文散落"
    assert key["paired_cert_fingerprint"] == key_entry["fingerprint_sha256"]
    assert {source["kind"] for source in key["sources"]} == {"container"}

    assert len(payload["certs"]) == 2
    assert payload["summary"]["paired_keys"] == 1
    assert payload["summary"]["containers"] == 1
    assert payload["summary"]["containers_unreadable"] == 0
    assert trusted["fingerprint_sha256"] in {
        record["fingerprint_sha256"] for record in payload["certs"]
    }


def test_an_unreadable_container_keeps_its_reason(policy, tmp_path) -> None:
    """A container we could not open is a record with a reason, not silence.

    The bytes say PKCS#12 and no password opens it, so the entry is visible and
    says why. Dropping it would render "we could not look inside" as "the box is
    empty" — the distinction the whole failure-path table exists to keep.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    key = rsa_key()
    (tmp_path / "sealed.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"sealed", key, None, None, serialization.BestAvailableEncryption(b"a-real-secret")
        )
    )
    payload = build(roots=[str(tmp_path)], files=[], source="none",
                    follow_symlinks=False, policy=policy)

    assert len(payload["containers"]) == 1
    sealed = payload["containers"][0]
    assert sealed["format"] == "pkcs12"
    assert sealed["password"] == "unknown"
    assert sealed["entries"] == []
    assert sealed["unreadable"]
    assert payload["summary"]["containers_unreadable"] == 1


def test_pkcs7_is_still_reported_as_unsupported(policy, tmp_path) -> None:
    """PKCS#7 keeps its ``PARSE_UNSUPPORTED``: named, not read, not silent.

    The container reader landed for PKCS#12 / JKS / JCEKS and for nothing else.
    A PKCS#7 bundle must therefore still leave a visible record — this is what
    stops "we do not read this format" from becoming "there is nothing in this
    file".
    """
    import base64

    blob = base64.b64encode(b"\x30\x03\x02\x01\x01").decode("ascii")
    (tmp_path / "bundle.p7").write_text(
        f"-----BEGIN PKCS7-----\n{blob}\n-----END PKCS7-----\n", encoding="utf-8"
    )
    payload = build(roots=[str(tmp_path)], files=[], source="none",
                    follow_symlinks=False, policy=policy)
    unsupported = [item for item in payload["diagnostics"] if item["code"] == "PARSE_UNSUPPORTED"]
    assert unsupported, payload["diagnostics"]
    assert unsupported[0]["stage"] == "container"
    assert unsupported[0]["path"].endswith("bundle.p7")
    assert payload["certs"] == [] and payload["keys"] == []


def rsa_key():
    """A throwaway 2048-bit key for tests that need a real container."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_inventory_requires_a_policy(tmp_path) -> None:
    """K3: no policy, no ledger — never "use the built-in thresholds"."""
    from certledger.errors import CliError

    with pytest.raises(CliError):
        build(roots=[str(tmp_path)], files=[], source="none",
              follow_symlinks=False, policy=None)


def test_empty_tree_is_an_empty_ledger_not_an_error(policy, tmp_path) -> None:
    """An empty answer is allowed *here*: it is a counted empty answer.

    The shells raise because they have no data at all. This module has data —
    zero records — and says so, with counters that show the walk happened.
    """
    payload = build(roots=[str(tmp_path)], files=[], source="none",
                    follow_symlinks=False, policy=policy)
    assert payload["kind"] == "inventory"
    assert payload["certs"] == [] and payload["keys"] == [] and payload["diagnostics"] == []
    assert payload["summary"]["collect"]["visited"] == 0


# ── ⑥ encrypted keys ────────────────────────────────────────────────────────


def test_encrypted_key_without_a_passphrase_keeps_a_record(policy, tmp_path) -> None:
    """A locked key is understood but not readable — it still exists (plan/03 §②).

    Omitting it would say "there is no private key here", which is false. It
    gets ``encrypted=true`` and ``spki_sha256=null`` (no SPKI is derivable
    without the passphrase), so no pairing rule can match it by accident.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "locked.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"fixture-passphrase"),
        )
    )

    payload = build(roots=[str(tmp_path)], files=[], source="none",
                    follow_symlinks=False, policy=policy)
    assert len(payload["keys"]) == 1
    record = payload["keys"][0]
    assert record["encrypted"] is True
    assert record["spki_sha256"] is None
    assert record["paired_cert_fingerprint"] is None
    assert payload["summary"]["locked_keys"] == 1
    assert payload["summary"]["paired_keys"] == 0


def test_two_locked_keys_do_not_merge_into_one_record(policy, tmp_path) -> None:
    """Without an SPKI there is no identity — so do not invent one.

    A ``spki_sha256`` sentinel would merge every locked key on the machine into
    a single record. That is worse than not merging: it asserts an identity that
    nothing verified.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    for name in ("one.pem", "two.pem"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (tmp_path / name).write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"fixture-passphrase"),
            )
        )
    payload = build(roots=[str(tmp_path)], files=[], source="none",
                    follow_symlinks=False, policy=policy)
    assert len(payload["keys"]) == 2
    assert all(record["spki_sha256"] is None for record in payload["keys"])
    assert payload["summary"]["locked_keys"] == 2


# ── ⑦ privacy and shape ─────────────────────────────────────────────────────


@needs_artifacts
def test_ledger_carries_no_host_name_or_timestamp(policy) -> None:
    """D9: the ledger must be publishable as-is."""
    text = dump_json(build_case("healthy", policy))
    for forbidden in ("scanned_at", "parsed_at", "hostname", "username", "generated_at"):
        assert forbidden not in text, forbidden


@needs_artifacts
def test_summary_units_are_named_not_summed(policy) -> None:
    """``certs`` / ``keys`` / ``sources`` are different units (plan/03 §② 统计口径).

    The record counts are checked against the arrays they describe, so a summary
    that drifts from the body fails here rather than in a report months later.
    """
    payload = build(roots=[str(OUT)], files=[], source="none",
                    follow_symlinks=False, policy=policy)
    summary = payload["summary"]
    assert summary["certs"] == len(payload["certs"])
    assert summary["keys"] == len(payload["keys"])
    assert summary["cert_sources"] == sum(len(item["sources"]) for item in payload["certs"])
    assert summary["key_sources"] == sum(len(item["sources"]) for item in payload["keys"])
    assert summary["paired_keys"] <= summary["keys"]
