"""Hygiene rules: the nine families, the truth file, and the failure paths.

This is the module that turns a ledger into judgements, so the tests here are
organised around the three ways such a layer goes wrong:

1. **It disagrees with the truth file.** The 17 sample cases were written before
   this module existed and are recomputed independently in
   ``tests/test_fixtures_truth.py``. If the two disagree, one of them is wrong —
   that is the finding, not a test to adjust.
2. **It asserts something the data does not support.** An undecodable key is not
   weak, a locked key is not an orphan, an unparseable date is not expired.
   Each of those has a test that would fail if the rule started guessing.
3. **It hides what it did not look at.** A diagnostic must survive into the
   report, and a rule switched to ``off`` must still be counted as suppressed —
   otherwise a quiet report cannot be told apart from a clean one.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from certledger.hygiene import evaluate
from certledger.policy.loader import load_policy
from certledger.timebase import parse_as_of

ROOT = Path(__file__).resolve().parent.parent
TRUTH_PATH = ROOT / "fixtures" / "expected.json"
OUT = ROOT / "fixtures" / "out"
AS_OF = 1_900_000_000

#: Inside both the ``EXPIRING`` and the ``EXPIRY_CLIFF`` windows of ``AS_OF``
#: (10 days out, against a 30-day policy for both). Named so a synthetic record
#: cannot silently fall outside the window it is meant to sit in.
IN_WINDOW = "2030-03-27T17:46:40Z"

_HAVE_ARTIFACTS = pytest.mark.skipif(
    not OUT.is_dir(), reason="fixtures/out 不存在：样本按需生成，不入库"
)


# ── helpers ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def truth() -> dict[str, Any]:
    return json.loads(TRUTH_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cases(truth) -> dict[str, dict[str, Any]]:
    return {entry["case"]: entry for entry in truth["cases"]}


def evaluate_case(case: dict[str, Any], policy=None, as_of: int | None = None) -> dict:
    """Run ``hygiene`` over one case's declared inputs, exactly as declared.

    The ``inputs`` list is the contract: it names the files, so a case that
    gained a stray file would be evaluated on what the truth says, not on what
    happens to be in the directory.
    """
    files = [str(OUT / item) for item in case["inputs"]]
    return evaluate(
        roots=[],
        files=files,
        inventory_path=None,
        as_of=parse_as_of(str(as_of if as_of is not None else case["as_of"])),
        policy=policy or load_policy(),
        source="none",
    )


def codes(payload: dict) -> list[str]:
    """Every finding code, repeated once per finding — the unit the truth uses."""
    return sorted(item["code"] for item in payload["findings"])


def by_code(payload: dict, code: str) -> list[dict]:
    return [item for item in payload["findings"] if item["code"] == code]


def expected(entry: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for finding in entry["expect"]["findings"]:
        out += [finding["code"]] * int(finding["count"])
    return sorted(out)


# ── ① the truth file, case by case ──────────────────────────────────────────

#: Cases whose expected findings depend on a surface that is still outstanding.
#: Named explicitly (rather than skipped by pattern) so that when M5 lands, the
#: list has to be edited — a silently shrinking coverage set is the failure mode
#: a `pytest.skip` inside a loop would create.
@pytest.fixture(autouse=True)
def _sample_container_password(container_password):
    """Hand the container reader the sample password for this whole module.

    Three of the seventeen cases put their certificates inside a PKCS#12, and the
    password is part of that input. Asking for it in each test would mean the one
    that forgot was silently asserting over a *different* ledger — a container
    that never opened — and could still pass when its expectations happened to be
    about something else.
    """
    return container_password


@_HAVE_ARTIFACTS
@pytest.mark.parametrize("name", sorted(
    {entry["case"] for entry in json.loads(TRUTH_PATH.read_text(encoding="utf-8"))["cases"]}
    - {"perm"}
))
def test_case_matches_the_truth_file(cases, name) -> None:
    """Each remaining case produces exactly the declared code multiset.

    ``perm`` is the one exclusion, and it is not a gap: the recorded permission
    bits are ``None`` on Windows by design, so that rule correctly stays silent
    here. It has its own test below, on a ledger that carries a mode.
    """
    payload = evaluate_case(cases[name])
    assert codes(payload) == expected(cases[name]), name


@_HAVE_ARTIFACTS
def test_the_only_unreconciled_case_is_the_posix_only_one(cases) -> None:
    """Every case reconciles except ``perm``, whose premise this platform lacks.

    This test used to pin a *four*-case gap: the three container cases needed the
    contents of a PKCS#12, which the ledger did not open. The container reader has
    landed, so the gap is down to the one case Windows cannot have — and the
    assertion is written so that a regression which silently re-opens the gap
    fails here rather than in a report.
    """
    unreconciled = []
    for name, entry in cases.items():
        if codes(evaluate_case(entry)) != expected(entry):
            unreconciled.append(name)
    assert unreconciled == ["perm"]


@_HAVE_ARTIFACTS
def test_every_case_declares_the_severity_the_rule_emits(cases) -> None:
    """The truth file pins severities, not only codes.

    A rule that fires with the right code at the wrong severity would satisfy a
    code-only check while quietly changing whether the report gates a build.
    ``perm`` is excluded because it cannot fire here at all (see above); every
    other case, container ones included, must match code *and* severity.
    """
    for name, entry in cases.items():
        if name == "perm":
            continue
        payload = evaluate_case(entry)
        actual = {(item["code"], item["severity"]) for item in payload["findings"]}
        declared = {(item["code"], item["severity"]) for item in entry["expect"]["findings"]}
        assert actual == declared, (name, actual - declared, declared - actual)


@_HAVE_ARTIFACTS
def test_absent_codes_really_do_not_fire(cases) -> None:
    """``expect.absent`` is a claim, so it gets checked like one — for all 17 cases.

    The truth file's partition rule is enforced for the file itself in
    ``test_fixtures_truth.py``; this is the other half — the engine must agree
    that those rules are silent on those inputs. It holds for every one of the
    seventeen cases, including the container ones whose certificates only became
    visible when the container reader landed: "these rules must not fire" is a
    claim that has to survive the moment more of the input becomes readable.
    """
    for name, entry in cases.items():
        fired = {item["code"] for item in evaluate_case(entry)["findings"]}
        for code in entry["expect"]["absent"]:
            assert code not in fired, (name, code)


@_HAVE_ARTIFACTS
def test_every_finding_carries_a_citation(cases) -> None:
    """No rule may enter the report without a source (plan/03 §③ 纪律)."""
    for name, entry in cases.items():
        for finding in evaluate_case(entry)["findings"]:
            assert finding["rule_source"].strip(), (name, finding["code"])


@_HAVE_ARTIFACTS
def test_the_citation_shape_is_one_of_the_documented_forms(cases) -> None:
    """``rule_source`` carries the same citation shape the loader accepts.

    The tokens are imported from the loader rather than re-typed here, so the
    "what counts as a citation" rule has exactly one definition: if the loader
    were taught a new document family, this test would follow it instead of
    drifting into a second, stricter opinion.
    """
    from certledger.policy.loader import _SOURCE_RE

    for name, entry in cases.items():
        for finding in evaluate_case(entry)["findings"]:
            assert any(token in finding["rule_source"] for token in _SOURCE_RE), (
                name, finding["rule_source"],
            )


# ── ② cliff counts distinct certificates, not copies ────────────────────────


@_HAVE_ARTIFACTS
def test_cliff_counts_distinct_fingerprints_not_records(policy, tmp_path) -> None:
    """The counting unit, pinned where the two candidate units actually differ.

    A file scan cannot discriminate: ``inventory`` already merges one
    fingerprint into one record, so "count records" and "count distinct
    fingerprints" agree. They diverge on a ledger that carries the same
    fingerprint twice — which a hand-merged or concatenated ledger can — and
    there the rule must still count **one** renewal.

    Below the threshold of 3, two records sharing one fingerprint must not fire
    a cliff; three records over two fingerprints must not fire either.
    """
    minimum = int(policy.require("hygiene.cliff.min_count"))
    assert minimum >= 3, "this test assumes a threshold of at least three"

    def run(records: list[dict]) -> dict:
        return evaluate(
            roots=[], files=[],
            inventory_path=_write_ledger(tmp_path, {"certs": records, "keys": []}),
            as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
        )

    # ``minimum - 1`` records, all one fingerprint: one renewal, no cliff.
    same = [
        _cert(fingerprint="1" * 64, spki=str(index) * 64, not_after=IN_WINDOW)
        for index in range(minimum - 1)
    ]
    assert not by_code(run(same), "EXPIRY_CLIFF")

    # ``minimum`` records sharing one fingerprint: still one renewal.
    wider = [
        _cert(fingerprint="1" * 64, spki=str(index) * 64, not_after=IN_WINDOW)
        for index in range(minimum)
    ]
    assert not by_code(run(wider), "EXPIRY_CLIFF")

    # ``minimum`` distinct fingerprints: the cliff fires, evidence names them.
    distinct = [
        _cert(fingerprint=str(index) * 64, spki=str(index) * 64, not_after=IN_WINDOW)
        for index in range(minimum)
    ]
    fired = by_code(run(distinct), "EXPIRY_CLIFF")
    assert len(fired) == 1
    assert fired[0]["evidence"]["count"] == minimum


@_HAVE_ARTIFACTS
def test_cliff_counts_deduplicated_copies_as_one(policy, tmp_path) -> None:
    """Three copies of one certificate on disk are one record and no cliff.

    The complementary case through the real pipeline: the dedupe happens in
    ``inventory``, so this asserts the two layers agree about what "one
    certificate" means rather than restating the rule.
    """
    source = OUT / "cliff-hit" / "c1.pem"
    for index in range(3):
        shutil.copy(source, tmp_path / f"copy-{index}.pem")

    payload = evaluate(
        roots=[str(tmp_path)],
        files=[],
        inventory_path=None,
        as_of=parse_as_of(str(AS_OF)),
        policy=policy,
        source="none",
    )
    assert payload["summary"]["records"]["certs"] == 1
    assert not by_code(payload, "EXPIRY_CLIFF")
    # And the copies are still visible — as duplicates, the correct diagnosis.
    assert len(by_code(payload, "DUPLICATE_CERT")) == 1


@_HAVE_ARTIFACTS
def test_cliff_fires_exactly_at_the_policy_minimum(policy, tmp_path) -> None:
    """One below the threshold is silent; at the threshold it fires.

    The threshold is read from the policy, so the case is built from the policy
    value rather than from the number 3 — a policy change moves both sides.
    """
    minimum = int(policy.require("hygiene.cliff.min_count"))
    sources = [OUT / "cliff-hit" / f"c{index}.pem" for index in (1, 2, 3)]

    def run(count: int) -> dict:
        directory = tmp_path / f"n{count}"
        directory.mkdir()
        for index in range(count):
            shutil.copy(sources[index % len(sources)], directory / f"c{index}.pem")
        return evaluate(
            roots=[str(directory)],
            files=[],
            inventory_path=None,
            as_of=parse_as_of(str(AS_OF)),
            policy=policy,
            source="none",
        )

    assert not by_code(run(minimum - 1), "EXPIRY_CLIFF")
    assert len(by_code(run(minimum), "EXPIRY_CLIFF")) == 1


@_HAVE_ARTIFACTS
def test_cliff_evidence_lists_the_fingerprints_it_counted(policy) -> None:
    """The count is auditable: the evidence names exactly the records counted."""
    payload = evaluate_case({"case": "cliff-hit", "as_of": AS_OF,
                             "inputs": [f"cliff-hit/c{index}.pem" for index in (1, 2, 3)]},
                            policy=policy)
    cliff = by_code(payload, "EXPIRY_CLIFF")
    assert len(cliff) == 1
    evidence = cliff[0]["evidence"]
    assert evidence["count"] == len(evidence["fingerprints"]) == 3
    assert evidence["fingerprints"] == sorted(evidence["fingerprints"])


# ── ③ expiry boundary ───────────────────────────────────────────────────────


@_HAVE_ARTIFACTS
def test_not_after_equal_to_as_of_is_still_valid(policy) -> None:
    """``not_after == as_of`` is valid, not expired (data/README §五.2).

    The boundary is decided once, in ``hygiene``, and the truth file's
    ``expired`` case sits strictly before it — so this test pins the side the
    samples do not: exactly on the instant.
    """
    from certledger.timebase import parse_stamp

    entry = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
    case = next(item for item in entry["cases"] if item["case"] == "expiring")
    not_after = next(
        parse_stamp(artifact["not_after"]) for artifact in case["artifacts"] if artifact["kind"] == "cert"
    )
    payload = evaluate_case(case, policy=policy, as_of=not_after)
    fired = {item["code"] for item in payload["findings"]}
    assert "EXPIRED" not in fired
    # One second later it has expired: the boundary is sharp in both directions.
    payload = evaluate_case(case, policy=policy, as_of=not_after + 1)
    assert "EXPIRED" in {item["code"] for item in payload["findings"]}


@_HAVE_ARTIFACTS
def test_expiry_evidence_reports_days_over(policy) -> None:
    entry = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
    case = next(item for item in entry["cases"] if item["case"] == "expired")
    expired = by_code(evaluate_case(case, policy=policy), "EXPIRED")
    assert len(expired) == 1
    assert expired[0]["evidence"]["days_over"] >= 0
    assert expired[0]["evidence"]["as_of"] == "2030-03-17T17:46:40Z"


# ── ④ rules do not invent facts ─────────────────────────────────────────────


def test_a_certificate_without_a_decodable_key_is_not_weak(policy, tmp_path) -> None:
    """``key_algo == ""`` means "this build cannot read it", not "it is weak".

    Measured on the host store: 1 of 81 certificates (an MD5-signed legacy root)
    has no decodable public key. Calling it weak would be a judgement about a
    key nobody read; the ledger keeps the record, and the rule stays silent.
    """
    payload = evaluate(
        roots=[str(tmp_path)],
        files=[],
        inventory_path=_write_ledger(tmp_path, {
            "certs": [_cert(algo="", bits=None, sig_algo="1.2.840.113549.1.1.4")],
            "keys": [],
        }),
        as_of=parse_as_of(str(AS_OF)),
        policy=policy,
        source="none",
    )
    assert not by_code(payload, "WEAK_KEY")


def test_a_locked_key_is_not_an_orphan(policy, tmp_path) -> None:
    """An encrypted key with no passphrase has no SPKI, so it has no orphan claim.

    "We could not check whether it has a certificate" is not "it has none", and
    the ledger deliberately keeps the SPKI ``null`` rather than inventing one.
    """
    ledger = _write_ledger(tmp_path, {
        "certs": [],
        "keys": [{
            "spki_sha256": None,
            "key_algo": "",
            "key_bits": None,
            "curve": None,
            "encrypted": True,
            "paired_cert_fingerprint": None,
            "sources": [{"kind": "file", "path": "locked.key", "posix_mode": None}],
        }],
    })
    payload = evaluate(
        roots=[],
        files=[],
        inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)),
        policy=policy,
        source="none",
    )
    assert not by_code(payload, "ORPHAN_KEY")
    # It is still reported as encrypted, which is the whole point of keeping it.
    assert not by_code(payload, "PRIVATE_KEY_UNENCRYPTED")


def test_an_unparseable_date_is_not_evidence_of_expiry(policy, tmp_path) -> None:
    """A record whose stamp will not parse produces no expiry finding.

    Silently treating it as "expired" would be the safe-looking wrong answer;
    treating it as "fine" without saying so would hide a damaged ledger. It is
    neither: the rule stays silent, and the damaged record is still in
    ``summary.records``.
    """
    ledger = _write_ledger(tmp_path, {
        "certs": [_cert(not_after="not-a-date")],
        "keys": [],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    fired = {item["code"] for item in payload["findings"]}
    assert "EXPIRED" not in fired and "EXPIRING" not in fired
    assert payload["summary"]["records"]["certs"] == 1


# ── ⑤ failure records stay visible ──────────────────────────────────────────


def test_parse_failed_becomes_a_finding(policy, tmp_path) -> None:
    """A damaged file is reported, not dropped (plan/03 §⑥)."""
    ledger = _write_ledger(tmp_path, {
        "certs": [],
        "keys": [],
        "diagnostics": [{
            "code": "PARSE_FAILED", "path": "broken.der", "stage": "der", "detail": "截断",
        }],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    failed = by_code(payload, "PARSE_FAILED")
    assert len(failed) == 1
    assert failed[0]["severity"] == "WARN"
    assert failed[0]["evidence"]["stage"] == "der"


def test_source_unavailable_becomes_a_finding_without_changing_anything(policy, tmp_path) -> None:
    """D11: an unavailable backend is INFO, and there is no gate on it here.

    ``hygiene`` has no exit code of its own beyond 0/2 — the threshold belongs
    to ``report``. What this asserts is that the record survives and stays INFO.
    """
    ledger = _write_ledger(tmp_path, {
        "certs": [],
        "keys": [],
        "diagnostics": [{
            "code": "SOURCE_UNAVAILABLE", "path": "store:macos", "stage": "backend",
            "detail": "本机未验证",
        }],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    unavailable = by_code(payload, "SOURCE_UNAVAILABLE")
    assert len(unavailable) == 1
    assert unavailable[0]["severity"] == "INFO"


def test_an_unlisted_failure_code_takes_the_documented_default(policy, tmp_path) -> None:
    """A new ``SKIP_*`` code must not be able to become silent by accident.

    The collector's code vocabulary is open. An unlisted code inherits
    ``hygiene.diagnostics.default`` from the policy, so the fallback is a
    reviewable line in a data file rather than a missing branch in code.
    """
    ledger = _write_ledger(tmp_path, {
        "certs": [], "keys": [],
        "diagnostics": [{
            "code": "SKIP_SOMETHING_NEW", "path": "x", "stage": "", "detail": "",
        }],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    finding = by_code(payload, "SKIP_SOMETHING_NEW")[0]
    assert finding["severity"] == policy.require("hygiene.diagnostics.default")


# ── ⑥ suppression is counted, never silent ─────────────────────────────────


def test_level_off_removes_findings_but_counts_them(policy, tmp_path) -> None:
    """``level: off`` means "do not show", not "did not happen" (plan/03 §③).

    Without ``summary.suppressed`` a report where a rule was switched off is
    byte-identical to a report over a machine where nothing was wrong — the two
    most different situations a reader can be in.
    """
    from certledger.policy.loader import load_policy as reload

    data = json.loads(policy.raw)
    data["hygiene"]["private_key"]["level"] = "off"
    path = tmp_path / "off.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    off = reload(path)

    ledger = _write_ledger(tmp_path, {
        "keys": [{
            "spki_sha256": "aa", "key_algo": "rsa", "key_bits": 2048, "curve": None,
            "encrypted": False, "paired_cert_fingerprint": None,
            "sources": [{"kind": "file", "path": "k.pem", "posix_mode": None}],
        }],
        "certs": [_cert(spki="aa")],
    })

    def run(p) -> dict:
        return evaluate(
            roots=[], files=[], inventory_path=ledger,
            as_of=parse_as_of(str(AS_OF)), policy=p, source="none",
        )

    on, suppressed = run(policy), run(off)
    assert by_code(on, "PRIVATE_KEY_UNENCRYPTED")
    assert not by_code(suppressed, "PRIVATE_KEY_UNENCRYPTED")
    assert suppressed["summary"]["suppressed"] >= 1
    assert suppressed["summary"]["suppressed_by_code"]["PRIVATE_KEY_UNENCRYPTED"] == 1


# ── ⑦ the ledger input ──────────────────────────────────────────────────────


@_HAVE_ARTIFACTS
def test_a_stored_ledger_gives_the_same_answer_as_a_fresh_scan(policy) -> None:
    """``--inventory`` is a real input, not a second code path with own rules.

    The stored ledger and the fresh scan describe the same files, so they must
    produce the same findings — otherwise the stored form would be a different
    tool that happens to share a name.
    """
    from certledger.inventory import build

    case = {"case": "cliff-hit", "as_of": AS_OF,
            "inputs": [f"cliff-hit/c{index}.{suffix}" for index in (1, 2, 3) for suffix in ("pem", "key")]}
    fresh = evaluate_case(case, policy=policy)

    ledger = build(
        roots=[str(OUT / "cliff-hit")], files=[], source="none",
        follow_symlinks=False, policy=policy,
    )
    stored_path = OUT.parent.parent / ".tmp-ledger.json"  # never in the repo tree
    try:
        from certledger.model import dump_json

        stored_path.write_text(dump_json(ledger), encoding="utf-8")
        stored = evaluate(
            roots=[], files=[], inventory_path=str(stored_path),
            as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
        )
    finally:
        stored_path.unlink(missing_ok=True)

    assert codes(stored) == codes(fresh)


def test_a_missing_ledger_file_is_exit_two_not_an_empty_report(tmp_path) -> None:
    """"The file you named does not exist" must not read as "nothing found"."""
    from certledger.errors import CliError

    with pytest.raises(CliError) as error:
        evaluate(
            roots=[], files=[], inventory_path=str(tmp_path / "absent.json"),
            as_of=parse_as_of(str(AS_OF)), policy=load_policy(), source="none",
        )
    assert "不存在" in str(error.value)


def test_a_ledger_of_the_wrong_kind_is_rejected(tmp_path) -> None:
    """A ``collect`` payload is not a ledger; reading it would lose every record."""
    from certledger.errors import CliError

    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"kind": "collect", "candidates": []}), encoding="utf-8")
    with pytest.raises(CliError) as error:
        evaluate(
            roots=[], files=[], inventory_path=str(path),
            as_of=parse_as_of(str(AS_OF)), policy=load_policy(), source="none",
        )
    assert "kind" in str(error.value)


def test_as_of_is_mandatory() -> None:
    """There is no branch that falls back to the wall clock (K2)."""
    from certledger.errors import CliError

    with pytest.raises(CliError):
        evaluate(roots=[], files=[], inventory_path=None, as_of=None,
                 policy=load_policy(), source="none")


def test_policy_is_mandatory() -> None:
    """Thresholds have no code defaults (K3)."""
    from certledger.errors import CliError

    with pytest.raises(CliError):
        evaluate(roots=[], files=[], inventory_path=None,
                 as_of=parse_as_of(str(AS_OF)), policy=None, source="none")


# ── ⑧ output shape ──────────────────────────────────────────────────────────


@_HAVE_ARTIFACTS
def test_key_order_is_declared(policy) -> None:
    payload = evaluate_case({"case": "healthy", "as_of": AS_OF,
                             "inputs": ["healthy/healthy.pem", "healthy/healthy.key"]}, policy=policy)
    assert list(payload) == [
        "schema_version", "kind", "as_of", "as_of_utc",
        "policy_version", "policy_sha256", "findings", "summary",
    ]
    assert list(payload["findings"][0]) == [
        "code", "severity", "subject", "fingerprint", "evidence", "rule_source",
    ]


@_HAVE_ARTIFACTS
def test_two_runs_are_byte_identical(policy) -> None:
    from certledger.model import dump_json

    case = {"case": "cliff-hit", "as_of": AS_OF,
            "inputs": [f"cliff-hit/c{index}.{suffix}" for index in (1, 2, 3) for suffix in ("pem", "key")]}
    first = dump_json(evaluate_case(case, policy=policy))
    second = dump_json(evaluate_case(case, policy=policy))
    assert first == second


@_HAVE_ARTIFACTS
def test_findings_are_sorted_by_severity_then_code(policy) -> None:
    payload = evaluate_case({"case": "expired", "as_of": AS_OF,
                             "inputs": ["expired/expired.pem", "expired/expired.key"]}, policy=policy)
    order = {"ERROR": 0, "WARN": 1, "INFO": 2}
    ranks = [order[item["severity"]] for item in payload["findings"]]
    assert ranks == sorted(ranks), payload["findings"]


@_HAVE_ARTIFACTS
def test_the_document_carries_no_host_name_or_timestamp(policy) -> None:
    """D9: the finding document must be publishable as-is."""
    from certledger.model import dump_json

    payload = evaluate_case({"case": "healthy", "as_of": AS_OF,
                             "inputs": ["healthy/healthy.pem", "healthy/healthy.key"]}, policy=policy)
    text = dump_json(payload)
    for forbidden in ("hostname", "username", "generated_at", "scanned_at", "elapsed"):
        assert forbidden not in text, forbidden


@_HAVE_ARTIFACTS
def test_the_document_echoes_the_instant_and_the_policy(policy) -> None:
    """A report that does not say what it was judged against cannot be diffed."""
    payload = evaluate_case({"case": "healthy", "as_of": AS_OF,
                             "inputs": ["healthy/healthy.pem"]}, policy=policy)
    assert payload["as_of"] == str(AS_OF)
    assert payload["as_of_utc"] == "2030-03-17T17:46:40Z"
    assert payload["policy_version"] == policy.version
    assert payload["policy_sha256"] == policy.sha256


@_HAVE_ARTIFACTS
def test_summary_names_its_units_and_they_are_not_summed(policy) -> None:
    """Records and findings are different units (plan/03 §③ 统计口径).

    One certificate can carry several findings, or none, so the summary states
    both and never adds them. The one relation asserted is a partition: every
    finding is counted in exactly one severity bucket.
    """
    payload = evaluate_case({"case": "cliff-hit", "as_of": AS_OF,
                             "inputs": [f"cliff-hit/c{index}.{suffix}"
                                        for index in (1, 2, 3) for suffix in ("pem", "key")]},
                            policy=policy)
    summary = payload["summary"]
    assert summary["findings"] == len(payload["findings"])
    assert sum(summary["by_severity"].values()) == summary["findings"]
    assert summary["records"]["certs"] >= 0 and summary["records"]["keys"] >= 0


# ── ⑨ container and permission rules on a synthetic ledger ─────────────────
#
# The three container cases and the POSIX-permission case cannot reconcile
# through a file scan yet (see ``test_the_unreconciled_cases_are_exactly_the
# _documented_ones``). The rules themselves are implemented, so they are tested
# here on a ledger that carries the data those surfaces will supply. This keeps
# the rule set from being "written but never executed".


def test_permission_rule_compares_against_the_policy_mask(policy, tmp_path) -> None:
    """0644 is too open; 0600 is not — and the boundary comes from the policy.

    A bit-mask comparison against ``max_posix_mode`` (``640`` by default) rather
    than a hard-coded ``& 0o044`` keeps the permitted set in one data file: a
    policy that allowed group-read would move this test's midpoint, not the
    code.
    """
    ledger = _write_ledger(tmp_path, {
        "certs": [_cert(spki="aa")],
        "keys": [
            _key("aa", mode="0644", path="loose.key"),
            _key("bb", mode="0600", path="tight.key"),
        ],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    open_findings = by_code(payload, "PERMISSION_TOO_OPEN")
    assert len(open_findings) == 1
    assert open_findings[0]["evidence"]["path"] == "loose.key"
    assert open_findings[0]["evidence"]["max_posix_mode"] == "640"


def test_a_key_without_a_recorded_mode_is_not_judged(policy, tmp_path) -> None:
    """Windows has no POSIX mode; absence of evidence is not a finding."""
    ledger = _write_ledger(tmp_path, {
        "certs": [_cert(spki="aa")],
        "keys": [_key("aa", mode=None, path="k.pem")],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    assert not by_code(payload, "PERMISSION_TOO_OPEN")


def test_truststore_with_a_private_key_fires(policy, tmp_path) -> None:
    """A key inside a trust store is the mixed-purpose container (plan/03 §⑤)."""
    ledger = _write_ledger(tmp_path, {
        "certs": [],
        "keys": [],
        "containers": [{
            "path": "mixed.p12",
            "format": "pkcs12",
            "password": "set",
            "has_private_key": True,
            "entries": [
                {"alias": "key-entry", "entry_type": "privateKey"},
                {"alias": "trusted-only", "entry_type": "trustedCert"},
            ],
        }],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    assert len(by_code(payload, "CONTAINER_TRUSTSTORE_WITH_KEY")) == 1


def test_an_empty_password_container_fires(policy, tmp_path) -> None:
    ledger = _write_ledger(tmp_path, {
        "certs": [], "keys": [],
        "containers": [{
            "path": "empty-pass.p12", "format": "pkcs12", "password": "empty",
            "has_private_key": True,
            "entries": [{"alias": "empty-pass", "entry_type": "privateKey"}],
        }],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    assert len(by_code(payload, "CONTAINER_EMPTY_PASSWORD")) == 1
    # A trust store holding only a key is not "mixed"; only one rule may fire.
    assert not by_code(payload, "CONTAINER_TRUSTSTORE_WITH_KEY")


def test_an_unreadable_container_is_reported_not_guessed(policy, tmp_path) -> None:
    """``CONTAINER_UNREADABLE`` must not turn into "this container is clean"."""
    ledger = _write_ledger(tmp_path, {
        "certs": [], "keys": [],
        "containers": [{"path": "x.jks", "format": "jks", "unreadable": "keytool 缺失"}],
    })
    payload = evaluate(
        roots=[], files=[], inventory_path=ledger,
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    unreadable = by_code(payload, "CONTAINER_UNREADABLE")
    assert len(unreadable) == 1
    assert unreadable[0]["evidence"]["reason"] == "keytool 缺失"


def test_two_alias_in_one_container_is_one_duplicate_not_two_sources(policy, tmp_path) -> None:
    """Two aliases for one certificate is a duplicate — the truth case's shape.

    Built from the real containment relation rather than by copying a file: one
    ``certs[]`` record whose ``sources[]`` names two aliases in one container.
    """
    cert = _cert(sources=0)
    cert["sources"] = [
        {"kind": "container", "path": "multi-alias.p12", "container_format": "pkcs12",
         "alias": "multi-alias-primary", "posix_mode": None},
        {"kind": "container", "path": "multi-alias.p12", "container_format": "pkcs12",
         "alias": "multi-alias-secondary", "posix_mode": None},
    ]
    payload = evaluate(
        roots=[], files=[],
        inventory_path=_write_ledger(tmp_path, {"certs": [cert], "keys": []}),
        as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
    )
    duplicates = by_code(payload, "DUPLICATE_CERT")
    assert len(duplicates) == 1
    assert len(duplicates[0]["evidence"]["paths"]) == 2
    # And nothing pairs it, so the same record is an orphan too.
    assert len(by_code(payload, "ORPHAN_CERT")) == 1


# ── local helpers ───────────────────────────────────────────────────────────


def _cert(
    *,
    fingerprint: str = "f" * 64,
    spki: str = "s" * 64,
    algo: str = "rsa",
    bits: int | None = 2048,
    sig_algo: str = "1.2.840.113549.1.1.11",
    not_after: str = "2031-03-17T17:46:40Z",
    sources: int = 1,
) -> dict:
    return {
        "fingerprint_sha256": fingerprint,
        "spki_sha256": spki,
        "subject": {"display": "CN=test", "der_sha256": "d" * 64},
        "issuer": {"display": "CN=root", "der_sha256": "e" * 64},
        "san": {"dns": [], "ip": [], "email": [], "uri": []},
        "not_before": "2029-03-17T17:46:40Z",
        "not_after": not_after,
        "key_algo": algo,
        "key_bits": bits,
        "curve": None,
        "sig_algo": sig_algo,
        "key_usage": [],
        "extended_key_usage": [],
        "is_ca": False,
        "subject_key_id": None,
        "sources": [
            {"kind": "file", "path": f"c{index}.pem", "posix_mode": None}
            for index in range(sources)
        ],
    }


def _key(spki: str, *, mode: str | None, path: str) -> dict:
    return {
        "spki_sha256": spki,
        "key_algo": "rsa",
        "key_bits": 2048,
        "curve": None,
        "encrypted": False,
        "paired_cert_fingerprint": None,
        "sources": [{"kind": "file", "path": path, "posix_mode": mode}],
    }


def _write_ledger(directory: Path, body: dict) -> str:
    """Write a minimal ledger document and return its path.

    Built by hand rather than through ``inventory.build`` so the rules can be
    exercised on shapes the fixtures do not contain (a locked key, an
    unparseable date, a diagnostic, a container table). The shape is the one
    ``plan/03`` §② fixes, plus the ``containers[]`` section the container view
    will fill in.
    """
    payload = {
        "schema_version": 1,
        "kind": "inventory",
        "certs": body.get("certs", []),
        "keys": body.get("keys", []),
        "diagnostics": body.get("diagnostics", []),
        "containers": body.get("containers", []),
        "summary": {},
    }
    path = directory / "ledger.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return str(path)
