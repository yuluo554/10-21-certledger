"""Strength policy: citation required, severity from the policy, no fact errors.

Three claims are under test here, and each exists because the obvious
alternative produces a report that is wrong in a way a reader would trust:

1. **The number is configurable and the consequence follows it.** The same
   fixture, evaluated under two policies, must reach different verdicts. If a
   threshold change cannot flip a severity, the "policy file" is decoration.
2. **The citation is required.** A rule with no source cannot be switched on.
   The loader already refuses such a policy; this file asserts the engine also
   refuses to emit a finding with an empty ``rule_source``.
3. **The NIST wording is exact.** ``POLICY_NIST_2031`` describes a 2031
   transition, not a weakness today. Writing "RSA 2048 is weak" is a factual
   error that manufactures false alarms in real environments (``plan/00`` D3),
   so the banned phrasings are asserted, not just the required one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from certledger.hygiene import evaluate
from certledger.policy.loader import load_policy
from certledger.timebase import parse_as_of

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "out"
AS_OF = 1_900_000_000

_HAVE_ARTIFACTS = pytest.mark.skipif(
    not OUT.is_dir(), reason="fixtures/out 不存在：样本按需生成，不入库"
)


def variant_policy(tmp_path: Path, mutate) -> object:
    """Write a policy derived from the bundled one and load it back.

    Going through the loader (rather than editing a dict in memory) is the
    point: a variant that the loader would reject is not a policy a user could
    run, so testing with it would prove nothing.
    """
    data = json.loads(load_policy().raw)
    mutate(data)
    path = tmp_path / "variant.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return load_policy(path)


def run(case: str, policy, files: list[str] | None = None) -> dict:
    return evaluate(
        roots=[],
        files=[str(OUT / item) for item in (files or [])],
        inventory_path=None,
        as_of=parse_as_of(str(AS_OF)),
        policy=policy,
        source="none",
    )


def findings(payload: dict, code: str) -> list[dict]:
    return [item for item in payload["findings"] if item["code"] == code]


# ── ① a threshold change flips the verdict ─────────────────────────────────


@_HAVE_ARTIFACTS
def test_raising_the_rsa_minimum_turns_healthy_into_weak(tmp_path) -> None:
    """The same certificate, two policies, two conclusions.

    ``healthy`` is RSA 2048 and sits exactly on the default minimum, so raising
    the minimum to 4096 must make it weak. This is the test that proves the
    threshold is read rather than memorised.
    """
    files = ["healthy/healthy.pem", "healthy/healthy.key"]
    baseline = run("healthy", load_policy(), files)
    assert not findings(baseline, "WEAK_KEY")

    strict = variant_policy(
        tmp_path, lambda data: data["hygiene"]["weak_key"]["rsa"].__setitem__("min_bits", 4096)
    )
    raised = run("healthy", strict, files)
    weak = findings(raised, "WEAK_KEY")
    assert len(weak) == 1
    assert weak[0]["evidence"]["min_bits"] == 4096
    assert weak[0]["evidence"]["key_bits"] == 2048


@_HAVE_ARTIFACTS
def test_lowering_the_rsa_minimum_silences_the_weak_key_case(tmp_path) -> None:
    """And the reverse direction: 1024 is acceptable if the policy says so.

    Without this direction a rule could be "always warn about RSA < 2048"
    written as a literal and still pass the test above.
    """
    files = ["weak-key/weak-key.pem", "weak-key/weak-key.key"]
    assert findings(run("weak-key", load_policy(), files), "WEAK_KEY")

    relaxed = variant_policy(
        tmp_path, lambda data: data["hygiene"]["weak_key"]["rsa"].__setitem__("min_bits", 1024)
    )
    assert not findings(run("weak-key", relaxed, files), "WEAK_KEY")


@_HAVE_ARTIFACTS
def test_severity_comes_from_the_policy_not_from_the_code(tmp_path) -> None:
    """A ``WARN`` rule can be promoted to ``ERROR`` without touching code.

    The finding keeps its code and evidence; only the severity — the thing that
    decides whether a build fails — moves.
    """
    files = ["weak-key/weak-key.pem", "weak-key/weak-key.key"]
    assert findings(run("weak-key", load_policy(), files), "WEAK_KEY")[0]["severity"] == "WARN"

    promoted = variant_policy(
        tmp_path, lambda data: data["hygiene"]["weak_key"]["rsa"].__setitem__("level", "ERROR")
    )
    finding = findings(run("weak-key", promoted, files), "WEAK_KEY")[0]
    assert finding["severity"] == "ERROR"


@_HAVE_ARTIFACTS
def test_the_expiry_window_length_is_configurable(tmp_path) -> None:
    """``warn_days`` widens or narrows ``EXPIRING`` — the truth file's 30 is data."""
    files = ["healthy/healthy.pem"]
    assert not findings(run("healthy", load_policy(), files), "EXPIRING")

    wide = variant_policy(
        tmp_path, lambda data: data["hygiene"]["expiring"].__setitem__("warn_days", 2000)
    )
    assert findings(run("healthy", wide, files), "EXPIRING")


@_HAVE_ARTIFACTS
def test_the_forbidden_digest_list_is_configurable(tmp_path) -> None:
    """``WEAK_SIG`` follows the policy's list, not a hard-coded ``"sha1"``."""
    files = ["weak-sig/weak-sig.pem", "weak-sig/weak-sig.key"]
    assert findings(run("weak-sig", load_policy(), files), "WEAK_SIG")

    empty = variant_policy(
        tmp_path, lambda data: data["hygiene"]["weak_sig"].__setitem__("forbidden_digests", [])
    )
    assert not findings(run("weak-sig", empty, files), "WEAK_SIG")


@_HAVE_ARTIFACTS
def test_an_unlisted_curve_is_weak_only_if_the_policy_excludes_it(tmp_path) -> None:
    """ECDSA strength is a curve *membership* test, and the set is in the policy.

    The fixtures deliberately contain no ECDSA sample (M1 note 20), so this
    builds the ledger shape by hand — one record with an unusual curve, judged
    under the default policy and under one that permits it.
    """
    ledger = tmp_path / "ec.json"
    ledger.write_text(json.dumps({
        "schema_version": 1, "kind": "inventory", "certs": [_ec_cert("secp224r1")],
        "keys": [], "diagnostics": [], "summary": {},
    }, ensure_ascii=False), encoding="utf-8")

    def evaluate_with(policy) -> dict:
        return evaluate(
            roots=[], files=[], inventory_path=str(ledger),
            as_of=parse_as_of(str(AS_OF)), policy=policy, source="none",
        )

    assert findings(evaluate_with(load_policy()), "WEAK_KEY")

    permitting = variant_policy(
        tmp_path,
        lambda data: data["hygiene"]["weak_key"]["ec"].__setitem__(
            "allowed_curves", ["secp224r1"]
        ),
    )
    assert not findings(evaluate_with(permitting), "WEAK_KEY")


# ── ② every finding is cited ────────────────────────────────────────────────


@_HAVE_ARTIFACTS
def test_every_strength_finding_names_a_standard() -> None:
    """``WEAK_KEY`` / ``WEAK_SIG`` cite CA/B or NIST, not "because I said so"."""
    payload = run(
        "weak-key",
        load_policy(),
        ["weak-key/weak-key.pem", "weak-key/weak-key.key"],
    )
    for finding in findings(payload, "WEAK_KEY"):
        assert finding["rule_source"].startswith(("CA/B", "NIST", "SP 800")), finding


def test_the_engine_refuses_an_uncited_rule(tmp_path) -> None:
    """Belt and braces: even a policy built in memory cannot emit an uncited finding.

    The loader rejects an empty ``source`` first, so this path is normally
    unreachable — which is exactly why it is asserted: the engine must not rely
    on a *different* module having done the check.
    """
    from certledger.errors import CliError
    from certledger.policy.loader import Policy

    data = json.loads(load_policy().raw)
    data["hygiene"]["weak_key"]["rsa"]["source"] = ""
    hand_built = Policy(path=Path("memory.json"), raw=b"{}", data=data)

    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({
        "schema_version": 1, "kind": "inventory",
        "certs": [_ec_cert(None, algo="rsa", bits=1024)],
        "keys": [], "diagnostics": [], "summary": {},
    }, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(CliError) as error:
        evaluate(
            roots=[], files=[], inventory_path=str(ledger),
            as_of=parse_as_of(str(AS_OF)), policy=hand_built, source="none",
        )
    assert "出处" in str(error.value)


def test_an_invalid_level_is_rejected_at_load_time(tmp_path) -> None:
    """A typo in a severity must fail loudly, not sort to the bottom of a report."""
    from certledger.errors import CliError

    data = json.loads(load_policy().raw)
    data["hygiene"]["weak_sig"]["level"] = "SEVERE"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(CliError) as error:
        load_policy(path)
    assert "level" in str(error.value)


def test_a_non_octal_mode_is_rejected_at_load_time(tmp_path) -> None:
    """``"640"`` is a mode; ``"abc"`` and ``640`` (a number) are not."""
    from certledger.errors import CliError

    for value in ("abc", 640, "0o640", "6648"):
        data = json.loads(load_policy().raw)
        data["hygiene"]["permissions"]["max_posix_mode"] = value
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        with pytest.raises(CliError, match="max_posix_mode"):
            load_policy(path)


# ── ③ the NIST 2031 wording ────────────────────────────────────────────────


@_HAVE_ARTIFACTS
def test_nist_2031_is_off_by_default_and_says_why(tmp_path) -> None:
    """The rule is opt-in: RSA 2048 is acceptable today, so it cannot be a default alarm."""
    policy = load_policy()
    assert policy.get("hygiene.nist_2031.enabled") is False
    assert not findings(
        run("healthy", policy, ["healthy/healthy.pem"]), "POLICY_NIST_2031"
    )

    enabled = variant_policy(
        tmp_path, lambda data: data["hygiene"]["nist_2031"].__setitem__("enabled", True)
    )
    fired = findings(run("healthy", enabled, ["healthy/healthy.pem"]), "POLICY_NIST_2031")
    assert len(fired) == 1
    assert fired[0]["severity"] == "INFO", "the transition notice must not gate anything"


@_HAVE_ARTIFACTS
def test_nist_2031_text_says_2031_not_weak_today(tmp_path) -> None:
    """The exact wording matters: 2031 transition, not present-tense "weak".

    ``plan/01`` §1.5 and ``plan/00`` D3 both state the distinction, because the
    wrong phrasing makes the tool cry wolf over a configuration NIST still
    accepts for applying protection.
    """
    enabled = variant_policy(
        tmp_path, lambda data: data["hygiene"]["nist_2031"].__setitem__("enabled", True)
    )
    payload = run("healthy", enabled, ["healthy/healthy.pem"])
    finding = findings(payload, "POLICY_NIST_2031")[0]
    text = json.dumps(finding, ensure_ascii=False)

    assert "2031" in text
    assert "施加保护" in text
    for banned in ("已弱", "不再安全", "已失效", "不应使用", "insecure", "weak"):
        assert banned not in text, f"POLICY_NIST_2031 出现了「{banned}」类表述"


def test_the_policy_statement_is_the_single_wording_source() -> None:
    """The sentence lives in the policy file, so a reword is a data change.

    Keeping it in code would mean two places to edit (the policy a reviewer
    reads, and the string the tool prints) — and the copies drift.
    """
    statement = load_policy().get("hygiene.nist_2031.statement")
    assert isinstance(statement, str) and statement.strip()
    assert "2031" in statement
    assert "已弱" not in statement


def test_the_bundled_policy_cites_every_rule_block() -> None:
    """Every block the engine can read has a citation in the shipped file."""
    from certledger.policy.loader import DIAGNOSTICS_BLOCK, RULE_BLOCKS

    policy = load_policy()
    for block in RULE_BLOCKS + (DIAGNOSTICS_BLOCK,):
        source = policy.get(f"{block}.source")
        assert isinstance(source, str) and source.strip(), block


# ── local helpers ───────────────────────────────────────────────────────────


def _ec_cert(
    curve: str | None,
    *,
    algo: str = "ec",
    bits: int | None = None,
) -> dict:
    return {
        "fingerprint_sha256": "a" * 64,
        "spki_sha256": "b" * 64,
        "subject": {"display": "CN=ec", "der_sha256": "c" * 64},
        "issuer": {"display": "CN=root", "der_sha256": "d" * 64},
        "san": {"dns": [], "ip": [], "email": [], "uri": []},
        "not_before": "2029-03-17T17:46:40Z",
        "not_after": "2031-03-17T17:46:40Z",
        "key_algo": algo,
        "key_bits": bits,
        "curve": curve,
        "sig_algo": "1.2.840.10045.4.3.2",
        "key_usage": [],
        "extended_key_usage": [],
        "is_ca": False,
        "subject_key_id": None,
        "sources": [{"kind": "file", "path": "ec.pem", "posix_mode": None}],
    }
