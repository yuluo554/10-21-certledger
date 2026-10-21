"""Hygiene rules over the ledger: the judgement layer.

``inventory`` decides what *is*; this module decides what follows from it. The
separation is deliberate and load-bearing: the ledger is a fact table that can
be stored, diffed and replayed, while a finding is an opinion with a citation,
a severity and an ``--as-of``. Keeping them in different modules is what makes
``--inventory <path>`` a real feature — the same stored ledger evaluated against
a different policy or a different instant yields a different report without
reading the filesystem again.

Four rules govern everything below:

1. **Every finding cites a source.** ``rule_source`` comes from the policy
   block that owns the threshold (``plan/03`` §③). A judgement with no citation
   is not allowed into the rule set, and the loader refuses a policy whose
   ``source`` is empty or unshaped (K3).

2. **No threshold is written in code.** Windows, bit sizes, curve lists, the
   cliff count, the severities themselves and the "off" switch all come from
   the policy document. Changing the JSON changes the verdict; changing this
   module does not.

3. **"Not looked at" is a finding too.** Every ledger diagnostic
   (``PARSE_FAILED`` / ``PARSE_UNSUPPORTED`` / ``SOURCE_UNAVAILABLE`` /
   ``SKIP_*``) becomes a finding. A report that lists only what was found
   cannot be told apart from a report over a machine that was never read
   (``plan/03`` §⑥).

4. **No invented facts.** A certificate whose key this build cannot decode
   (``key_algo == ""``) is not called weak; a locked key with no SPKI is not
   called an orphan; a record whose ``not_after`` will not parse is not called
   expired. Each of those would be an assertion the data does not support.

Key-side findings carry the **SPKI hash** in ``fingerprint`` (a private key has
no certificate fingerprint) and an empty string when even that is unknown
(encrypted key without a passphrase). Certificate-side findings carry the DER
fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from certledger.errors import CliError
from certledger.model import LEDGER_KIND, SCHEMA_VERSION, Finding, sorted_findings
from certledger.timebase import AsOf, add_days, format_utc, parse_stamp

#: The block that grades failure codes (``plan/03`` §⑥ 失败路径总表).
DIAGNOSTICS_BLOCK = "hygiene.diagnostics"

#: Fixed wording for the NIST 2031 transition (plan/01 §1.5, D3). The statement
#: lives in the policy file so the *text* is data too; this constant is only the
#: fallback name used when building the evidence payload.
NIST_2031_EVIDENCE_KEY = "statement"


def evaluate(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    inventory_path: str | None,
    as_of: AsOf,
    policy,
    source: str,
    ledger: dict | None = None,
) -> dict:
    """Apply the rule set to one ledger and return the finding document.

    ``as_of`` is mandatory (K2): there is no branch that reads the wall clock.
    The ledger comes either from ``inventory_path`` (a stored document) or from
    one fresh ``inventory.build()`` pass over ``roots``/``files``/the system
    store — never both, and never a mixture that could describe two machines.

    ``ledger`` is the third, in-memory form, used by the report pipeline so that
    one command reads the machine **once**: it evaluates a ledger that was just
    built instead of building a second one, which could disagree with the first
    over a file that changed, or merely over a container that opened the first
    time. Passing it together with a path or a root is refused rather than
    resolved — a silent choice between two machines is exactly the failure this
    module's single-ledger rule exists to prevent.
    """
    if policy is None:
        raise CliError("策略缺失", "hygiene 需要已加载的策略文件（阈值不设代码默认值）")
    if as_of is None:
        raise CliError(
            "--as-of 必填",
            "该工具没有「当前时间」缺省值；请给出 Unix 秒或带时区的 ISO-8601 时刻",
        )
    if ledger is not None and (inventory_path or roots or files):
        raise CliError(
            "台账来源冲突",
            "已在内存中给出台账，不得同时再给 --inventory / --roots / --files"
            "——一份台账只能描述一台机器",
        )

    if ledger is None:
        ledger = _load_ledger(
            roots=roots,
            files=files,
            inventory_path=inventory_path,
            policy=policy,
            source=source,
        )
    rules = RuleSet(policy)

    certs = [item for item in ledger.get("certs", []) if isinstance(item, dict)]
    keys = [item for item in ledger.get("keys", []) if isinstance(item, dict)]
    diagnostics = [item for item in ledger.get("diagnostics", []) if isinstance(item, dict)]
    containers = [item for item in ledger.get("containers", []) if isinstance(item, dict)]

    _expiry_rules(rules, certs, as_of)
    _cliff_rule(rules, certs, as_of)
    _strength_rules(rules, certs)
    _key_hygiene_rules(rules, keys)
    _pairing_rules(rules, certs, keys)
    _duplicate_rules(rules, certs, keys)
    _container_rules(rules, containers)
    _diagnostic_rules(rules, diagnostics)

    findings = sorted_findings(rules.findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "hygiene",
        "as_of": as_of.raw,
        "as_of_utc": as_of.iso,
        "policy_version": policy.version,
        "policy_sha256": policy.sha256,
        "findings": [finding.to_dict() for finding in findings],
        "summary": _summary(findings, rules, certs, keys, diagnostics),
    }


# ── the ledger input ────────────────────────────────────────────────────────


def _load_ledger(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    inventory_path: str | None,
    policy,
    source: str,
) -> dict:
    """A stored ledger, or one built now. Never a silent empty fallback.

    A missing or malformed ``--inventory`` file is an input error (exit 2), not
    an empty ledger: "the file you pointed at does not exist" and "this machine
    holds no certificates" must not look the same.
    """
    if inventory_path:
        return _read_ledger(inventory_path)

    from certledger.inventory import build

    return build(
        roots=roots,
        files=files,
        source=source,
        follow_symlinks=None,
        policy=policy,
    )


def _read_ledger(path: str) -> dict:
    """Delegate to :func:`inventory.read_ledger` — one definition of a ledger.

    Kept as a name here because the error contract (which sentences carry which
    exit) is asserted through this module's behaviour, and an alias makes that
    continuity explicit rather than accidental.
    """
    from certledger.inventory import read_ledger

    return read_ledger(path)


# ── rule bookkeeping ────────────────────────────────────────────────────────


@dataclass(slots=True)
class RuleSet:
    """Reads severities from the policy and accumulates findings.

    ``emit`` is the single door a finding comes through, so "did this rule have
    a citation?" and "was this rule switched off?" are answered in exactly one
    place. A rule set to ``level: off`` produces nothing and is counted in
    ``summary.suppressed`` — switching a rule off must leave a trace, otherwise
    a quiet report cannot be distinguished from a clean one.
    """

    policy: Any
    findings: list[Finding] = None  # type: ignore[assignment]
    suppressed: dict[str, int] = None  # type: ignore[assignment]
    counts_by_rule: dict[str, int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.findings = []
        self.suppressed = {}
        self.counts_by_rule = {}

    def level(self, block: str) -> str:
        return str(self.policy.require(f"{block}.level"))

    def source(self, block: str) -> str:
        return str(self.policy.require(f"{block}.source"))

    def emit(
        self,
        *,
        block: str,
        code: str,
        subject: str,
        fingerprint: str,
        evidence: dict[str, Any],
    ) -> None:
        self._record(
            block=block,
            code=code,
            level=self.level(block),
            citation=self.source(block),
            subject=subject,
            fingerprint=fingerprint,
            evidence=evidence,
        )

    def emit_failure(self, *, code: str, evidence: dict[str, Any]) -> None:
        """A collector/container failure code, graded by the diagnostics block.

        The code vocabulary is open (new ``SKIP_*`` codes appear as the walker
        grows), so the severity is looked up per code with a declared default.
        An unlisted code therefore inherits the *documented* default rather than
        an accidental silence — and the default sits in a data file a reviewer
        can see.
        """
        block = DIAGNOSTICS_BLOCK
        level = str(self.policy.get(f"{block}.codes.{code}", self.policy.require(f"{block}.default")))
        self._record(
            block=block,
            code=code,
            level=level,
            citation=self.source(block),
            subject="",
            fingerprint="",
            evidence=evidence,
        )

    def _record(
        self,
        *,
        block: str,
        code: str,
        level: str,
        citation: str,
        subject: str,
        fingerprint: str,
        evidence: dict[str, Any],
    ) -> None:
        if level == "off":
            self.suppressed[code] = self.suppressed.get(code, 0) + 1
            return
        if not citation.strip():
            # Unreachable through ``load_policy`` — the loader rejects it first.
            # Kept as a hard stop because this module is also imported directly
            # by tests and by any future caller that builds a Policy by hand.
            raise CliError("阈值缺出处", f"{block}.source 为空——无出处的判据不得进入规则集")
        self.counts_by_rule[block] = self.counts_by_rule.get(block, 0) + 1
        self.findings.append(
            Finding(
                code=code,
                severity=level,
                subject=subject,
                fingerprint=fingerprint,
                evidence=evidence,
                rule_source=citation,
            )
        )


# ── 1. expiry ───────────────────────────────────────────────────────────────


def _expiry_rules(rules: RuleSet, certs: list[dict], as_of: AsOf) -> None:
    """``EXPIRED`` / ``EXPIRING`` against the pinned instant.

    ``not_after == as_of`` counts as still valid (``data/README`` §五.2): the
    boundary is written down once, here, because a boundary that moves with the
    caller's mood makes two reports over one machine disagree.
    """
    warn_days = int(rules.policy.require("hygiene.expiring.warn_days"))
    warn_end = add_days(as_of.seconds, warn_days)

    for cert in certs:
        not_after = parse_stamp(cert.get("not_after", ""))
        if not_after is None:
            continue  # an unparseable stamp is not evidence of expiry
        subject = _display(cert.get("subject"))
        fingerprint = str(cert.get("fingerprint_sha256", ""))
        if not_after < as_of.seconds:
            rules.emit(
                block="hygiene.expired",
                code="EXPIRED",
                subject=subject,
                fingerprint=fingerprint,
                evidence={
                    "not_after": cert["not_after"],
                    "as_of": as_of.iso,
                    "days_over": _days_over(as_of.seconds, not_after),
                },
            )
        elif not_after < warn_end:
            rules.emit(
                block="hygiene.expiring",
                code="EXPIRING",
                subject=subject,
                fingerprint=fingerprint,
                evidence={
                    "not_after": cert["not_after"],
                    "as_of": as_of.iso,
                    "days_left": _days_left(as_of.seconds, not_after),
                    "warn_days": warn_days,
                },
            )


def _days_over(as_of_seconds: int, not_after: int) -> int:
    """Whole days past expiry (floor: "0 days over" for anything under a day)."""
    return (as_of_seconds - not_after) // 86400


def _days_left(as_of_seconds: int, not_after: int) -> int:
    """Whole days remaining, rounded **up**: 20 hours left is "1 day", not "0"."""
    remaining = not_after - as_of_seconds
    return -((-remaining) // 86400)


# ── 2. expiry cliff ─────────────────────────────────────────────────────────


def _cliff_rule(rules: RuleSet, certs: list[dict], as_of: AsOf) -> None:
    """``EXPIRY_CLIFF``: many distinct certificates expiring in one window.

    Counted by **unique fingerprint**, not by record or by source: three copies
    of one certificate are one renewal, and counting copies would make a
    backup directory look like a crisis (``data/README`` §五.3).
    """
    window_days = int(rules.policy.require("hygiene.cliff.window_days"))
    min_count = int(rules.policy.require("hygiene.cliff.min_count"))
    window_end = add_days(as_of.seconds, window_days)

    expiring: dict[str, dict] = {}
    for cert in certs:
        not_after = parse_stamp(cert.get("not_after", ""))
        if not_after is None:
            continue
        if as_of.seconds <= not_after < window_end:
            expiring[str(cert.get("fingerprint_sha256", ""))] = cert

    if len(expiring) < min_count:
        return

    rules.emit(
        block="hygiene.cliff",
        code="EXPIRY_CLIFF",
        subject="",
        fingerprint="",
        evidence={
            "window_start": as_of.iso,
            "window_end": format_utc(window_end),
            "window_days": window_days,
            "min_count": min_count,
            "count": len(expiring),
            "fingerprints": sorted(expiring),
        },
    )


# ── 3./4./5. strength ───────────────────────────────────────────────────────


def _strength_rules(rules: RuleSet, certs: list[dict]) -> None:
    """``WEAK_KEY`` / ``WEAK_SIG`` / ``POLICY_NIST_2031`` (per certificate)."""
    rsa_min = int(rules.policy.require("hygiene.weak_key.rsa.min_bits"))
    allowed_curves = list(rules.policy.require("hygiene.weak_key.ec.allowed_curves"))
    forbidden = [
        digest.lower()
        for digest in rules.policy.require("hygiene.weak_sig.forbidden_digests")
    ]
    nist_enabled = bool(rules.policy.require("hygiene.nist_2031.enabled"))
    nist_bits = int(rules.policy.require("hygiene.nist_2031.bits"))
    nist_statement = str(rules.policy.get("hygiene.nist_2031.statement", ""))

    for cert in certs:
        subject = _display(cert.get("subject"))
        fingerprint = str(cert.get("fingerprint_sha256", ""))
        algo = str(cert.get("key_algo", ""))
        bits = cert.get("key_bits")
        curve = cert.get("curve")

        if algo == "rsa" and isinstance(bits, int) and bits < rsa_min:
            rules.emit(
                block="hygiene.weak_key.rsa",
                code="WEAK_KEY",
                subject=subject,
                fingerprint=fingerprint,
                evidence={"key_algo": "rsa", "key_bits": bits, "min_bits": rsa_min},
            )
        elif algo == "ec" and curve is not None and curve not in allowed_curves:
            rules.emit(
                block="hygiene.weak_key.ec",
                code="WEAK_KEY",
                subject=subject,
                fingerprint=fingerprint,
                evidence={
                    "key_algo": "ec",
                    "curve": curve,
                    "allowed_curves": allowed_curves,
                },
            )
        # ``algo == ""`` is a key this build of ``cryptography`` cannot decode
        # (measured: 1 of 81 real store certificates). It is not weak, it is
        # unread — calling it weak would be an invented judgement.

        digest_name = _signature_name(cert.get("sig_algo", ""))
        matched = next((name for name in forbidden if name in digest_name), None)
        if matched is not None:
            rules.emit(
                block="hygiene.weak_sig",
                code="WEAK_SIG",
                subject=subject,
                fingerprint=fingerprint,
                evidence={
                    "sig_algo": cert.get("sig_algo", ""),
                    "sig_algo_name": digest_name,
                    "forbidden_digests": forbidden,
                },
            )

        if nist_enabled and algo == "rsa" and bits == nist_bits:
            rules.emit(
                block="hygiene.nist_2031",
                code="POLICY_NIST_2031",
                subject=subject,
                fingerprint=fingerprint,
                evidence={
                    "key_algo": "rsa",
                    "key_bits": bits,
                    NIST_2031_EVIDENCE_KEY: nist_statement,
                },
            )


def _signature_name(dotted: str) -> str:
    """The algorithm's short name, lower-cased; the dotted form when unnamed.

    ``inventory`` stores ``sig_algo`` as a **dotted OID** (``plan/03`` §② wants
    the name, but the name is only reachable through ``ObjectIdentifier._name``
    — a private attribute — so the stable spelling was stored instead). The
    policy lists digest *names* (``sha1``/``md5``), which are exactly the
    substrings those short names contain.

    An OID this build has no name for yields the dotted string, which matches no
    digest name and therefore produces no finding: unknown is not weak.
    """
    if not dotted:
        return ""
    try:
        from cryptography.x509.oid import ObjectIdentifier

        name = getattr(ObjectIdentifier(dotted), "_name", None)
    except (ValueError, TypeError):  # not an OID at all
        name = None
    return str(name or dotted).lower()


# ── 6. private key hygiene ──────────────────────────────────────────────────


def _key_hygiene_rules(rules: RuleSet, keys: list[dict]) -> None:
    """``PRIVATE_KEY_UNENCRYPTED`` / ``PERMISSION_TOO_OPEN``.

    The permission check compares the recorded mode against the policy's
    ``max_posix_mode`` as a bit mask, so the policy states the *permitted* set
    once and the code derives "too open" from it. A record with no recorded mode
    (Windows, or a store entry) yields no finding: there is no POSIX mode to
    judge, and inventing one would flag every key on such a machine.
    """
    permitted = int(str(rules.policy.require("hygiene.permissions.max_posix_mode")), 8)

    for key in keys:
        spki = key.get("spki_sha256") or ""
        encrypted = bool(key.get("encrypted", False))
        if not encrypted:
            rules.emit(
                block="hygiene.private_key",
                code="PRIVATE_KEY_UNENCRYPTED",
                subject="",
                fingerprint=spki,
                evidence={"encrypted": False, "sources": len(key.get("sources") or [])},
            )

        for item in key.get("sources") or []:
            if not isinstance(item, dict):
                continue
            mode = item.get("posix_mode")
            if not mode:
                continue
            actual = int(str(mode), 8)
            if actual & ~permitted & 0o777:
                rules.emit(
                    block="hygiene.permissions",
                    code="PERMISSION_TOO_OPEN",
                    subject="",
                    fingerprint=spki,
                    evidence={
                        "path": item.get("path", ""),
                        "posix_mode": str(mode),
                        "max_posix_mode": str(rules.policy.require("hygiene.permissions.max_posix_mode")),
                    },
                )


# ── 7. orphans ──────────────────────────────────────────────────────────────


def _pairing_rules(rules: RuleSet, certs: list[dict], keys: list[dict]) -> None:
    """``ORPHAN_CERT`` / ``ORPHAN_KEY`` — read straight off the ledger.

    The ledger already contains the pairing decision (``spki_sha256`` on both
    sides, K4); re-deciding it here would give the tool two pairing rules that
    can disagree. A locked key (``spki_sha256 is None``) is **not** an orphan:
    without its SPKI there is no basis for saying it has no certificate, and
    "we could not check" is not "it is missing".
    """
    key_spkis = {key["spki_sha256"] for key in keys if key.get("spki_sha256")}
    cert_spkis = {cert["spki_sha256"] for cert in certs if cert.get("spki_sha256")}

    for cert in certs:
        spki = cert.get("spki_sha256") or ""
        if not spki:
            continue  # no SPKI means no pairing claim can be made either way
        if spki not in key_spkis:
            rules.emit(
                block="hygiene.orphans",
                code="ORPHAN_CERT",
                subject=_display(cert.get("subject")),
                fingerprint=str(cert.get("fingerprint_sha256", "")),
                evidence={"spki_sha256": spki, "paired": False},
            )

    for key in keys:
        spki = key.get("spki_sha256")
        if not spki:
            continue  # locked key: unknown SPKI, no orphan claim
        if spki not in cert_spkis:
            rules.emit(
                block="hygiene.orphans",
                code="ORPHAN_KEY",
                subject="",
                fingerprint=spki,
                evidence={"spki_sha256": spki, "paired": False},
            )


# ── 8. duplicates ───────────────────────────────────────────────────────────


def _duplicate_rules(rules: RuleSet, certs: list[dict], keys: list[dict]) -> None:
    """``DUPLICATE_CERT`` / ``DUPLICATE_KEY``: one asset in several places.

    Not a security problem — an inventory problem. It is the fact that makes
    rotation hard: renewing one copy leaves the others stale, and nothing on the
    machine says which is authoritative. Hence ``INFO`` by default.
    """
    for cert in certs:
        sources = cert.get("sources") or []
        if len(sources) > 1:
            rules.emit(
                block="hygiene.duplicates",
                code="DUPLICATE_CERT",
                subject=_display(cert.get("subject")),
                fingerprint=str(cert.get("fingerprint_sha256", "")),
                evidence={
                    "sources": len(sources),
                    "paths": [item.get("path", "") for item in sources if isinstance(item, dict)],
                },
            )

    for key in keys:
        sources = key.get("sources") or []
        if len(sources) > 1:
            rules.emit(
                block="hygiene.duplicates",
                code="DUPLICATE_KEY",
                subject="",
                fingerprint=key.get("spki_sha256") or "",
                evidence={
                    "sources": len(sources),
                    "paths": [item.get("path", "") for item in sources if isinstance(item, dict)],
                },
            )


# ── 9. container signals ────────────────────────────────────────────────────


def _container_rules(rules: RuleSet, containers: list[dict]) -> None:
    """``CONTAINER_TRUSTSTORE_WITH_KEY`` / ``CONTAINER_EMPTY_PASSWORD``.

    Driven entirely by the ledger's ``containers[]`` section, which the
    container view fills in. When that section is absent — as it is while the
    container reader is still outstanding — the rules produce nothing rather
    than guessing, and the containers themselves stay visible through their
    ``PARSE_UNSUPPORTED`` diagnostics.
    """
    for container in containers:
        path = str(container.get("path", ""))
        entries = [item for item in container.get("entries") or [] if isinstance(item, dict)]
        unreadable = container.get("unreadable")

        if unreadable:
            rules.emit_failure(
                code="CONTAINER_UNREADABLE",
                evidence={"path": path, "reason": str(unreadable)},
            )
            continue

        has_key = bool(container.get("has_private_key")) or any(
            item.get("entry_type") == "privateKey" for item in entries
        )
        has_other = any(item.get("entry_type") != "privateKey" for item in entries)
        if has_key and has_other:
            rules.emit(
                block="hygiene.container_truststore",
                code="CONTAINER_TRUSTSTORE_WITH_KEY",
                subject="",
                fingerprint="",
                evidence={"path": path, "entries": len(entries)},
            )

        if container.get("password") == "empty":
            rules.emit(
                block="hygiene.container_password",
                code="CONTAINER_EMPTY_PASSWORD",
                subject="",
                fingerprint="",
                evidence={"path": path},
            )


# ── failure records become findings ─────────────────────────────────────────


def _diagnostic_rules(rules: RuleSet, diagnostics: list[dict]) -> None:
    """Every ledger diagnostic becomes a finding, with a policy-set severity.

    Without this, a report over a directory the tool could not read would look
    exactly like a clean directory. The severity mapping lives in the policy
    (``hygiene.diagnostics``) with a declared ``default``, so a newly introduced
    collector code cannot inherit an accidental silence: it inherits the
    documented default, and the default is a reviewable line in a data file.
    """
    for item in diagnostics:
        code = str(item.get("code", ""))
        if not code:
            continue
        rules.emit_failure(
            code=code,
            evidence={
                "path": item.get("path", ""),
                "stage": item.get("stage", ""),
                "detail": item.get("detail", ""),
            },
        )


# ── shared helpers ──────────────────────────────────────────────────────────


def _display(subject: Any) -> str:
    """``subject.display`` from the ledger's ``{display, der_sha256}`` pair."""
    if isinstance(subject, dict):
        return str(subject.get("display", ""))
    return str(subject or "")


def _summary(
    findings: list[Finding],
    rules: RuleSet,
    certs: list[dict],
    keys: list[dict],
    diagnostics: list[dict],
) -> dict[str, Any]:
    """Counts with their units named — records and findings are not the same unit.

    ``records`` counts ledger rows, ``findings`` counts judgements, and one
    record can carry several findings (or none). The only relation the design
    asserts is a set partition: every finding names at least one record or one
    diagnostic, and every rule that could have fired is accounted for either in
    ``findings`` or in ``suppressed``.
    """
    by_severity = {"ERROR": 0, "WARN": 0, "INFO": 0}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    return {
        "records": {
            "certs": len(certs),
            "keys": len(keys),
            "diagnostics": len(diagnostics),
        },
        "findings": len(findings),
        "by_severity": by_severity,
        "suppressed": sum(rules.suppressed.values()),
        "suppressed_by_code": dict(sorted(rules.suppressed.items())),
    }


__all__ = ["evaluate", "LEDGER_KIND"]
