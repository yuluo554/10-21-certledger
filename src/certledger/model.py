"""The single record model for the whole tool.

Everything downstream (hygiene, report, baseline diff) reads these structures,
and every rendering goes through :func:`dump_report` / :func:`dump_inventory`.
JSON key order is fixed by construction (explicit dict literals, no
``sort_keys``) — a byte-identical second run is a hard requirement.

No field in here may carry a host name, a user name, or a parse timestamp
(plan/00 D9).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

SCHEMA_VERSION = 1

#: Finding severities, in report order (lower = more severe).
SEVERITY_ORDER = {"ERROR": 0, "WARN": 1, "INFO": 2}

#: Source kinds; ``sources[]`` is sorted by this rank before path/alias.
SOURCE_KIND_ORDER = {"file": 0, "container": 1, "store": 2}


@dataclass(frozen=True, slots=True)
class Source:
    kind: str
    path: str
    container_format: str | None = None
    alias: str | None = None
    entry_type: str | None = None
    store_name: str | None = None

    def sort_key(self) -> tuple[int, str, str]:
        return (
            SOURCE_KIND_ORDER.get(self.kind, 99),
            self.path,
            self.alias or "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "container_format": self.container_format,
            "alias": self.alias,
            "entry_type": self.entry_type,
            "store_name": self.store_name,
        }


@dataclass(frozen=True, slots=True)
class CertRecord:
    fingerprint_sha256: str
    spki_sha256: str
    subject: str
    issuer: str
    san_dns: tuple[str, ...] = ()
    san_ip: tuple[str, ...] = ()
    san_email: tuple[str, ...] = ()
    san_uri: tuple[str, ...] = ()
    not_before: str = ""
    not_after: str = ""
    key_algo: str = ""
    key_bits: int | None = None
    curve: str | None = None
    sig_algo: str = ""
    key_usage: tuple[str, ...] = ()
    extended_key_usage: tuple[str, ...] = ()
    is_ca: bool = False
    subject_key_id: str | None = None
    sources: tuple[Source, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint_sha256": self.fingerprint_sha256,
            "spki_sha256": self.spki_sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "san": {
                "dns": list(self.san_dns),
                "ip": list(self.san_ip),
                "email": list(self.san_email),
                "uri": list(self.san_uri),
            },
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key_algo": self.key_algo,
            "key_bits": self.key_bits,
            "curve": self.curve,
            "sig_algo": self.sig_algo,
            "key_usage": list(self.key_usage),
            "extended_key_usage": list(self.extended_key_usage),
            "is_ca": self.is_ca,
            "subject_key_id": self.subject_key_id,
            "sources": [source.to_dict() for source in sorted(self.sources, key=Source.sort_key)],
        }


@dataclass(frozen=True, slots=True)
class KeyRecord:
    spki_sha256: str | None
    key_algo: str = ""
    key_bits: int | None = None
    curve: str | None = None
    encrypted: bool = False
    paired_cert_fingerprint: str | None = None
    sources: tuple[Source, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "spki_sha256": self.spki_sha256,
            "key_algo": self.key_algo,
            "key_bits": self.key_bits,
            "curve": self.curve,
            "encrypted": self.encrypted,
            "paired_cert_fingerprint": self.paired_cert_fingerprint,
            "sources": [source.to_dict() for source in sorted(self.sources, key=Source.sort_key)],
        }


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    path: str
    stage: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "path": self.path, "stage": self.stage, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: str
    subject: str
    fingerprint: str
    evidence: dict[str, Any] = field(default_factory=dict)
    rule_source: str = ""

    def sort_key(self) -> tuple[int, str, str, str]:
        return (
            SEVERITY_ORDER.get(self.severity, 99),
            self.code,
            self.subject,
            self.fingerprint,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "subject": self.subject,
            "fingerprint": self.fingerprint,
            "evidence": self.evidence,
            "rule_source": self.rule_source,
        }


def sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Stable order for both JSON and Markdown output (plan/01 §四, §五.9)."""
    return sorted(findings, key=Finding.sort_key)


def dump_json(payload: dict[str, Any]) -> str:
    """Canonical JSON: declared key order, UTF-8, two-space indent, trailing LF.

    ``indent=2`` (rather than compact) because the JSON is meant to be read in a
    diff or a ticket; determinism comes from the fixed key order, not from the
    absence of whitespace.
    """
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
