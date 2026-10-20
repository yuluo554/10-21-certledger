"""Record model: key order, sorting, and the byte-identical serialization contract."""

from __future__ import annotations

import json

from certledger.model import (
    CertRecord,
    Diagnostic,
    Finding,
    KeyRecord,
    Source,
    dump_json,
    sorted_findings,
)


def make_source(kind: str, path: str, alias: str | None = None) -> Source:
    return Source(kind=kind, path=path, alias=alias)


def test_cert_key_order_is_declared_not_alphabetical() -> None:
    cert = CertRecord(
        fingerprint_sha256="aa",
        spki_sha256="bb",
        subject="CN=a",
        issuer="CN=root",
    )
    keys = list(cert.to_dict())
    assert keys[:3] == ["fingerprint_sha256", "spki_sha256", "subject"]
    assert keys[-1] == "sources"


def test_sources_are_sorted_by_kind_then_path_then_alias() -> None:
    cert = CertRecord(
        fingerprint_sha256="aa",
        spki_sha256="bb",
        subject="CN=a",
        issuer="CN=root",
        sources=(
            make_source("store", "z"),
            make_source("container", "m", "alias-b"),
            make_source("file", "b"),
            make_source("container", "m", "alias-a"),
            make_source("file", "a"),
        ),
    )
    paths = [(s["kind"], s["path"], s["alias"]) for s in cert.to_dict()["sources"]]
    assert paths == [
        ("file", "a", None),
        ("file", "b", None),
        ("container", "m", "alias-a"),
        ("container", "m", "alias-b"),
        ("store", "z", None),
    ]


def test_findings_sort_by_severity_code_subject_fingerprint() -> None:
    findings = [
        Finding("WEAK_KEY", "WARN", "CN=b", "ff", {}, "NIST"),
        Finding("EXPIRED", "ERROR", "CN=b", "aa", {}, "RFC 5280"),
        Finding("EXPIRED", "ERROR", "CN=a", "zz", {}, "RFC 5280"),
        Finding("EXPIRED", "ERROR", "CN=b", "aa", {}, "RFC 5280"),
        Finding("ORPHAN_KEY", "INFO", "CN=a", "aa", {}, "本项目定义"),
    ]
    ordered = [(f.severity, f.code, f.subject, f.fingerprint) for f in sorted_findings(findings)]
    assert ordered[0] == ("ERROR", "EXPIRED", "CN=a", "zz")
    assert ordered[1] == ("ERROR", "EXPIRED", "CN=b", "aa")
    assert ordered[2] == ("ERROR", "EXPIRED", "CN=b", "aa")
    assert ordered[3] == ("WARN", "WEAK_KEY", "CN=b", "ff")
    assert ordered[-1][1] == "ORPHAN_KEY"


def test_dump_json_is_byte_identical_across_calls() -> None:
    payload = {
        "schema_version": 1,
        "certs": [
            CertRecord("aa", "bb", "CN=a", "CN=root", sources=(make_source("file", "x"),)).to_dict()
        ],
        "keys": [KeyRecord("bb", "rsa", 2048, None, False, "aa").to_dict()],
        "diagnostics": [Diagnostic("PARSE_FAILED", "x.der", "der").to_dict()],
    }
    first = dump_json(payload)
    second = dump_json(payload)
    assert first == second
    assert first.endswith("\n") and not first.endswith("\n\n")


def test_dump_json_keeps_non_ascii_readable() -> None:
    text = dump_json({"subject": "CN=测试"})
    assert "CN=测试" in text  # ensure_ascii=False
    assert json.loads(text)["subject"] == "CN=测试"


def test_verbose_fields_absent_from_records() -> None:
    """No host name, user name or parse timestamp may enter a record (D9)."""
    cert = CertRecord("aa", "bb", "CN=a", "CN=root").to_dict()
    forbidden = {"host", "hostname", "user", "username", "scanned_at", "parsed_at", "timestamp"}
    assert forbidden.isdisjoint(cert)
    assert forbidden.isdisjoint(KeyRecord("bb").to_dict())
