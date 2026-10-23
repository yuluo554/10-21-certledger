"""The normalized ledger: one record per fingerprint, sources merged.

This is the layer where the collector's *stream* becomes a *table*. Three rules
decide what the table looks like, and each exists because the obvious
alternative produces a plausible wrong answer:

1. **Dedupe on the certificate's own DER hash, not on where it was found**
   (plan/03 §②, K1). The same CA certificate sitting in a bundle, in a
   PKCS#12 store and under ``/etc/ssl`` is one asset with three sources — not
   three assets. Counting files would make the ledger a directory listing.

2. **Pair keys to certificates on ``spki_sha256`` only** (K4). Not the file
   name (``server.crt`` is everywhere), not the subject (re-issuing under the
   same CN is routine — see the ``same-cn`` fixture), not the SKI (optional,
   and certificates in the wild reuse it). The SPKI is the one thing that is
   identical between a key and the certificate it belongs to and different
   everywhere else.

3. **Keep every source, sort them deterministically.** ``sources[]`` carries
   ``kind`` / ``path`` / ``alias``; two runs over one tree must produce the same
   bytes (plan/00 D9). Sorting is by ``Source.sort_key`` and the record list by
   fingerprint, so the output does not inherit filesystem order.

What this module deliberately does **not** do: judge. No expiry, no weakness,
no exit code — those belong to ``hygiene``. An unreadable file, an unsupported
container and an unavailable backend all become diagnostics and are carried
through unchanged, because "we could not look" must survive into the report
(plan/03 §⑥).
"""

from __future__ import annotations

import json
import os
import stat
import warnings
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import ExtensionOID

from certledger.collectors import PARSE_UNSUPPORTED, DecodedCandidate, collect_with_items
from certledger.containers import entry_spki, password_from_env, read_container
from certledger.errors import CliError
from certledger.model import (
    LEDGER_KIND,
    SCHEMA_VERSION,
    CertRecord,
    Diagnostic,
    KeyRecord,
    Source,
)
from certledger.parsing.fingerprint import der_sha256
from certledger.parsing.x509 import cert_parts

#: Diagnostics the collector may emit; the ledger passes them through. Named
#: here so a reader can see the ledger adds no new failure vocabulary.
PASSTHROUGH_PREFIXES = ("SKIP_", "PARSE_", "SOURCE_", "CONTAINER_")

#: Formats this module opens itself, through ``containers.read_container``.
#: Everything else that is named but not decoded (PKCS#7) keeps its
#: ``PARSE_UNSUPPORTED`` record: a visible "we did not open this" beats silence,
#: and silence would read as "there was nothing inside".
CONTAINER_FORMATS = ("pkcs12", "jks", "jceks")


def read_ledger(path: str) -> dict:
    """Read a stored ledger written by :func:`build`.

    A missing, malformed or differently-kinded file is an input error (exit 2),
    never an empty ledger: "the file you pointed at is not a ledger" and "this
    machine holds no certificates" must not produce the same document.

    Lives here rather than in the judgement layer because it is about the
    *shape of a ledger*: both ``hygiene`` and the report pipeline read the same
    file, and two readers would eventually disagree about what a ledger is.
    """
    target = Path(path)
    if not target.is_file():
        raise CliError("台账文件不存在", path)
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as error:
        raise CliError("台账文件不可读", f"{target.name}: {error.strerror}") from None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise CliError("台账文件不是合法 JSON", f"{target.name}: {error}") from None
    if not isinstance(payload, dict) or payload.get("kind") != LEDGER_KIND:
        raise CliError(
            "台账文件类型不符",
            f"{target.name} 的 kind 应为 {LEDGER_KIND}，收到 "
            f"{payload.get('kind') if isinstance(payload, dict) else type(payload).__name__}",
        )
    return payload


def build(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    source: str,
    follow_symlinks: bool | None,
    policy,
) -> dict:
    """Build the ledger, muting ``cryptography``'s advisory warnings for the pass.

    ``cryptography`` warns about certificates that violate RFC 5280 *lazily* —
    when ``.extensions`` (or the serial) is first parsed, not when the DER is
    loaded. Real trust stores carry such certificates (measured 2026-10-23: 2 of
    81, ``Go Daddy Class 2`` and ``Starfield Class 2``, each with an
    AuthorityKeyIdentifier whose embedded serial is zero). The warning is a
    property of the *file*, not a defect in this tool, and it prints this
    module's absolute source path to stderr — a leak in a tool whose contract is
    a report free of host paths (K5). The library also states it will *raise* in
    a future release, and these accesses sit outside any ``try``, so the mute
    covers the whole record build rather than the single load line in
    ``sniff._load_certificate`` — a scope where, as measured, the warning never
    fires anyway.

    Only ``CryptographyDeprecationWarning`` is silenced: a bare
    ``simplefilter("ignore")`` would also swallow warnings raised by this
    project's own code. The ``except x509.ExtensionNotFound`` guards inside the
    record builder are left untouched — an absent extension is a normal path,
    and widening them to ``except Exception`` would make "extension missing"
    indistinguishable from "parse failed", which this project forbids
    ("未知即显式").
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return _build(roots=roots, files=files, source=source,
                      follow_symlinks=follow_symlinks, policy=policy)


def _build(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    source: str,
    follow_symlinks: bool | None,
    policy,
) -> dict:
    """Build the ledger from one collection pass over ``roots``/``files``/store.

    Returns the payload shape fixed by ``plan/03`` §②:
    ``{schema_version, kind, certs[], keys[], diagnostics[], summary}``.

    ``policy`` is required even though no threshold is read here: the sniff
    window and size cap come from it, and a ledger built against a different
    policy is a different ledger (K3).
    """
    if policy is None:
        raise CliError("策略缺失", "inventory 需要已加载的策略文件（阈值不设代码默认值）")

    _payload, decoded = collect_with_items(
        roots=roots,
        files=files,
        source=source,
        follow_symlinks=follow_symlinks,
        max_size=None,  # inventory has no --max-size; the policy cap applies
        policy=policy,
    )

    certs: dict[str, CertRecord] = {}
    keys: dict[str, KeyRecord] = {}
    diagnostics: list[Diagnostic] = []
    containers: list[dict] = []

    for entry in decoded:
        if entry.item.cert is not None:
            _absorb_cert(certs, entry)
        elif entry.item.key is not None:
            _absorb_key(keys, entry)
        elif entry.item.key_locked:
            # An encrypted key with no passphrase: understood, not readable.
            # It still belongs in the ledger — omitting it would say "no key
            # here", which is false (plan/03 §② 失败路径).
            _absorb_locked_key(keys, entry)
        elif entry.item.detected_format in CONTAINER_FORMATS:
            _absorb_container(certs, keys, containers, entry)
        else:
            # Named but not decoded (PKCS#7, unknown label). The container's
            # *contents* are not in the ledger, but the container itself is a
            # fact about the machine and it must not vanish: a PKCS#7 silently
            # absent from the table reads as "no certificates in it". One
            # ``PARSE_UNSUPPORTED`` record says "there is something here we did
            # not open" (plan/03 §⑥ "没找到" vs "没看").
            diagnostics.append(
                Diagnostic(
                    code=PARSE_UNSUPPORTED,
                    path=entry.path,
                    stage="container",
                    detail=f"{entry.item.detected_format} 未展开（当前版本不读该容器）",
                )
            )

    diagnostics.extend(Diagnostic(**diagnostic) for diagnostic in _payload["diagnostics"])

    paired_certs = _pair_certs(keys, certs)
    ordered_certs = tuple(
        sorted(certs.values(), key=lambda record: record.fingerprint_sha256)
    )
    ordered_keys = tuple(
        sorted(
            keys.values(),
            key=lambda record: (record.spki_sha256 is None, record.spki_sha256 or ""),
        )
    )
    ordered_diagnostics = tuple(
        sorted(
            diagnostics,
            key=lambda item: (item.code, item.path, item.stage, item.detail),
        )
    )
    ordered_containers = tuple(sorted(containers, key=lambda item: item["path"]))

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "inventory",
        "certs": [record.to_dict() for record in ordered_certs],
        "keys": [_key_with_pair(record, paired_certs).to_dict() for record in ordered_keys],
        "containers": [item for item in ordered_containers],
        "diagnostics": [item.to_dict() for item in ordered_diagnostics],
        "summary": _summary(
            ordered_certs, ordered_keys, paired_certs, _payload["summary"], ordered_containers
        ),
    }


# ── certificates ────────────────────────────────────────────────────────────


def _absorb_cert(records: dict[str, CertRecord], entry: DecodedCandidate) -> None:
    """Merge one decoded certificate into the ledger keyed by its DER hash."""
    cert = entry.item.cert
    assert cert is not None  # caller checked
    der = entry.item.der
    fingerprint = der_sha256(der)
    source = _source_for(entry)

    existing = records.get(fingerprint)
    if existing is not None:
        records[fingerprint] = _with_source(existing, source)
        return
    records[fingerprint] = _cert_record(cert, der, fingerprint, (source,))


def _cert_record(
    cert: x509.Certificate,
    der: bytes,
    fingerprint: str,
    sources: tuple[Source, ...],
) -> CertRecord:
    parts = cert_parts(der)
    # A certificate whose TBS will not walk keeps its record: the hashes that
    # matter (fingerprint) come from the whole DER, and the subject/issuer
    # display strings come from cryptography either way. Empty hashes say
    # "not derived", which is honest, rather than inventing a value.
    subject_der_sha256 = der_sha256(parts.subject_der) if parts else ""
    issuer_der_sha256 = der_sha256(parts.issuer_der) if parts else ""
    spki_sha256 = der_sha256(parts.spki_der) if parts else _spki_from_key(cert)

    dns, ip, email, uri = _san_values(cert)
    # The key object is needed for the display fields even when the SPKI hash
    # came from the raw slice. ``None`` means the algorithm is one this build of
    # ``cryptography`` cannot deserialise (measured: 1 of 81 real store
    # certificates, an MD5-signed legacy root). The fingerprint and SPKI hash
    # are still correct; only the human-readable key description is empty.
    key = _public_key(cert)

    return CertRecord(
        fingerprint_sha256=fingerprint,
        spki_sha256=spki_sha256,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        subject_der_sha256=subject_der_sha256,
        issuer_der_sha256=issuer_der_sha256,
        san_dns=dns,
        san_ip=ip,
        san_email=email,
        san_uri=uri,
        not_before=_stamp(cert.not_valid_before_utc),
        not_after=_stamp(cert.not_valid_after_utc),
        key_algo=_key_algo(key),
        key_bits=getattr(key, "key_size", None),
        curve=getattr(getattr(key, "curve", None), "name", None),
        sig_algo=cert.signature_algorithm_oid.dotted_string,
        key_usage=_key_usage(cert),
        extended_key_usage=_extended_key_usage(cert),
        is_ca=_is_ca(cert),
        subject_key_id=_subject_key_id(cert),
        sources=tuple(sorted(sources, key=Source.sort_key)),
    )


def _with_source(record: CertRecord, source: Source) -> CertRecord:
    """Same certificate, one more place it was found."""
    return replace(record, sources=tuple(sorted(record.sources + (source,), key=Source.sort_key)))


def _public_key(cert: x509.Certificate):
    """The decoded public key, or ``None`` when this build cannot decode it.

    Returning ``None`` rather than raising is deliberate. A certificate whose
    key algorithm is legacy or unsupported is still a real, fingerprinted asset;
    dropping the record would under-report the ledger, and raising would abort
    the whole run over one root certificate (plan/03 §⑥).
    """
    try:
        return cert.public_key()
    except Exception:  # noqa: BLE001 - unsupported/legacy key algorithm
        return None


def _spki_from_key(cert: x509.Certificate) -> str:
    """Fallback when the DER walk fails: derive and re-encode.

    Only reached for a structurally unusual certificate. It is the *fallback*,
    not the default, because re-encoding is what K1 forbids as the primary path.
    """
    try:
        spki = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:  # noqa: BLE001 - unsupported key algorithm
        return ""
    return der_sha256(spki)

def _san_values(cert: x509.Certificate) -> tuple[tuple[str, ...], ...]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return (), (), (), ()
    return (
        tuple(san.get_values_for_type(x509.DNSName)),
        tuple(str(value) for value in san.get_values_for_type(x509.IPAddress)),
        tuple(san.get_values_for_type(x509.RFC822Name)),
        tuple(san.get_values_for_type(x509.UniformResourceIdentifier)),
    )


def _key_usage(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return ()
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    )
    return tuple(name for name in names if getattr(usage, name, False))


def _extended_key_usage(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return ()
    # The short name (``serverAuth``) is what a reader recognises; ``_name`` is
    # the only accessor cryptography exposes for it, and it is stable in
    # practice — the dotted form is the fallback when it is absent.
    return tuple(getattr(oid, "_name", oid.dotted_string) for oid in eku)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _subject_key_id(cert: x509.Certificate) -> str | None:
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return None
    return ski.digest.hex()


# ── keys ────────────────────────────────────────────────────────────────────


def _absorb_key(records: dict[str, KeyRecord], entry: DecodedCandidate) -> None:
    """Merge one decoded private key, keyed by the SPKI its public half implies."""
    key = entry.item.key
    assert key is not None  # caller checked
    spki_sha256 = _key_spki(key)
    if not spki_sha256:  # pragma: no cover - every supported key type yields one
        _absorb_locked_key(records, entry)
        return
    source = _source_for(entry)
    existing = records.get(spki_sha256)
    if existing is not None:
        records[spki_sha256] = replace(
            existing, sources=tuple(sorted(existing.sources + (source,), key=Source.sort_key))
        )
        return
    records[spki_sha256] = KeyRecord(
        spki_sha256=spki_sha256,
        key_algo=_key_algo(key),
        key_bits=getattr(key, "key_size", None),
        curve=getattr(getattr(key, "curve", None), "name", None),
        encrypted=entry.item.key_encrypted,
        sources=(source,),
    )


def _absorb_locked_key(records: dict[str, KeyRecord], entry: DecodedCandidate) -> None:
    """An encrypted key we cannot open: one record per *file*, not per SPKI.

    No SPKI is derivable without the passphrase, so there is no merge key. Using
    a sentinel like ``""`` would merge every locked key on the machine into one
    record — worse than not merging at all, because it invents an identity.
    The path is used as the identity instead, and ``spki_sha256`` stays ``None``
    so no pairing rule can accidentally match it (plan/03 §② 失败路径).
    """
    source = _source_for(entry)
    identity = f"\x00locked:{source.kind}:{source.path}:{entry.offset}"
    existing = records.get(identity)
    if existing is not None:
        records[identity] = replace(
            existing, sources=tuple(sorted(existing.sources + (source,), key=Source.sort_key))
        )
        return
    records[identity] = KeyRecord(
        spki_sha256=None,
        key_algo="",
        key_bits=None,
        curve=None,
        encrypted=True,
        sources=(source,),
    )


def _key_spki(key: object) -> str:
    """SPKI DER hash of a private key's public half, or ``""`` when unavailable."""
    try:
        public = key.public_key()  # type: ignore[attr-defined]
        spki = public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:  # noqa: BLE001 - unsupported key type; reported as locked
        return ""
    return der_sha256(spki)


# ── containers ──────────────────────────────────────────────────────────────


def _absorb_container(
    certs: dict[str, CertRecord],
    keys: dict[str, KeyRecord],
    containers: list[dict],
    entry: DecodedCandidate,
) -> None:
    """Open one container and fold its contents into the same two tables.

    A certificate inside a PKCS#12 is the same asset as the same certificate on
    disk: it merges by fingerprint, and its ``sources[]`` grows a
    ``kind="container"`` row carrying ``container_format`` / ``alias`` /
    ``entry_type`` — the three ``Source`` fields that were reserved for exactly
    this and had no producer until now.

    The container itself is recorded either way. A store that did not open is a
    **fact about the machine** ("this box is here and we could not look inside"),
    which is a different statement from "the box is empty"; the ``unreadable``
    reason is what keeps the two apart, and ``hygiene`` turns it into one
    ``CONTAINER_UNREADABLE`` finding.
    """
    reading = read_container(entry.path, password=password_from_env())
    containers.append(reading.to_dict())

    for item in reading.entries:
        source = Source(
            kind="container",
            path=reading.path,
            container_format=reading.format,
            alias=item.alias,
            entry_type=item.entry_type,
        )
        if item.cert_der:
            _absorb_container_cert(certs, item, source)
        if item.entry_type == "privateKey":
            _absorb_container_key(keys, item, source)


def _absorb_container_cert(
    records: dict[str, CertRecord], item, source: Source
) -> None:
    """Merge one container certificate, keyed by its DER hash like any other."""
    fingerprint = der_sha256(item.cert_der)
    existing = records.get(fingerprint)
    if existing is not None:
        records[fingerprint] = _with_source(existing, source)
        return
    records[fingerprint] = _cert_record(item.certificate, item.cert_der, fingerprint, (source,))


def _absorb_container_key(records: dict[str, KeyRecord], item, source: Source) -> None:
    """Record the private key a container *declares*, from the certificate.

    Two shapes arrive here and both are honest:

    * **PKCS#12** gives the key object itself, so the SPKI is derived from the
      key's own public half;
    * **JKS/JCEKS** gives only the certificate — ``keytool`` cannot hand out a
      private key without its key password — but a ``PrivateKeyEntry`` *is* a
      statement that a private key exists for that certificate, and the public
      half of that key is the certificate's. Deriving the SPKI from the
      certificate therefore records a fact the store asserted, not a guess.

    ``encrypted=True`` is the stored form, not an opinion: key material inside a
    PKCS#12 or a JKS ``PrivateKeyEntry`` is protected by the container's own
    password. Whether *that* protection is worth anything is the container's
    question, and ``CONTAINER_EMPTY_PASSWORD`` answers it; a file on disk has no
    such claim and is judged by ``PRIVATE_KEY_UNENCRYPTED`` instead.
    """
    spki = _key_spki(item.key) if item.key is not None else entry_spki(item)
    if not spki:
        return
    subject_key = item.key if item.key is not None else item.certificate
    existing = records.get(spki)
    if existing is not None:
        records[spki] = replace(
            existing, sources=tuple(sorted(existing.sources + (source,), key=Source.sort_key))
        )
        return
    records[spki] = KeyRecord(
        spki_sha256=spki,
        key_algo=_key_algo(subject_key),
        key_bits=getattr(subject_key, "key_size", None),
        curve=getattr(getattr(subject_key, "curve", None), "name", None),
        encrypted=True,
        sources=(source,),
    )


# ── pairing ─────────────────────────────────────────────────────────────────


def _pair_certs(
    keys: dict[str, KeyRecord], certs: dict[str, CertRecord]
) -> dict[str, str]:
    """``spki_sha256`` → certificate fingerprint, for SPKIs seen on both sides.

    When several certificates share one SPKI (the same key re-issued under a new
    validity period), the pairing names the **lowest fingerprint**. Any choice is
    arbitrary there; making it the smallest is what keeps two runs identical
    (plan/00 D9), and the ledger still lists every certificate separately, so
    nothing is hidden — only the "which one is *the* pair" pointer is pinned.
    """
    by_spki: dict[str, str] = {}
    for record in certs.values():
        if not record.spki_sha256:
            continue
        current = by_spki.get(record.spki_sha256)
        if current is None or record.fingerprint_sha256 < current:
            by_spki[record.spki_sha256] = record.fingerprint_sha256
    return {
        spki: fingerprint
        for spki, fingerprint in by_spki.items()
        if spki in keys
    }


def _key_with_pair(record: KeyRecord, paired: dict[str, str]) -> KeyRecord:
    if record.spki_sha256 is None:
        return record
    target = paired.get(record.spki_sha256)
    if target is None or target == record.paired_cert_fingerprint:
        return record
    return replace(record, paired_cert_fingerprint=target)


# ── shared helpers ──────────────────────────────────────────────────────────


def _source_for(entry: DecodedCandidate) -> Source:
    """Map a decoded candidate onto the ``sources[]`` vocabulary.

    File sources carry their POSIX mode, read **here** rather than later: a
    stored ledger may be evaluated on another machine, and re-stat'ing the path
    there would describe a different filesystem (or fail). ``None`` on Windows,
    which has no POSIX mode — recording the read-only bit as ``0o666`` would
    make every key on such a machine look world-readable.
    """
    if entry.source_kind == "store":
        return Source(
            kind="store",
            path=entry.path,
            alias=entry.container_alias,
            store_name=entry.store_name,
        )
    if entry.container_alias is not None:
        return Source(kind="container", path=entry.path, alias=entry.container_alias)
    return Source(kind="file", path=entry.path, posix_mode=_posix_mode(entry.path))


def _posix_mode(path: str) -> str | None:
    """The file's permission bits as an octal string, or ``None`` where n/a."""
    if os.name != "posix":
        return None
    try:
        return format(stat.S_IMODE(os.stat(path).st_mode), "04o")
    except OSError:
        return None


def _key_algo(key: object) -> str:
    """``rsa`` / ``ec`` / ``ed25519`` / ``""`` from the object's class name.

    Class names are ``RSAPublicKey`` / ``EllipticCurvePrivateKey`` / …; the
    mapping below normalises the two irregular ones and lower-cases the rest.

    ``""`` for ``None`` (an undecodable key, see :func:`_public_key`): an empty
    string says "not known", which is true. ``"nonetype"`` would be a Python
    class name leaked into a report and read as an algorithm.
    """
    if key is None:
        return ""
    name = type(key).__name__
    for suffix in ("PublicKey", "PrivateKey"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    lowered = name.lower()
    return {"ellipticcurve": "ec", "rsa": "rsa", "dsa": "dsa"}.get(lowered, lowered)


def _stamp(moment) -> str:
    """UTC timestamp in the one format the truth file and reports use."""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _summary(
    certs: tuple[CertRecord, ...],
    keys: tuple[KeyRecord, ...],
    paired: dict[str, str],
    collect_summary: dict[str, Any],
    containers: tuple[dict, ...],
) -> dict[str, Any]:
    """Counts with their units named, because they do not add up to each other.

    ``certs`` counts distinct certificates; ``sources`` counts places they were
    found; ``paired_keys`` counts keys with a certificate; ``containers`` counts
    boxes, each holding an unknown number of the above. Adding any two of them
    would produce a number that means nothing, so they are laid out side by side
    and the candidate counters are nested under their own key rather than
    flattened in.

    ``containers_unreadable`` is separate from ``containers`` on purpose: "three
    stores, one of which we could not open" and "three stores, all opened" are
    different answers, and only one of them is an answer about the stores.
    """
    paired_keys = sum(1 for record in keys if record.spki_sha256 in paired)
    return {
        "certs": len(certs),
        "keys": len(keys),
        "cert_sources": sum(len(record.sources) for record in certs),
        "key_sources": sum(len(record.sources) for record in keys),
        "paired_keys": paired_keys,
        "locked_keys": sum(1 for record in keys if record.spki_sha256 is None),
        "containers": len(containers),
        "containers_unreadable": sum(1 for item in containers if item.get("unreadable")),
        "collect": {
            "visited": collect_summary["visited"],
            "scanned": collect_summary["scanned"],
            "skipped": collect_summary["skipped"],
        },
    }


__all__ = ["build"]
