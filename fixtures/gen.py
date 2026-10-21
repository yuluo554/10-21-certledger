#!/usr/bin/env python3
"""Fixture generator: eight sample classes plus the rule-boundary supplements.

Entry point is ``fixtures/gen.sh`` (it probes the toolchain first). This module
does the real work because JSON writing, deterministic key generation and
container inspection are not things a shell script does safely.

Two kinds of output, deliberately kept apart (``plan/04`` §一.3):

* ``fixtures/out/**``  — **artifacts**: certificates, keys, containers. Generated
  on demand, never committed, blocked by ``.gitignore``.
* ``fixtures/expected.json`` — **truth**: inputs plus the expected conclusions.
  Committed. Carries no key material and no ``observed_*`` field: a truth file
  that records what the code produced stops being a truth file the moment the
  code changes (``plan/04`` §二.1).

Every case directory contains **exactly** the files the truth lists as inputs.
Anything used only to sign or to hold a value lives in a scratch directory
outside the output tree, so "scan this case" and "the expected inputs" cannot
drift apart.

Reproducibility rules this file is written to satisfy:

* every certificate is signed by ``openssl ca`` with pinned ``-startdate`` /
  ``-enddate`` and a pinned serial — two runs produce byte-identical files;
* every RSA key comes from a deterministic SHA-256 counter stream, so a fresh
  clone reproduces the same key bytes without shipping a key;
* PKCS#12 bytes are **not** reproducible (random salt and IV), so containers are
  compared by alias table and contained fingerprints, never by file hash
  (``data/README.md`` §4.4).

Deliberate omissions, each with a reason:

* private keys are **plaintext**: an encrypted PEM carries a random salt, which
  would break "two runs, same hash". Consequence: every case holding a key file
  legitimately reports ``PRIVATE_KEY_UNENCRYPTED``;
* no ECDSA-signed certificate: ECDSA signatures draw a random nonce, so the
  bytes would differ between runs;
* no JKS sample: JKS bytes embed creation timestamps and the format needs
  ``keytool``, which is optional. A sample that cannot be produced everywhere
  would make the truth machine-dependent. JKS arrives with the container route.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

# ── constants pinned by plan/04 §四 ─────────────────────────────────────────

#: The single baseline instant. Every sample's validity is pinned relative to it.
AS_OF = 1_900_000_000  # 2030-03-17T17:46:40Z

#: Container password for every generated PKCS#12 (public fixture material).
CONTAINER_PASSWORD = b"changeit"

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PATH = REPO_ROOT / "fixtures" / "expected.json"
DEFAULT_OUT = REPO_ROOT / "fixtures" / "out"

#: RSA exponent: the OpenSSL default, and the only one still universal.
RSA_EXPONENT = 65537


# ── small helpers ───────────────────────────────────────────────────────────


def iso(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def openssl_stamp(seconds: int) -> str:
    """``[CC]YYMMDDHHMMSSZ`` — the format ``ca -startdate`` / ``-enddate`` expect."""
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y%m%d%H%M%SZ")


def parse_stamp(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _display(path: Path) -> str:
    """Repo-relative when inside the tree, absolute-free name otherwise.

    ``--out`` may point anywhere (a scratch dir, a mount); printing a machine
    path into a transcript would be a privacy leak of exactly the kind the
    desensitization gate exists to catch.
    """
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return f"<out>/{path.name}"


class GenerateError(RuntimeError):
    """A toolchain or argument problem; rendered as exit code 2 by ``main``."""


def run(argv: Sequence[str], *, what: str) -> str:
    result = subprocess.run(list(argv), capture_output=True, text=True)
    if result.returncode != 0:
        raise GenerateError(f"{what} 失败（rc={result.returncode}）：{result.stderr.strip()[:400]}")
    return result.stdout


# ── deterministic RSA keys ──────────────────────────────────────────────────

_SMALL_PRIMES = tuple(p for p in range(2, 2000) if all(p % d for d in range(2, int(p**0.5) + 1)))
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53)


def _is_probable_prime(n: int) -> bool:
    """Miller-Rabin with a fixed base set; deterministic far below 2**128."""
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in _MR_BASES:
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _candidate(seed: str, bits: int, index: int, attempt: int) -> int:
    """A ``bits``-wide odd integer derived from a counter stream.

    The top two bits are forced so the product of two such primes is exactly
    ``bits`` bits wide — otherwise the actual key size would drift and
    ``key_bits`` in the truth file would stop describing the artifact.
    """
    need = (bits + 7) // 8
    stream = b""
    counter = 0
    while len(stream) < need:
        stream += hashlib.sha256(f"{seed}|{bits}|{index}|{attempt}|{counter}".encode()).digest()
        counter += 1
    value = int.from_bytes(stream[:need], "big")
    return value | (1 << (bits - 1)) | (1 << (bits - 2)) | 1


def _deterministic_prime(seed: str, bits: int, index: int) -> int:
    for attempt in range(200_000):
        candidate = _candidate(seed, bits, index, attempt)
        if _is_probable_prime(candidate):
            return candidate
    raise GenerateError(f"在 {seed!r} 上找不到 {bits} 位素数；确定性密钥流有问题")


def deterministic_rsa(seed: str, bits: int):
    """Build an RSA private key from a seed. Same seed → same key bytes.

    Shipping fixture private keys would break the privacy rule; deriving them
    from a public seed gives reproducibility without shipping anything.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers

    p = _deterministic_prime(seed, bits // 2, 0)
    q = _deterministic_prime(seed, bits // 2, 1)
    if p == q:  # pragma: no cover - astronomically unlikely, but not impossible
        q = _deterministic_prime(seed, bits // 2, 2)
    modulus = p * q
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    d = pow(RSA_EXPONENT, -1, lam)
    numbers = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=RSAPublicNumbers(RSA_EXPONENT, modulus),
    )
    return numbers.private_key()


def write_private_key(key, path: Path) -> None:
    """Write a PKCS#8 PEM with no password (see the module docstring).

    The file is left owner-only so the samples describe what a careful operator
    does. With the default umask (022 → 0644) every sample key would report
    ``PERMISSION_TOO_OPEN`` on POSIX and ``healthy`` would stop being healthy
    for an accidental reason. The ``perm`` case sets its own loose mode *after*
    calling this.
    """
    from cryptography.hazmat.primitives import serialization

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - filesystems without POSIX modes
        pass


# ── certificates via OpenSSL ────────────────────────────────────────────────


def make_certificate(
    *,
    key_path: Path,
    out_path: Path,
    common_name: str,
    serial: int,
    not_before: int,
    not_after: int,
    digest: str = "sha256",
    san: str | None = None,
    is_ca: bool = False,
    issuer: tuple[Path, Path] | None = None,
) -> None:
    """Sign a certificate with a pinned serial and pinned validity.

    ``issuer`` is ``(ca_cert, ca_key)`` for a CA-signed leaf, ``None`` for a
    self-signed one. Both go through one signing path.

    **Why ``openssl ca`` and not ``openssl req``.** ``req -x509`` grew
    ``-not_before`` / ``-not_after`` only in **OpenSSL 3.5**; the distro builds
    the CI runners carry (3.0) reject them with ``req: Use -help for summary``,
    so the earlier generator could only produce samples on one machine's OpenSSL.
    ``ca`` has pinned dates through ``-startdate`` / ``-enddate`` since long
    before 3.0, pins the serial through its database, and — unlike
    ``cryptography`` 50, which refuses to *sign* with SHA-1 — still emits the
    ``sha1WithRSAEncryption`` certificate the ``weak-sig`` sample exists to
    describe. One path, both properties, every OpenSSL ≥ 3.0.

    The subject and extensions are passed through a **config file** rather than
    ``-subj /CN=…``: on Windows, MSYS rewrites an argument that looks like a
    ``/path`` into a native path, which turns ``/CN=x`` into ``D:/…/CN=x`` and
    fails the request (observed locally and on the Windows runners).
    """
    # Signing material lives in a throwaway directory, never beside the artifact:
    # a case directory must contain **exactly** the files the truth lists as
    # inputs, and ``ca`` writes a config, a request, a serial and a database.
    # Leaving those behind makes the tree disagree with the truth file — the
    # failure the "declared inputs" test exists to catch.
    with tempfile.TemporaryDirectory(prefix="certledger-sign-") as tmp:
        work = Path(tmp)
        database = work / "db"
        database.mkdir(exist_ok=True)
        (database / "index.txt").write_text("", encoding="utf-8")
        # ``ca`` assigns the certificate the serial *currently in the file*, then
        # increments it — so the file holds the wanted value, not value + 1.
        (database / "serial").write_text(f"{serial:04X}\n", encoding="utf-8")
        # ``ca`` refuses a second certificate with the same subject unless this
        # is set; every case signs from a fresh database anyway.
        (database / "index.txt.attr").write_text("unique_subject = no\n", encoding="utf-8")

        extensions = [
            f"basicConstraints = critical,CA:{'TRUE' if is_ca else 'FALSE'}",
            # Declared as ``none`` on purpose. ``openssl ca`` fills in a
            # Subject Key Identifier by default, and *which* defaults it fills
            # in has changed between releases — so the same invocation produced
            # a different DER on OpenSSL 3.0 (the CI runners) and 3.5 (this
            # machine), which made the truth file irreproducible across
            # platforms. Every extension the certificate carries is now named
            # here; nothing is left to a version-dependent default.
            "subjectKeyIdentifier = none",
            "authorityKeyIdentifier = none",
        ]
        if is_ca:
            extensions.append("keyUsage = critical,keyCertSign,cRLSign")
        else:
            extensions.append("keyUsage = critical,digitalSignature,keyEncipherment")
            extensions.append("extendedKeyUsage = serverAuth")
            if san:
                extensions.append(f"subjectAltName = DNS:{san}")

        config = work / "ca.cnf"
        config.write_text(
            "\n".join(
                [
                    "[ca]",
                    "default_ca = CA_default",
                    "[CA_default]",
                    f"dir = {database.as_posix()}",
                    f"database = {(database / 'index.txt').as_posix()}",
                    f"serial = {(database / 'serial').as_posix()}",
                    f"new_certs_dir = {database.as_posix()}",
                    f"default_md = {digest}",
                    "policy = policy_any",
                    "x509_extensions = ext",
                    "unique_subject = no",
                    "[policy_any]",
                    "commonName = supplied",
                    "[req]",
                    "distinguished_name = dn",
                    "prompt = no",
                    "[dn]",
                    f"CN = {common_name}",
                    "[ext]",
                    *extensions,
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        request = work / "request.csr"
        run(
            ["openssl", "req", "-new", "-key", str(key_path), "-config", str(config),
             "-out", str(request)],
            what=f"生成证书请求 {out_path.name}（CN={common_name}）",
        )

        argv = [
            "openssl",
            "ca",
            "-config",
            str(config),
            "-in",
            str(request),
            "-startdate",
            openssl_stamp(not_before),
            "-enddate",
            openssl_stamp(not_after),
            "-batch",
            # Without ``-notext`` ``ca`` prepends a human-readable dump of the
            # certificate, and the file then starts with ``Certificate:`` rather
            # than ``-----BEGIN CERTIFICATE-----``. The sniffer classifies by
            # prefix, so every sample would be skipped as "unrecognised" — a
            # whole fixture tree that looks generated and contains nothing the
            # tool can read.
            "-notext",
            "-out",
            str(out_path),
        ]
        if issuer is None:
            argv += ["-selfsign", "-keyfile", str(key_path)]
        else:
            issuer_cert_path, issuer_key_path = issuer
            argv += ["-cert", str(issuer_cert_path), "-keyfile", str(issuer_key_path)]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        run(argv, what=f"签发 {out_path.name}（CN={common_name}）")


# ── reading artifacts back (never guessing) ─────────────────────────────────


def pem_blocks(raw: bytes) -> list[tuple[str, bytes]]:
    """Split PEM bytes into ``(label, der)`` pairs.

    Fingerprints are taken from these bytes directly rather than from a
    re-encoded certificate: K1 says the hash input is the DER as stored.
    """
    text = raw.decode("ascii")
    found: list[tuple[str, bytes]] = []
    for match in re.finditer(
        r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", text, re.DOTALL
    ):
        body = re.sub(r"\s+", "", match.group(2))
        found.append((match.group(1), base64.b64decode(body, validate=True)))
    return found


def cert_metadata(raw: bytes, *, offset: int | None = None) -> dict[str, Any]:
    """Read the fields the truth declares, straight from the certificate bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    if b"-----BEGIN CERTIFICATE-----" in raw:
        certs = [der for label, der in pem_blocks(raw) if label == "CERTIFICATE"]
        index = offset or 0
        der = certs[index]
        cert = x509.load_der_x509_certificate(der)
    else:
        der = raw
        cert = x509.load_der_x509_certificate(raw)

    public_key = cert.public_key()
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": f"0x{cert.serial_number:x}",
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "spki_sha256": hashlib.sha256(spki).hexdigest(),
        "key_algo": public_key.__class__.__name__.replace("PublicKey", "").lower(),
        "key_bits": getattr(public_key, "key_size", None),
        "key_curve": getattr(getattr(public_key, "curve", None), "name", None),
        "sig_algo": cert.signature_algorithm_oid.dotted_string,
        "sig_algo_name": cert.signature_algorithm_oid._name,  # noqa: SLF001 - stable
        "san_dns": _san_dns(cert),
        "is_ca": _is_ca(cert),
    }


def _san_dns(cert) -> list[str]:
    from cryptography import x509

    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(extension.value.get_values_for_type(x509.DNSName))


def _is_ca(cert) -> bool:
    from cryptography import x509

    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def key_metadata(path: Path) -> dict[str, Any]:
    """Describe a private key artifact: algorithm, size, encryption state."""
    from cryptography.hazmat.primitives import serialization

    raw = path.read_bytes()
    encrypted = False
    key = None
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError):
        encrypted = True
        try:
            key = serialization.load_pem_private_key(raw, password=b"certledger-fixture")
        except (TypeError, ValueError):
            key = None

    if key is None:  # pragma: no cover - only if an artifact gets corrupted
        return {
            "key_algo": "",
            "key_bits": None,
            "key_curve": None,
            "encrypted": encrypted,
            "spki_sha256": None,
        }
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "key_algo": key.__class__.__name__.replace("PrivateKey", "").lower(),
        "key_bits": getattr(key, "key_size", None),
        "key_curve": getattr(getattr(key, "curve", None), "name", None),
        "encrypted": encrypted,
        "spki_sha256": hashlib.sha256(spki).hexdigest(),
    }


# ── containers ──────────────────────────────────────────────────────────────


def p12_multi_alias(cert_path: Path, aliases: Sequence[str], out_path: Path) -> None:
    """A trust store holding the *same* certificate under several aliases.

    This is the shape that produces ``DUPLICATE_CERT`` inside one container —
    a fingerprint that repeats without a second file on disk.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    blob = pkcs12.serialize_java_truststore(
        [pkcs12.PKCS12Certificate(cert, friendly_name=alias.encode()) for alias in aliases],
        BestAvailableEncryption(CONTAINER_PASSWORD),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(blob)


def p12_key_with_trusted(
    key_path: Path,
    cert_path: Path,
    trusted_cert_path: Path,
    alias: str,
    trusted_alias: str,
    out_path: Path,
) -> None:
    """A PKCS#12 holding a private key entry *and* an unrelated trusted certificate.

    ``CONTAINER_TRUSTSTORE_WITH_KEY`` is defined by the bag structure
    ``cryptography`` exposes (``plan/03`` §⑤ routes PKCS#12 through it, so its
    view is the contract): a key bag plus a certificate bag carrying its own
    friendly name and a different public key. ``keytool`` folds the extra
    certificate into the chain and reports a single entry — which is exactly why
    JKS and PKCS#12 must not share a reader.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    trusted = x509.load_pem_x509_certificate(trusted_cert_path.read_bytes())
    blob = pkcs12.serialize_key_and_certificates(
        alias.encode(),
        key,
        cert,
        [pkcs12.PKCS12Certificate(trusted, friendly_name=trusted_alias.encode())],
        BestAvailableEncryption(CONTAINER_PASSWORD),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(blob)


def p12_empty_password(key_path: Path, cert_path: Path, alias: str, out_path: Path) -> None:
    """Export through OpenSSL with an empty password.

    ``cryptography`` refuses to *write* an empty-password bag, but OpenSSL will.
    The point of the sample is that the container opens with no password at
    all — the signal that a trust store is being used as a key store by accident.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "openssl",
            "pkcs12",
            "-export",
            "-inkey",
            str(key_path),
            "-in",
            str(cert_path),
            "-name",
            alias,
            "-out",
            str(out_path),
            "-passout",
            "pass:",
            "-certpbe",
            "AES-256-CBC",
            "-keypbe",
            "AES-256-CBC",
            "-macalg",
            "sha256",
        ],
        what=f"导出 {out_path.name}（空口令）",
    )


def _cert_fingerprint(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _spki_fingerprint(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def inspect_p12(path: Path, password: bytes) -> dict[str, Any]:
    """Alias table of a PKCS#12 as ``cryptography`` sees it (the M5 contract)."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    raw = path.read_bytes()
    parsed = None
    used_empty = password == b""
    for candidate in (password, b""):
        try:
            parsed = pkcs12.load_pkcs12(raw, candidate)
            break
        except (ValueError, TypeError):
            continue
    if parsed is None:  # pragma: no cover - every generated container opens
        raise GenerateError(f"容器 {path.name} 无法解析")

    entries: list[dict[str, Any]] = []
    if parsed.key is not None and parsed.cert is not None:
        entries.append(
            {
                "alias": (parsed.cert.friendly_name or b"").decode() or None,
                "entry_type": "privateKey",
                "fingerprint_sha256": _cert_fingerprint(parsed.cert.certificate),
                "spki_sha256": _spki_fingerprint(parsed.cert.certificate),
            }
        )
        for extra in parsed.additional_certs:
            entries.append(
                {
                    "alias": (extra.friendly_name or b"").decode() or None,
                    "entry_type": "trustedCert",
                    "fingerprint_sha256": _cert_fingerprint(extra.certificate),
                    "spki_sha256": _spki_fingerprint(extra.certificate),
                }
            )
    else:
        for entry in parsed.additional_certs:
            entries.append(
                {
                    "alias": (entry.friendly_name or b"").decode() or None,
                    "entry_type": "trustedCert",
                    "fingerprint_sha256": _cert_fingerprint(entry.certificate),
                    "spki_sha256": _spki_fingerprint(entry.certificate),
                }
            )
    entries.sort(key=lambda item: (item["alias"] or "", item["entry_type"]))
    return {
        "format": "pkcs12",
        "password": "empty" if used_empty else "set",
        "entries": entries,
        "has_private_key": any(item["entry_type"] == "privateKey" for item in entries),
    }


# ── case specification ──────────────────────────────────────────────────────

#: Every case: what it is for, what it contains, and the *complete* expected
#: finding set (not a summary). ``absent`` names rules that must stay silent —
#: a rule that fires everywhere explains nothing.
CASES: tuple[dict[str, Any], ...] = (
    {
        "case": "healthy",
        "group": "required",
        "index": 1,
        "purpose": "健康：有效期与强度都在界内，私钥与证书配对",
        "pattern": "self-signed",
        "cn": "healthy.example",
        "serial": 0x1001,
        "offset_days": 365,
        "with_key": True,
        "findings": [("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["EXPIRED", "EXPIRING", "EXPIRY_CLIFF", "WEAK_KEY", "WEAK_SIG",
                   "ORPHAN_CERT", "ORPHAN_KEY", "DUPLICATE_CERT", "DUPLICATE_KEY"],
    },
    {
        "case": "expiring",
        "group": "required",
        "index": 2,
        "purpose": "将过期：not_after 落在 [as_of, as_of+30d)",
        "pattern": "self-signed",
        "cn": "expiring.example",
        "serial": 0x1002,
        "offset_days": 10,
        "with_key": True,
        "findings": [("EXPIRING", "WARN", 1), ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["EXPIRED", "EXPIRY_CLIFF", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT",
                   "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "expired",
        "group": "required",
        "index": 3,
        "purpose": "已过期：not_after 严格早于 as_of",
        "pattern": "self-signed",
        "cn": "expired.example",
        "serial": 0x1003,
        "offset_days": -5,
        "with_key": True,
        "findings": [("EXPIRED", "ERROR", 1), ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "weak-key",
        "group": "required",
        "index": 4,
        "purpose": "弱密钥：RSA 1024，低于 CA/B §6.1.5 的 2048",
        "pattern": "self-signed",
        "cn": "weak-key.example",
        "serial": 0x1004,
        "offset_days": 365,
        "bits": 1024,
        "with_key": True,
        "findings": [("WEAK_KEY", "WARN", 1), ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "weak-sig",
        "group": "required",
        "index": 5,
        "purpose": "弱签名：SHA-1 签发（NIST SP 800-131A Rev.2：签名生成不再允许）",
        "pattern": "self-signed",
        "cn": "weak-sig.example",
        "serial": 0x1005,
        "offset_days": 365,
        "digest": "sha1",
        "with_key": True,
        "findings": [("WEAK_SIG", "WARN", 1), ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "ORPHAN_CERT", "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "multi-alias",
        "group": "required",
        "index": 6,
        "purpose": "多别名：同一证书在一个容器里挂两个 alias → 2 条来源、DUPLICATE_CERT",
        "pattern": "container-multi-alias",
        "cn": "multi-alias.example",
        "serial": 0x1006,
        "offset_days": 365,
        "aliases": ["multi-alias-primary", "multi-alias-secondary"],
        "findings": [("DUPLICATE_CERT", "INFO", 1), ("ORPHAN_CERT", "INFO", 1)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_KEY",
                   "CONTAINER_TRUSTSTORE_WITH_KEY", "CONTAINER_EMPTY_PASSWORD"],
    },
    {
        "case": "truststore-with-key",
        "group": "required",
        "index": 7,
        "purpose": "truststore 混私钥：一个私钥条目 + 一个外来可信证书（两把不同的公钥）",
        "pattern": "container-mixed",
        "cn": "key-entry.example",
        "serial": 0x1007,
        "offset_days": 365,
        "trusted_cn": "trusted-only.example",
        "trusted_serial": 0x1008,
        "aliases": ["key-entry", "trusted-only"],
        "findings": [("CONTAINER_TRUSTSTORE_WITH_KEY", "WARN", 1), ("ORPHAN_CERT", "INFO", 1)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_KEY",
                   "DUPLICATE_CERT", "CONTAINER_EMPTY_PASSWORD"],
    },
    {
        "case": "orphan",
        "group": "required",
        "index": 8,
        "purpose": "孤儿：私钥与证书来自两个不同密钥对，谁也不配谁",
        "pattern": "orphan",
        "cn": "orphan-cert.example",
        "serial": 0x1009,
        "offset_days": 365,
        "findings": [
            ("ORPHAN_CERT", "INFO", 1),
            ("ORPHAN_KEY", "INFO", 1),
            ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1),
        ],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "DUPLICATE_CERT"],
    },
    {
        "case": "pair",
        "group": "supplementary",
        "purpose": "配对正确：同一密钥对的 cert.pem + key.pem 互相配对，不产 ORPHAN_*",
        "pattern": "pair",
        "cn": "pair.example",
        "serial": 0x2001,
        "offset_days": 365,
        "findings": [("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["ORPHAN_CERT", "ORPHAN_KEY", "EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG"],
    },
    {
        "case": "same-cn",
        "group": "supplementary",
        "purpose": "不误配：同 CN 的两个不同密钥对，证书与私钥互不配对（按 SPKI，不按 CN）",
        "pattern": "same-cn",
        "cn": "shared.example",
        "serial": 0x2002,
        "offset_days": 365,
        "findings": [
            ("ORPHAN_CERT", "INFO", 1),
            ("ORPHAN_KEY", "INFO", 1),
            ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1),
        ],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "DUPLICATE_CERT"],
    },
    {
        "case": "cliff-none",
        "group": "supplementary",
        "purpose": "EXPIRY_CLIFF 不触发：窗口内只有 1 张不同证书",
        "pattern": "cliff",
        "count": 1,
        "serial_base": 0x3000,
        "offset_days": 10,
        "findings": [("EXPIRING", "WARN", 1), ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1)],
        "absent": ["EXPIRY_CLIFF", "EXPIRED", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY"],
    },
    {
        "case": "cliff-hit",
        "group": "supplementary",
        "purpose": "EXPIRY_CLIFF 触发：窗口内 3 张不同证书扎堆到期（按去重指纹计数）",
        "pattern": "cliff",
        "count": 3,
        "serial_base": 0x3100,
        "offset_days": 10,
        "findings": [
            ("EXPIRY_CLIFF", "WARN", 1),
            ("EXPIRING", "WARN", 3),
            ("PRIVATE_KEY_UNENCRYPTED", "WARN", 3),
        ],
        "absent": ["EXPIRED", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "empty-pass",
        "group": "supplementary",
        "purpose": "空口令容器：不带口令就能打开 → CONTAINER_EMPTY_PASSWORD",
        "pattern": "container-empty-password",
        "cn": "empty-pass.example",
        "serial": 0x4001,
        "offset_days": 365,
        "aliases": ["empty-pass"],
        "findings": [("CONTAINER_EMPTY_PASSWORD", "INFO", 1)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY",
                   "CONTAINER_TRUSTSTORE_WITH_KEY"],
    },
    {
        "case": "perm",
        "group": "supplementary",
        "purpose": "权限过宽：POSIX mode 0644 的私钥（POSIX-only，见 platform）",
        "pattern": "permissions",
        "cn": "perm.example",
        "serial": 0x4002,
        "offset_days": 365,
        "mode": 0o644,
        "platform": "posix",
        "findings": [
            ("PRIVATE_KEY_UNENCRYPTED", "WARN", 1),
            ("PERMISSION_TOO_OPEN", "WARN", 1),
        ],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "bundle",
        "group": "supplementary",
        "purpose": "多块 PEM：一个文件里 3 个证书块，逐块展开（offset 0/1/2）",
        "pattern": "bundle",
        "count": 3,
        "serial_base": 0x5000,
        "offset_days": 365,
        "findings": [("ORPHAN_CERT", "INFO", 3)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_KEY", "DUPLICATE_CERT"],
    },
    {
        "case": "broken-der",
        "group": "supplementary",
        "purpose": "坏 DER：截断字节 → PARSE_FAILED，stage=der，不整体失败",
        "pattern": "broken-der",
        "serial": 0x6001,
        "offset_days": 365,
        "findings": [("PARSE_FAILED", "WARN", 1)],
        "absent": ["EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG", "ORPHAN_CERT", "ORPHAN_KEY"],
    },
    {
        "case": "noise",
        "group": "supplementary",
        "purpose": "二进制噪声：非证书内容 → SKIP_BINARY，不是失败",
        "pattern": "noise",
        "findings": [("SKIP_BINARY", "INFO", 1)],
        "absent": ["PARSE_FAILED", "EXPIRED", "EXPIRING", "WEAK_KEY", "WEAK_SIG"],
    },
)

CASE_BY_NAME = {case["case"]: case for case in CASES}


# ── generation ──────────────────────────────────────────────────────────────


@dataclass
class Built:
    """One generated case: its artifacts and the declared expectations."""

    spec: dict[str, Any]
    inputs: list[str] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    container: dict[str, Any] | None = None


def _seed(case: str, suffix: str = "") -> str:
    return f"certledger-fixture|{case}|{suffix}"


def _validity(spec: dict[str, Any], *, days: int | None = None) -> tuple[int, int]:
    """Not-before fixed one year back; not-after moves with the case offset."""
    offset = int(spec.get("offset_days", 365)) if days is None else days
    not_after = AS_OF + offset * 86400
    not_before = AS_OF - 365 * 86400 if offset >= 0 else AS_OF - 400 * 86400
    return not_before, not_after


def _cert_artifact(
    built: Built,
    out_root: Path,
    rel: str,
    data: bytes,
    *,
    offset: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    meta = cert_metadata(data, offset=offset)
    entry: dict[str, Any] = {"path": rel, "kind": "cert", "format": "pem", "reproducible": "bytes"}
    if offset is not None:
        entry["offset"] = offset
    entry.update(meta)
    entry["sha256"] = hashlib.sha256(data).hexdigest()
    if extra:
        entry.update(extra)
    built.artifacts.append(entry)
    return entry


def _key_artifact(built: Built, out_root: Path, rel: str, path: Path, *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "path": rel,
        "kind": "key",
        "format": "pem",
        "reproducible": "bytes",
        **key_metadata(path),
        "sha256": sha256_file(path),
    }
    if extra:
        entry.update(extra)
    built.artifacts.append(entry)
    return entry


def _container_artifact(built: Built, out_root: Path, path: Path, password: bytes) -> None:
    """Record a container by its alias table, never by its bytes.

    A PKCS#12 carries a random salt and IV, so its file digest changes on every
    generation. Storing that digest here would make ``expected.json`` itself
    irreproducible — the truth file would differ between two runs while claiming
    to be a fixed reference. The alias table plus the contained fingerprints is
    the reproducible description (``data/README.md`` §4.4).
    """
    table = inspect_p12(path, password)
    rel = path.relative_to(out_root).as_posix()
    built.container = {**table, "path": rel}
    built.artifacts.append(
        {
            "path": rel,
            "kind": "container",
            "format": "pkcs12",
            "reproducible": "alias_table",
            "entry_count": len(table["entries"]),
        }
    )


def build_case(spec: dict[str, Any], out_root: Path, scratch: Path) -> Built:
    """Build one case. ``scratch`` holds signing material the case must not ship."""
    built = Built(spec=spec)
    name = spec["case"]
    directory = out_root / name
    directory.mkdir(parents=True, exist_ok=True)
    work = scratch / name
    work.mkdir(parents=True, exist_ok=True)
    not_before, not_after = _validity(spec)
    pattern = spec["pattern"]

    if pattern == "self-signed":
        key = deterministic_rsa(_seed(name), int(spec.get("bits", 2048)))
        key_path = directory / f"{name}.key"
        write_private_key(key, key_path)
        cert_path = directory / f"{name}.pem"
        make_certificate(
            key_path=key_path,
            out_path=cert_path,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            digest=spec.get("digest", "sha256"),
            san=spec["cn"],
        )
        _cert_artifact(built, out_root, cert_path.relative_to(out_root).as_posix(), cert_path.read_bytes())
        built.inputs = [cert_path.relative_to(out_root).as_posix()]
        if spec.get("with_key"):
            _key_artifact(built, out_root, key_path.relative_to(out_root).as_posix(), key_path)
            built.inputs.append(key_path.relative_to(out_root).as_posix())

    elif pattern == "orphan":
        # Two independent key pairs: the key never matches the certificate.
        key_a = deterministic_rsa(_seed(name, "key"), 2048)
        key_b = deterministic_rsa(_seed(name, "cert"), 2048)
        key_path = directory / "orphan.key"
        write_private_key(key_a, key_path)
        signing_key = work / "signing.key"
        write_private_key(key_b, signing_key)
        cert_path = directory / "orphan.crt"
        make_certificate(
            key_path=signing_key,
            out_path=cert_path,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        _key_artifact(built, out_root, "orphan/orphan.key", key_path)
        _cert_artifact(built, out_root, "orphan/orphan.crt", cert_path.read_bytes())
        built.inputs = ["orphan/orphan.key", "orphan/orphan.crt"]

    elif pattern == "pair":
        key = deterministic_rsa(_seed(name), 2048)
        key_path = directory / "key.pem"
        write_private_key(key, key_path)
        cert_path = directory / "cert.pem"
        make_certificate(
            key_path=key_path,
            out_path=cert_path,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        _cert_artifact(built, out_root, "pair/cert.pem", cert_path.read_bytes())
        _key_artifact(built, out_root, "pair/key.pem", key_path)
        built.inputs = ["pair/cert.pem", "pair/key.pem"]

    elif pattern == "same-cn":
        key_cert = deterministic_rsa(_seed(name, "cert"), 2048)
        key_only = deterministic_rsa(_seed(name, "key"), 2048)
        signing_key = work / "signing.key"
        write_private_key(key_cert, signing_key)
        cert_path = directory / "cert.pem"
        make_certificate(
            key_path=signing_key,
            out_path=cert_path,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        key_path = directory / "key.pem"
        write_private_key(key_only, key_path)
        _cert_artifact(built, out_root, "same-cn/cert.pem", cert_path.read_bytes())
        _key_artifact(built, out_root, "same-cn/key.pem", key_path)
        built.inputs = ["same-cn/cert.pem", "same-cn/key.pem"]

    elif pattern == "cliff":
        for index in range(int(spec["count"])):
            suffix = f"c{index + 1}"
            key = deterministic_rsa(_seed(name, suffix), 2048)
            key_path = directory / f"{suffix}.key"
            write_private_key(key, key_path)
            cert_path = directory / f"{suffix}.pem"
            make_certificate(
                key_path=key_path,
                out_path=cert_path,
                common_name=f"{name}-{suffix}.example",
                serial=int(spec["serial_base"]) + index,
                not_before=not_before,
                not_after=AS_OF + (int(spec["offset_days"]) + index * 5) * 86400,
                san=f"{name}-{suffix}.example",
            )
            _cert_artifact(built, out_root, cert_path.relative_to(out_root).as_posix(), cert_path.read_bytes())
            _key_artifact(built, out_root, key_path.relative_to(out_root).as_posix(), key_path)
            built.inputs += [
                cert_path.relative_to(out_root).as_posix(),
                key_path.relative_to(out_root).as_posix(),
            ]

    elif pattern == "bundle":
        chunks: list[bytes] = []
        for index in range(int(spec["count"])):
            suffix = f"b{index + 1}"
            key = deterministic_rsa(_seed(name, suffix), 2048)
            key_path = work / f"{suffix}.key"
            write_private_key(key, key_path)
            single = work / f"{suffix}.pem"
            make_certificate(
                key_path=key_path,
                out_path=single,
                common_name=f"bundle-{suffix}.example",
                serial=int(spec["serial_base"]) + index,
                not_before=not_before,
                not_after=not_after,
                san=f"bundle-{suffix}.example",
            )
            chunks.append(single.read_bytes())
        bundle_path = directory / "bundle.pem"
        bundle_bytes = b"".join(chunks)
        bundle_path.write_bytes(bundle_bytes)
        for index in range(int(spec["count"])):
            _cert_artifact(
                built,
                out_root,
                "bundle/bundle.pem",
                bundle_bytes,
                offset=index,
                extra={"block_count": int(spec["count"])},
            )
        built.inputs = ["bundle/bundle.pem"]

    elif pattern == "broken-der":
        key = deterministic_rsa(_seed(name), 2048)
        signing_key = work / "signing.key"
        write_private_key(key, signing_key)
        whole = work / "whole.pem"
        make_certificate(
            key_path=signing_key,
            out_path=whole,
            common_name="broken-der.example",
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san="broken-der.example",
        )
        der = [block for label, block in pem_blocks(whole.read_bytes()) if label == "CERTIFICATE"][0]
        truncated = der[: len(der) // 3]
        broken_path = directory / "broken.der"
        broken_path.write_bytes(truncated)
        built.artifacts.append(
            {
                "path": "broken-der/broken.der",
                "kind": "broken",
                "format": "der",
                "reproducible": "bytes",
                "sha256": hashlib.sha256(truncated).hexdigest(),
                "source_der_bytes": len(der),
                "truncated_to_bytes": len(truncated),
            }
        )
        built.inputs = ["broken-der/broken.der"]

    elif pattern == "noise":
        payload = bytearray()
        counter = 0
        while len(payload) < 512:
            payload += hashlib.sha256(f"{_seed(name, 'noise')}|{counter}".encode()).digest()
            counter += 1
        payload = payload[:512]
        payload[0] = 0x7F  # never a DER SEQUENCE tag
        payload[16] = 0x00  # guarantees "binary", not "unknown text"
        noise_path = directory / "noise.bin"
        noise_path.write_bytes(bytes(payload))
        built.artifacts.append(
            {
                "path": "noise/noise.bin",
                "kind": "noise",
                "format": "bin",
                "reproducible": "bytes",
                "sha256": hashlib.sha256(bytes(payload)).hexdigest(),
                "has_nul_byte": True,
            }
        )
        built.inputs = ["noise/noise.bin"]

    elif pattern == "permissions":
        key = deterministic_rsa(_seed(name), 2048)
        key_path = directory / "loose.key"
        write_private_key(key, key_path)
        cert_path = directory / "perm.pem"
        make_certificate(
            key_path=key_path,
            out_path=cert_path,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        os.chmod(key_path, int(spec["mode"]))
        _cert_artifact(built, out_root, "perm/perm.pem", cert_path.read_bytes())
        _key_artifact(built, out_root, "perm/loose.key", key_path, extra={"posix_mode": f"{int(spec['mode']):04o}"})
        built.inputs = ["perm/perm.pem", "perm/loose.key"]

    elif pattern == "container-multi-alias":
        key = deterministic_rsa(_seed(name), 2048)
        signing_key = work / "signing.key"
        write_private_key(key, signing_key)
        build_cert = work / "build.pem"
        make_certificate(
            key_path=signing_key,
            out_path=build_cert,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        container_path = directory / "multi-alias.p12"
        p12_multi_alias(build_cert, spec["aliases"], container_path)
        _container_artifact(built, out_root, container_path, CONTAINER_PASSWORD)
        built.inputs = ["multi-alias/multi-alias.p12"]

    elif pattern == "container-mixed":
        key = deterministic_rsa(_seed(name), 2048)
        signing_key = work / "signing.key"
        write_private_key(key, signing_key)
        build_cert = work / "build.pem"
        make_certificate(
            key_path=signing_key,
            out_path=build_cert,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        # A second, unrelated key pair supplies the trusted-only certificate.
        trusted_key = deterministic_rsa(_seed(name, "trusted"), 2048)
        trusted_signing_key = work / "trusted.key"
        write_private_key(trusted_key, trusted_signing_key)
        trusted_cert = work / "trusted.pem"
        make_certificate(
            key_path=trusted_signing_key,
            out_path=trusted_cert,
            common_name=spec["trusted_cn"],
            serial=spec["trusted_serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["trusted_cn"],
        )
        container_path = directory / "mixed.p12"
        p12_key_with_trusted(
            signing_key, build_cert, trusted_cert, spec["aliases"][0], spec["aliases"][1], container_path
        )
        _container_artifact(built, out_root, container_path, CONTAINER_PASSWORD)
        built.inputs = ["truststore-with-key/mixed.p12"]

    elif pattern == "container-empty-password":
        key = deterministic_rsa(_seed(name), 2048)
        signing_key = work / "signing.key"
        write_private_key(key, signing_key)
        build_cert = work / "build.pem"
        make_certificate(
            key_path=signing_key,
            out_path=build_cert,
            common_name=spec["cn"],
            serial=spec["serial"],
            not_before=not_before,
            not_after=not_after,
            san=spec["cn"],
        )
        container_path = directory / "empty-pass.p12"
        p12_empty_password(signing_key, build_cert, spec["aliases"][0], container_path)
        _container_artifact(built, out_root, container_path, b"")
        built.inputs = ["empty-pass/empty-pass.p12"]

    else:  # pragma: no cover - guards a typo in CASES
        raise GenerateError(f"未知样本形态: {pattern!r}")

    return built


# ── truth document ──────────────────────────────────────────────────────────


def build_expected(built_cases: Sequence[Built]) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for built in sorted(built_cases, key=lambda item: item.spec.get("index", 999)):
        spec = built.spec
        findings = [
            {"code": code, "severity": severity, "count": count} for code, severity, count in spec["findings"]
        ]
        findings.sort(key=lambda item: (item["severity"], item["code"]))
        entry: dict[str, Any] = {
            "case": spec["case"],
            "group": spec["group"],
            "purpose": spec["purpose"],
            "as_of": AS_OF,
            "as_of_utc": iso(AS_OF),
            "inputs": built.inputs,
            "artifacts": built.artifacts,
            "expect": {"findings": findings, "absent": sorted(spec["absent"])},
        }
        if "index" in spec:
            entry["index"] = spec["index"]
        if spec.get("platform"):
            entry["platform"] = spec["platform"]
        if built.container is not None:
            entry["expect"]["container"] = {
                "format": built.container["format"],
                "password": built.container["password"],
                "has_private_key": built.container["has_private_key"],
                "entries": [
                    {
                        "alias": item["alias"],
                        "entry_type": item["entry_type"],
                        "fingerprint_sha256": item["fingerprint_sha256"],
                        "spki_sha256": item["spki_sha256"],
                    }
                    for item in built.container["entries"]
                ],
            }
        cases.append(entry)

    return {
        "schema_version": 1,
        "kind": "fixture-truth",
        "note": (
            "输入 + 期望，不含任何观测值（没有 observed_*/actual_* 字段）。"
            "每条期望都能只凭本文件的 artifacts 独立复算，不需要 import 规则引擎。"
        ),
        "as_of": AS_OF,
        "as_of_utc": iso(AS_OF),
        "generator": {
            "entry": "fixtures/gen.sh",
            "engine": "fixtures/gen.py",
            "openssl_min_major": 3,
            "container_password": "changeit（公开夹具口令；空口令用例除外）",
            "policy": "src/certledger/data/default-policy.json",
        },
        "policy_numbers_used": {
            "warn_days": 30,
            "cliff_window_days": 30,
            "cliff_min_count": 3,
            "weak_key_rsa_min_bits": 2048,
        },
        "cases": cases,
    }


def write_manifest(out_root: Path, built_cases: Sequence[Built]) -> Path:
    """``fixtures/out/manifest.json`` — a generation record, never committed."""
    payload = {
        "as_of": AS_OF,
        "as_of_utc": iso(AS_OF),
        "openssl": run(["openssl", "version"], what="读取 openssl 版本").strip(),
        "cases": [
            {
                "case": built.spec["case"],
                "group": built.spec["group"],
                "purpose": built.spec["purpose"],
                # data/README §4.1 asks for name / format / expected result /
                # generation parameters per entry. The command is the one
                # invocation that regenerates this case alone.
                "generate": f"bash fixtures/gen.sh --only {built.spec['case']} --out <dir>",
                "files": [
                    {
                        "path": artifact["path"],
                        "format": artifact["format"],
                        "kind": artifact["kind"],
                        "reproducible": artifact["reproducible"],
                        "sha256": artifact.get("sha256"),
                    }
                    for artifact in sorted(built.artifacts, key=lambda item: (item["path"], item.get("offset", 0)))
                ],
                "expect": {
                    "findings": [code for code, _severity, _count in built.spec["findings"]],
                    "absent": list(built.spec["absent"]),
                },
            }
            for built in built_cases
        ],
    }
    path = out_root / "manifest.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


# ── verification ────────────────────────────────────────────────────────────


def recompute_expectations(entry: dict[str, Any], policy_numbers: dict[str, Any]) -> list[str]:
    """Re-derive the expected codes from the artifact description alone.

    This is the generator's own consistency check, not the rule engine: it
    compares declared numbers only (``not_after`` against ``as_of``,
    ``key_bits`` against the policy minimum, SPKI sets against each other).
    Keeping it here means ``--check`` can assert "the truth still follows from
    the inputs" without importing ``certledger.hygiene`` — which is exactly the
    independence ``plan/04`` §二.2 asks for.
    """
    codes: list[str] = []
    as_of = entry["as_of"]
    warn_end = as_of + int(policy_numbers["warn_days"]) * 86400
    cliff_end = as_of + int(policy_numbers["cliff_window_days"]) * 86400
    min_bits = int(policy_numbers["weak_key_rsa_min_bits"])
    min_count = int(policy_numbers["cliff_min_count"])

    container = entry["expect"].get("container")
    container_entries = container["entries"] if container else []

    # Findings are per *record*, and a record is one fingerprint — so the
    # artifact list must be folded into records before counting (plan/03 §②).
    # A container's private-key entry contributes both a key record and the
    # certificate record that goes with it.
    cert_records: dict[str, dict[str, Any]] = {}
    for cert in entry["artifacts"]:
        if cert["kind"] == "cert":
            cert_records.setdefault(cert["fingerprint_sha256"], cert)
    for item in container_entries:
        if item["entry_type"] == "privateKey":
            cert_records.setdefault(item["fingerprint_sha256"], {"spki_sha256": item["spki_sha256"]})
        else:
            cert_records.setdefault(item["fingerprint_sha256"], {"spki_sha256": item["spki_sha256"]})

    key_spki: set[str] = set()
    key_files: list[dict[str, Any]] = []
    for key in entry["artifacts"]:
        if key["kind"] == "key":
            if key["spki_sha256"]:
                key_spki.add(key["spki_sha256"])
            key_files.append(key)
    # Container-resident keys are protected by the container itself, so they do
    # not raise PRIVATE_KEY_UNENCRYPTED — the container signals cover them.
    for item in container_entries:
        if item["entry_type"] == "privateKey":
            key_spki.add(item["spki_sha256"])

    # Expiry and strength are judged per certificate record.
    for cert in cert_records.values():
        if "not_after" not in cert:  # a container entry declared only by its hashes
            continue
        not_after = parse_stamp(cert["not_after"])
        if not_after < as_of:
            codes.append("EXPIRED")
        elif not_after < warn_end:
            codes.append("EXPIRING")
        if cert["key_algo"] == "rsa" and cert["key_bits"] is not None and cert["key_bits"] < min_bits:
            codes.append("WEAK_KEY")
        if "sha1" in cert["sig_algo_name"].lower():
            codes.append("WEAK_SIG")

    in_window = {
        fingerprint
        for fingerprint, cert in cert_records.items()
        if "not_after" in cert and as_of <= parse_stamp(cert["not_after"]) < cliff_end
    }
    if len(in_window) >= min_count:
        codes.append("EXPIRY_CLIFF")

    # Orphans: one finding per record with no counterpart of the other kind.
    codes += ["ORPHAN_KEY"] * sum(1 for spki in key_spki if spki not in {c["spki_sha256"] for c in cert_records.values()})
    codes += ["ORPHAN_CERT"] * sum(
        1 for cert in cert_records.values() if cert["spki_sha256"] not in key_spki
    )

    # Duplicates: one finding per fingerprint with more than one source.
    sources: dict[str, int] = {}
    for cert in entry["artifacts"]:
        if cert["kind"] == "cert":
            sources[cert["fingerprint_sha256"]] = sources.get(cert["fingerprint_sha256"], 0) + 1
    for item in container_entries:
        sources[item["fingerprint_sha256"]] = sources.get(item["fingerprint_sha256"], 0) + 1
    codes += ["DUPLICATE_CERT"] * sum(1 for count in sources.values() if count > 1)

    if container:
        if container["has_private_key"] and any(item["entry_type"] != "privateKey" for item in container_entries):
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

    declared: list[str] = []
    for finding in entry["expect"]["findings"]:
        declared += [finding["code"]] * int(finding["count"])
    if sorted(codes) != sorted(declared):
        raise GenerateError(
            f"{entry['case']}: 真值与输入不自洽——按输入复算得 {sorted(codes)}，"
            f"声明为 {sorted(declared)}"
        )
    return codes


def check_against_truth(out_root: Path, truth: dict[str, Any]) -> int:
    """``--check``: compare a fresh generation against the committed truth.

    Byte comparison applies only to artifacts that are reproducible. Containers
    are compared by alias table and contained fingerprints, and the number
    skipped is printed rather than hidden (``plan/04`` §三, last bullet).
    """
    problems: list[str] = []
    compared_bytes = 0
    compared_tables = 0
    skipped_bytes = 0

    for entry in truth["cases"]:
        name = entry["case"]
        if not (out_root / name).is_dir():
            problems.append(f"{name}: 重生成后目录缺失")
            continue
        try:
            recompute_expectations(entry, truth["policy_numbers_used"])
        except GenerateError as error:
            problems.append(str(error))

        for artifact in entry["artifacts"]:
            path = out_root / artifact["path"]
            if not path.is_file():
                problems.append(f"{name}: 重生成后缺少 {artifact['path']}")
                continue
            if artifact["reproducible"] == "bytes":
                actual = sha256_file(path)
                if actual != artifact["sha256"]:
                    problems.append(
                        f"{name}: {artifact['path']} 不可复现"
                        f"（真值 {artifact['sha256'][:16]}… 实得 {actual[:16]}…）"
                    )
                else:
                    compared_bytes += 1
            else:
                skipped_bytes += 1
                declared = entry["expect"].get("container")
                if declared is None:
                    problems.append(f"{name}: 容器未在真值里声明 alias 表")
                    continue
                password = b"" if declared["password"] == "empty" else CONTAINER_PASSWORD
                table = inspect_p12(path, password)
                actual_entries = [
                    (item["alias"], item["entry_type"], item["fingerprint_sha256"], item["spki_sha256"])
                    for item in table["entries"]
                ]
                declared_entries = [
                    (item["alias"], item["entry_type"], item["fingerprint_sha256"], item["spki_sha256"])
                    for item in declared["entries"]
                ]
                if actual_entries != declared_entries:
                    problems.append(f"{name}: alias 表与真值不一致（实得 {actual_entries}）")
                else:
                    compared_tables += 1

    if problems:
        print("--check 失败：")
        for problem in problems:
            print(f"  FAIL  {problem}")
        return 1

    print(
        f"--check 通过：{len(truth['cases'])} 个用例；"
        f"字节级比对 {compared_bytes} 项；alias 表比对 {compared_tables} 项；"
        f"容器字节跳过 {skipped_bytes} 项（P12 盐/IV 随机，按 data/README §4.4 不比字节）"
    )
    return 0


def run_determinism(only: Sequence[str]) -> int:
    """Generate twice into scratch trees and compare every *reproducible* byte.

    Containers are compared by alias table, not by bytes: a PKCS#12 carries a
    random salt and IV, so its bytes differ by design and byte-comparing it
    would report a failure that means nothing (``data/README.md`` §4.4).
    """
    with tempfile.TemporaryDirectory(prefix="certledger-det-a-") as first_raw, tempfile.TemporaryDirectory(
        prefix="certledger-det-b-"
    ) as second_raw:
        first, second = Path(first_raw), Path(second_raw)
        built_first = generate_all(first, only, write_truth=False, emit_manifest=False, quiet=True)
        built_second = generate_all(second, only, write_truth=False, emit_manifest=False, quiet=True)
        all_names = sorted(
            path.relative_to(first).as_posix()
            for path in first.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        )
        byte_names = [name for name in all_names if not name.endswith(".p12")]
        containers = [name for name in all_names if name.endswith(".p12")]

        mismatched = [
            name
            for name in byte_names
            if not (second / name).is_file() or sha256_file(first / name) != sha256_file(second / name)
        ]
        table_mismatched = [
            name
            for name in containers
            if not (second / name).is_file()
            or _alias_table(first / name) != _alias_table(second / name)
        ]
        digests = {name: sha256_file(first / name) for name in byte_names}

        # The truth document is itself an artifact, and the one that is
        # committed. If it cannot reproduce byte-for-byte, then either the
        # generator drifted or it is recording something unstable (a container
        # digest, say) — and the file everything else is checked against would
        # be quietly moving.
        truth_first = json.dumps(build_expected(built_first), ensure_ascii=False, indent=2)
        truth_second = json.dumps(build_expected(built_second), ensure_ascii=False, indent=2)
        truth_stable = truth_first == truth_second

    if mismatched or table_mismatched or not truth_stable:
        print("确定性自检失败：")
        for name in mismatched:
            print(f"  FAIL  {name}（应当逐字节可复现）")
        for name in table_mismatched:
            print(f"  FAIL  {name}（容器 alias 表不可复现）")
        if not truth_stable:
            print("  FAIL  expected.json 本身两次生成不同（真值必须是稳定的）")
        return 1

    print(
        f"确定性自检通过：{len(byte_names)} 个文件两次生成字节全等；"
        f"{len(containers)} 个容器按 alias 表比对通过；"
        f"expected.json 两次生成字节全等"
        f"（容器字节跳过——P12 盐/IV 随机，按 data/README §4.4 不比字节）"
    )
    for name in sorted(digests):
        print(f"  {digests[name]}  {name}")
    return 0


def _alias_table(path: Path) -> list[tuple[Any, ...]]:
    """Comparable alias table for a container, trying both passwords."""
    for password in (CONTAINER_PASSWORD, b""):
        try:
            table = inspect_p12(path, password)
        except GenerateError:
            continue
        return [(item["alias"], item["entry_type"], item["fingerprint_sha256"]) for item in table["entries"]]
    return [("UNREADABLE", path.name)]


# ── orchestration ───────────────────────────────────────────────────────────


def generate_all(
    out_root: Path,
    only: Sequence[str] | None,
    *,
    write_truth: bool,
    emit_manifest: bool,
    quiet: bool = False,
) -> list[Built]:
    if only:
        unknown = set(only) - set(CASE_BY_NAME)
        if unknown:
            raise GenerateError(f"未知用例: {', '.join(sorted(unknown))}")
        selected = [case for case in CASES if case["case"] in set(only)]
    else:
        selected = list(CASES)
    if not selected:
        raise GenerateError("没有选中任何用例")

    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="certledger-build-") as scratch_raw:
        scratch = Path(scratch_raw)
        built = [build_case(case, out_root, scratch) for case in selected]

    if not quiet:
        for item in built:
            print(f"  generated  {item.spec['case']:<22} {len(item.artifacts)} 个产物")
        # plan/04 §三: the generator prints every file's sha256 as it goes, so a
        # reviewer can compare two runs without a second tool.
        print("  sha256:")
        for name in sorted(
            path.relative_to(out_root).as_posix()
            for path in out_root.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        ):
            digest = sha256_file(out_root / name)
            note = "  (容器：字节每次不同，按 alias 表比对)" if name.endswith(".p12") else ""
            print(f"    {digest}  {name}{note}")

    if emit_manifest:
        manifest = write_manifest(out_root, built)
        if not quiet:
            print(f"  manifest   {_display(manifest)}")

    # The committed truth is written only for a full run: ``--only`` must never
    # narrow the case list stored in the repository (plan/04 §三, last bullet).
    if write_truth and not only:
        EXPECTED_PATH.write_text(
            json.dumps(build_expected(built), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        if not quiet:
            print(f"  truth      {EXPECTED_PATH.relative_to(REPO_ROOT).as_posix()}（{len(built)} 个用例）")
    return built


def parse_only(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    names = [part.strip() for part in raw.split(",") if part.strip()]
    return names or None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fixtures/gen.sh",
        description="生成可复现的样本集与真值（八类必需 + 规则边界补充）。",
    )
    parser.add_argument("--out", metavar="DIR", default=None, help="产物目录（默认 fixtures/out）")
    parser.add_argument("--only", metavar="CASE[,CASE]", default=None, help="只生成这些用例（不改写 expected.json）")
    parser.add_argument("--check", action="store_true", help="重生成到临时目录并与 fixtures/expected.json 比对")
    parser.add_argument("--determinism", action="store_true", help="连生成两次并逐文件比 sha256")
    parser.add_argument("--list", action="store_true", help="列出全部用例名后退出")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list:
        for case in CASES:
            print(f"{case['case']:<22} {case['group']:<13} {case['purpose']}")
        return 0

    only = parse_only(args.only)
    out_root = Path(args.out).resolve() if args.out else DEFAULT_OUT

    try:
        if (args.check or args.determinism) and not EXPECTED_PATH.is_file():
            raise GenerateError("fixtures/expected.json 不存在；先跑一次完整生成")

        if args.determinism:
            return run_determinism(only or [])

        if args.check:
            truth = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
            if only:
                truth = {
                    **truth,
                    "cases": [entry for entry in truth["cases"] if entry["case"] in set(only)],
                }
            print(f"重生成到临时目录并比对 {EXPECTED_PATH.relative_to(REPO_ROOT).as_posix()}")
            with tempfile.TemporaryDirectory(prefix="certledger-check-") as tmp:
                generate_all(Path(tmp), only, write_truth=False, emit_manifest=False, quiet=True)
                return check_against_truth(Path(tmp), truth)

        print(f"生成样本到 {_display(out_root)}")
        built = generate_all(out_root, only, write_truth=True, emit_manifest=True)
        print(f"完成：{len(built)} 个用例，产物在 {_display(out_root)}")
        return 0

    except GenerateError as error:
        print(f"gen.sh: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
