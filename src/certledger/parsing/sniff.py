"""Content-based format sniffing: name what a file *is* from its bytes.

Extension-based dispatch is deliberately absent. ``server.crt`` may hold a
PKCS#7 bundle, ``ca.pem`` may hold 150 blocks, and ``backup`` may hold a JCEKS
store; a collector that trusts names reports the wrong thing with full
confidence. Every decision below comes from the bytes.

The sniff is two-stage because the answer has two different uses:

1. **cheap prefix classification** — decides whether a file is worth opening,
   which is what keeps a 10k-file tree fast (plan/06 R10). It reads a fixed
   window, never the whole file.
2. **authoritative decode** — ``cryptography`` decides whether those bytes are
   actually a certificate or a key (D13). ASN.1 walking is used only to name the
   container family, where ``cryptography`` has no public "what is this" API.

A file that is recognised but not decodable is a ``PARSE_FAILED`` with a stage,
not a silent skip: "we could not read this" and "there is nothing here" must
stay distinguishable (plan/03 §⑥).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)

from certledger.parsing import asn1
from certledger.parsing.pem import split_pem_blocks

#: JKS magic. JCEKS uses a *different* magic (``CECECECE``), verified on this
#: machine with JDK 26 keytool — plan/03 §① said both share ``FEEDFEED``, which
#: is wrong, and relying on it would have mislabelled every JCEKS file.
MAGIC_JKS: Final = b"\xfe\xed\xfe\xed"
MAGIC_JCEKS: Final = b"\xce\xce\xce\xce"

#: First tokens of an OpenSSH public key line.
OPENSSH_PREFIXES: Final = (
    b"ssh-rsa",
    b"ssh-ed25519",
    b"ssh-dss",
    b"ecdsa-sha2-",
    b"sk-ssh-ed25519@",
    b"sk-ecdsa-sha2-",
)

#: Formats named by ``detected_format`` (plan/03 §① 输出表).
PEM_CERT: Final = "pem-cert"
PEM_KEY: Final = "pem-key"
PEM_PKCS7: Final = "pem-pkcs7"
DER_CERT: Final = "der-cert"
PKCS7: Final = "pkcs7"
PKCS12: Final = "pkcs12"
JKS: Final = "jks"
JCEKS: Final = "jceks"
PKCS8: Final = "pkcs8"
OPENSSH_PUB: Final = "openssh-pub"
UNKNOWN: Final = "unknown"


@dataclass(frozen=True, slots=True)
class Item:
    """One thing found in one file.

    ``offset`` is the 0-based PEM block index (0 for every non-PEM format). It
    is the difference between "this bundle has a bad block" and "this bundle has
    a bad block at position 2".
    """

    offset: int
    detected_format: str
    der: bytes
    #: Populated when the bytes decoded; ``None`` means "named but not read".
    cert: x509.Certificate | None = None
    #: ``(key_object, encrypted)`` when a private key decoded.
    key: object | None = None
    key_encrypted: bool = False
    #: True when the private key needs a password we do not have.
    key_locked: bool = False


@dataclass(frozen=True, slots=True)
class SniffFailure:
    """A recognised file whose content could not be decoded."""

    offset: int
    stage: str
    detail: str


@dataclass(frozen=True, slots=True)
class SniffResult:
    items: tuple[Item, ...] = ()
    failures: tuple[SniffFailure, ...] = ()
    #: True when the bytes are not any known format (``SKIP_*`` territory).
    unknown: bool = False
    #: True when the content is binary noise rather than a text/ASN.1 attempt.
    binary: bool = False


def looks_binary(window: bytes) -> bool:
    """NUL byte in the prefix means binary (plan/03 §① step 3).

    A NUL is not a definitive "not a certificate" test — DER can contain one —
    so the caller only uses this after the structured attempts have failed.
    """
    return b"\x00" in window


def looks_textual(window: bytes) -> bool:
    """True when the prefix reads as text rather than as an ASN.1 structure.

    Needed because ``0x30`` is also the ASCII character ``'0'``: a checksum
    file, a git reflog, or a log whose first field is a timestamp begins with
    ``0x30`` and is *not* a DER blob that failed to parse. Reporting
    ``PARSE_FAILED`` for one would put false alarms into a report whose whole
    value is that its alarms are real. It is worse than that, in fact: a line of
    hex can read as a plausible tag/length pair, so the ASN.1 walk can "succeed"
    by accident and name a container type for a text file.

    The test is UTF-8 decodability plus "no raw control characters", not a
    printable-ASCII ratio — a log may legitimately be UTF-8 Chinese, and a ratio
    test would call that binary. No real DER blob decodes as UTF-8 while also
    carrying no control bytes: its tag, length, serial and signature bytes
    include sequences that are not valid UTF-8, and DER integers contain 0x00.
    """
    if not window or b"\x00" in window:
        return False
    sample = window[:1024]
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return not any(ord(char) < 32 and char not in "\t\n\r" for char in text)


#: Verdicts from :func:`classify_prefix`.
NEEDS_FULL: Final = "needs-full"
UNRECOGNISED: Final = "unrecognised"


def classify_prefix(window: bytes) -> str:
    """Decide from the prefix alone whether the rest of the file is worth reading.

    This is the cheap gate that keeps a large tree fast (plan/06 R10): only a
    file whose first 4096 bytes say "certificate / key / container / DER" is
    read to the end. Everything else is classified and abandoned.

    Containers are read in full even though their family is known from four
    bytes, because ``file_sha256`` must cover the whole file: a hash of the
    first 4096 bytes would not identify it, and two different containers would
    look identical to the "same file scanned twice" dedupe.

    Note the asymmetry: an unrecognised file is *not* "not a certificate" — it
    is "not a certificate we can recognise". The caller records that as
    ``SKIP_UNKNOWN_FORMAT`` or ``SKIP_BINARY`` depending on ``looks_binary``,
    which is a statement about what was seen, not about what exists.
    """
    if _starts_with_pem_marker(window):
        return NEEDS_FULL
    if window.startswith(MAGIC_JKS) or window.startswith(MAGIC_JCEKS):
        return NEEDS_FULL
    if _starts_with_openssh(window):
        return NEEDS_FULL  # usually one line, but read it whole to be safe
    if window[:1] == b"\x30":
        return NEEDS_FULL
    return UNRECOGNISED


def sniff_bytes(window: bytes, *, full: bytes | None = None) -> SniffResult:
    """Classify ``window`` (the sniff prefix) and decode when possible.

    ``full`` is the complete file content. The prefix is enough to *classify*,
    but decoding needs the whole block: a 4096-byte window cuts most
    certificates in half. Callers that only want a classification may omit
    ``full``; the result then carries formats without decoded objects.
    """
    payload = full if full is not None else window

    if _starts_with_pem_marker(window):
        return _sniff_pem(payload)

    if window.startswith(MAGIC_JKS):
        return SniffResult(items=(Item(offset=0, detected_format=JKS, der=b""),))

    if window.startswith(MAGIC_JCEKS):
        # JCEKS has its own magic (``CECECECE``), measured on this machine. No
        # ambiguity to record: the two formats are distinguishable from bytes.
        return SniffResult(items=(Item(offset=0, detected_format=JCEKS, der=b""),))

    if _starts_with_openssh(window):
        return _sniff_openssh(window)

    if window[:1] == b"\x30":
        return _sniff_der(payload)

    return SniffResult(unknown=True, binary=looks_binary(window))


# ── PEM ─────────────────────────────────────────────────────────────────────


def _starts_with_pem_marker(window: bytes) -> bool:
    head = window.lstrip(b"\xef\xbb\xbf").lstrip(b" \t\r\n")
    return head.startswith(b"-----BEGIN ")


def _sniff_pem(data: bytes) -> SniffResult:
    blocks, errors = split_pem_blocks(data)
    items: list[Item] = []
    failures: list[SniffFailure] = [
        SniffFailure(offset=error.offset, stage=error.stage, detail=error.detail)
        for error in errors
    ]

    for block in blocks:
        if block.kind == "cert":
            try:
                cert = _load_certificate(block.der)
            except Exception as error:  # noqa: BLE001 - any decode failure is a finding
                failures.append(
                    SniffFailure(offset=block.offset, stage="der", detail=_short(error))
                )
                continue
            items.append(Item(offset=block.offset, detected_format=PEM_CERT, der=block.der, cert=cert))

        elif block.kind in ("pkcs8", "pkcs8-encrypted", "key"):
            item = _decode_pem_key(block.der, block.offset, block.kind, block.headers)
            if isinstance(item, SniffFailure):
                failures.append(item)
            else:
                items.append(item)

        elif block.kind == "pkcs7":
            items.append(Item(offset=block.offset, detected_format=PEM_PKCS7, der=block.der))

        elif block.kind == "public":
            items.append(Item(offset=block.offset, detected_format=PEM_KEY, der=block.der))

        elif block.kind == "openssh-key":
            items.append(
                Item(offset=block.offset, detected_format=PEM_KEY, der=block.der, key_locked=True)
            )

        else:
            # A recognised PEM envelope with an unknown label: named, not read.
            items.append(Item(offset=block.offset, detected_format=UNKNOWN, der=block.der))

    return SniffResult(items=tuple(items), failures=tuple(failures))


def _decode_pem_key(
    der: bytes, offset: int, kind: str, headers: tuple[tuple[str, str], ...]
) -> Item | SniffFailure:
    encrypted = kind == "pkcs8-encrypted" or any(name == "Proc-Type" for name, _ in headers)
    try:
        key = load_der_private_key(der, password=None)
    except TypeError:
        # TypeError means "this key is encrypted and you passed no password".
        return Item(
            offset=offset, detected_format=PEM_KEY, der=der, key_encrypted=True, key_locked=True
        )
    except Exception as error:  # noqa: BLE001
        return SniffFailure(offset=offset, stage="der", detail=_short(error))
    return Item(
        offset=offset,
        detected_format=PEM_KEY,
        der=der,
        key=key,
        key_encrypted=encrypted,
    )


# ── OpenSSH ─────────────────────────────────────────────────────────────────


def _starts_with_openssh(window: bytes) -> bool:
    head = window.lstrip(b" \t\r\n")
    return any(head.startswith(prefix) for prefix in OPENSSH_PREFIXES)


def _sniff_openssh(window: bytes) -> SniffResult:
    first_line = window.split(b"\n", 1)[0]
    try:
        key = load_ssh_public_key(first_line)
    except Exception as error:  # noqa: BLE001
        return SniffResult(
            failures=(SniffFailure(offset=0, stage="openssh", detail=_short(error)),)
        )
    return SniffResult(items=(Item(offset=0, detected_format=OPENSSH_PUB, der=first_line, key=key),))


# ── DER ─────────────────────────────────────────────────────────────────────


def _sniff_der(data: bytes) -> SniffResult:
    """Name an ``0x30``-leading blob.

    Order matters and is deliberate: a certificate is the most common case, and
    ``x509.load_der_x509_certificate`` is strict enough that a PKCS#7 or PFX
    will not slip through it. Container families are named next, then keys.

    Text is rejected **before** any ASN.1 walk. ``0x30`` is also the ASCII digit
    ``'0'``, so a checksum file or a git reflog opens with the same byte as a
    SEQUENCE. Walking such a file as ASN.1 can "succeed" by accident — a line of
    hex reads as a plausible tag/length pair — and would then name a container
    type for a plain text file. Textiness is therefore checked first.
    """
    if looks_textual(data):
        return SniffResult(unknown=True, binary=False)

    try:
        cert = _load_certificate(data)
    except Exception:  # noqa: BLE001 - expected for non-certificates
        cert = None
    if cert is not None:
        return SniffResult(items=(Item(offset=0, detected_format=DER_CERT, der=data, cert=cert),))

    if asn1.looks_like_pfx(data):
        return SniffResult(items=(Item(offset=0, detected_format=PKCS12, der=data),))

    oid = asn1.content_info_oid(data)
    if oid == asn1.OID_PKCS7_SIGNED_DATA:
        return SniffResult(items=(Item(offset=0, detected_format=PKCS7, der=data),))

    if asn1.is_encrypted_pkcs8(data):
        return SniffResult(
            items=(
                Item(offset=0, detected_format=PKCS8, der=data, key_encrypted=True, key_locked=True),
            )
        )

    key = _try_der_key(data)
    if key is not None:
        return SniffResult(items=(Item(offset=0, detected_format=PKCS8, der=data, key=key),))

    if asn1.is_private_key_info(data):
        # Structurally a PrivateKeyInfo but the algorithm is unsupported here.
        return SniffResult(
            failures=(
                SniffFailure(offset=0, stage="der", detail="私钥结构可识别但算法不受支持"),
            )
        )

    # Starts like DER and is not DER we understand. Two very different things
    # look identical at this point:
    #
    # * a *truncated or corrupt* structure — a real problem, reported as
    #   ``PARSE_FAILED`` with ``stage=der``;
    # * ordinary text that happens to start with ``0x30`` (the ASCII digit
    #   '0') — a checksum file, a reflog, a log line. Not a certificate, not a
    #   failure. Reporting ``PARSE_FAILED`` here would put false alarms in a
    #   report whose value is that its alarms are real.
    if looks_textual(data):
        return SniffResult(unknown=True, binary=False)
    return SniffResult(
        failures=(SniffFailure(offset=0, stage="der", detail="DER 结构损坏或不是已知格式"),)
    )


def _try_der_key(data: bytes):
    try:
        return load_der_private_key(data, password=None)
    except TypeError:
        return None  # encrypted
    except Exception:  # noqa: BLE001
        pass
    try:
        return load_der_public_key(data)
    except Exception:  # noqa: BLE001
        return None


def _short(error: BaseException) -> str:
    """First line of an exception, trimmed. Never carries key material."""
    text = str(error).strip().splitlines()
    head = text[0] if text else type(error).__name__
    return head[:200]


def _load_certificate(data: bytes):
    """Decode DER, muting ``cryptography``'s advisory warnings.

    The library warns about certificates that violate RFC 5280 (for example a
    non-positive serial). That is a *property of the file*, not a defect in this
    tool, and a library warning printed to stderr would be noise in a report
    whose output is meant to be a stable document. Non-compliance of this kind
    belongs to the rule engine, not to a warning channel.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return x509.load_der_x509_certificate(data)


def load_pem_certificate(data: bytes) -> x509.Certificate:
    """Decode a single PEM certificate block (used by tests and by the store reader)."""
    return x509.load_pem_x509_certificate(data)


def load_pem_private_key_bytes(data: bytes, password: bytes | None = None):
    return load_pem_private_key(data, password=password)


def load_pem_public_key_bytes(data: bytes):
    return load_pem_public_key(data)


__all__ = [
    "DER_CERT",
    "Item",
    "JCEKS",
    "JKS",
    "MAGIC_JCEKS",
    "MAGIC_JKS",
    "OPENSSH_PUB",
    "PEM_CERT",
    "PEM_KEY",
    "PEM_PKCS7",
    "PKCS12",
    "PKCS7",
    "PKCS8",
    "UNKNOWN",
    "SniffFailure",
    "SniffResult",
    "UNRECOGNISED",
    "NEEDS_FULL",
    "classify_prefix",
    "load_pem_certificate",
    "looks_binary",
    "looks_textual",
    "sniff_bytes",
]
