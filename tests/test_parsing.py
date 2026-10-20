"""Parser internals: PEM splitting, ASN.1 peeking, format naming, hashing.

These are unit tests on small synthetic inputs, separate from
``test_collectors.py`` (which drives everything through the public collector and
the committed truth file). The split is deliberate: a malformed PEM block is
hard to produce as a fixture without committing broken bytes, and it is exactly
the case that must not take a 150-block bundle down with it.

The overriding rule here: **nothing raises for bad input**. A parser that throws
on a corrupt block turns "one block is bad" into "the whole scan failed", and
the user learns nothing about the other 149 blocks.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from certledger.parsing import asn1
from certledger.parsing.fingerprint import der_sha256
from certledger.parsing.pem import LABEL_KINDS, split_pem_blocks
from certledger.parsing.sniff import (
    DER_CERT,
    JCEKS,
    JKS,
    NEEDS_FULL,
    OPENSSH_PUB,
    PEM_CERT,
    PEM_KEY,
    PKCS12,
    PKCS8,
    UNRECOGNISED,
    classify_prefix,
    looks_binary,
    sniff_bytes,
)


def pem(label: str, body: bytes) -> bytes:
    return (
        f"-----BEGIN {label}-----\n".encode()
        + base64.encodebytes(body)
        + f"-----END {label}-----\n".encode()
    )


# ── fingerprint (K1) ───────────────────────────────────────────────────────


def test_der_sha256_hashes_the_bytes_it_was_given() -> None:
    """K1: no re-encoding. The function is a plain SHA-256 over the input."""
    import hashlib

    assert der_sha256(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert der_sha256(b"abc") != der_sha256(b"abd")


def test_der_sha256_is_not_sensitive_to_how_the_caller_got_the_bytes() -> None:
    """Two callers handing over equal bytes get equal hashes — nothing else."""
    a = bytes(range(256))
    b = bytes(bytearray(range(256)))
    assert der_sha256(a) == der_sha256(b)


# ── PEM splitting ──────────────────────────────────────────────────────────


def test_multiple_blocks_get_sequential_offsets() -> None:
    data = pem("CERTIFICATE", b"\x01\x02") + pem("CERTIFICATE", b"\x03\x04") + pem(
        "PRIVATE KEY", b"\x05\x06"
    )
    blocks, errors = split_pem_blocks(data)
    assert errors == []
    assert [block.offset for block in blocks] == [0, 1, 2]
    assert [block.kind for block in blocks] == ["cert", "cert", "pkcs8"]
    assert [block.der for block in blocks] == [b"\x01\x02", b"\x03\x04", b"\x05\x06"]


def test_bad_base64_is_an_error_with_offset_and_stage() -> None:
    data = pem("CERTIFICATE", b"") .replace(b"\n", b"\n!!!!\n", 1)
    blocks, errors = split_pem_blocks(data)
    assert blocks == []
    assert len(errors) == 1
    assert errors[0].stage == "base64"
    assert errors[0].offset == 0


def test_bad_block_does_not_hide_the_good_one_after_it() -> None:
    """The whole point of returning errors: one corrupt block, not a dead scan."""
    good = pem("CERTIFICATE", b"\x01\x02")
    broken = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
    blocks, errors = split_pem_blocks(broken + good)
    assert len(blocks) == 1
    assert blocks[0].offset == 1
    assert len(errors) == 1
    assert errors[0].offset == 0


def test_missing_end_line_is_a_pem_stage_error() -> None:
    blocks, errors = split_pem_blocks(b"-----BEGIN CERTIFICATE-----\nMIIB\n")
    assert blocks == []
    assert errors[0].stage == "pem"


def test_unknown_label_is_kept_with_kind_unknown() -> None:
    blocks, errors = split_pem_blocks(pem("FROBNICATE", b"\x00\x00"))
    assert errors == []
    assert blocks[0].kind == "unknown"
    assert blocks[0].label == "FROBNICATE"


def test_encrypted_pem_headers_are_captured() -> None:
    data = (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"Proc-Type: 4,ENCRYPTED\n"
        b"DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n"
        b"\n"
        b"AAAA\n"
        b"-----END RSA PRIVATE KEY-----\n"
    )
    blocks, errors = split_pem_blocks(data)
    assert errors == []
    headers = dict(blocks[0].headers)
    assert headers["Proc-Type"] == "4,ENCRYPTED"
    assert headers["DEK-Info"].startswith("AES-128-CBC")


def test_prose_mentioning_a_marker_is_not_a_pem_file() -> None:
    """A README that quotes a PEM header is not a certificate file."""
    text = b"To create one, run openssl and paste -----BEGIN CERTIFICATE----- etc.\n"
    blocks, errors = split_pem_blocks(text)
    assert blocks == []
    assert errors == []


def test_label_table_covers_the_eight_declared_classes() -> None:
    """The label map is the contract for PEM-side format naming."""
    expected_kinds = {"cert", "pkcs8", "pkcs8-encrypted", "key", "public", "pkcs7", "openssh-key"}
    assert set(LABEL_KINDS.values()) == expected_kinds


# ── ASN.1 ──────────────────────────────────────────────────────────────────


def test_asn1_rejects_truncated_length() -> None:
    with pytest.raises(asn1.Asn1Error):
        asn1.read_tlv(b"\x30\x82\x01\x00", 0)


def test_asn1_rejects_indefinite_length() -> None:
    """BER indefinite lengths are not DER; accepting them would mean guessing."""
    with pytest.raises(asn1.Asn1Error):
        asn1.read_tlv(b"\x30\x80\x00\x00", 0)


def test_asn1_decodes_a_known_oid() -> None:
    # 1.2.840.113549.1.7.2 signedData
    raw = bytes.fromhex("2A864886F70D010702")
    assert asn1.decode_oid(raw) == "1.2.840.113549.1.7.2"


def test_asn1_rejects_empty_oid() -> None:
    with pytest.raises(asn1.Asn1Error):
        asn1.decode_oid(b"")


def test_pkcs12_detection_is_false_for_a_certificate() -> None:
    """A certificate is a SEQUENCE too; the PFX walk must not accept it."""
    from pathlib import Path

    out = Path(__file__).resolve().parent.parent / "fixtures" / "out"
    cert_path = out / "healthy" / "healthy.pem"
    if not cert_path.is_file():
        pytest.skip("fixtures/out 未生成")
    der = split_pem_blocks(cert_path.read_bytes())[0][0].der
    assert asn1.looks_like_pfx(der) is False


# ── format naming ──────────────────────────────────────────────────────────


def test_classify_prefix_recognises_each_family() -> None:
    assert classify_prefix(b"-----BEGIN CERTIFICATE-----\n") == NEEDS_FULL
    assert classify_prefix(b"\xef\xbb\xbf-----BEGIN CERTIFICATE-----\n") == NEEDS_FULL
    assert classify_prefix(b"\x30\x82\x01\x00") == NEEDS_FULL
    assert classify_prefix(b"\xfe\xed\xfe\xed") == NEEDS_FULL
    assert classify_prefix(b"\xce\xce\xce\xce") == NEEDS_FULL
    assert classify_prefix(b"ssh-ed25519 AAAAC3Nz") == NEEDS_FULL
    assert classify_prefix(b"just some text\n") == UNRECOGNISED
    assert classify_prefix(b"") == UNRECOGNISED


def test_openssh_public_key_is_named_and_decoded() -> None:
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    line = key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    result = sniff_bytes(line[:4096], full=line)
    assert result.items[0].detected_format == OPENSSH_PUB
    assert result.items[0].key is not None
    assert result.failures == ()


def test_malformed_openssh_line_becomes_a_failure_not_a_crash() -> None:
    result = sniff_bytes(b"ssh-ed25519 not-actually-base64\n")
    assert result.items == ()
    assert len(result.failures) == 1
    assert result.failures[0].stage == "openssh"


def test_truncated_der_is_a_parse_failure_with_stage_der() -> None:
    result = sniff_bytes(b"\x30\x82\x02\x00\x01\x02\x03", full=b"\x30\x82\x02\x00\x01\x02\x03")
    assert result.items == ()
    assert result.failures[0].stage == "der"


def test_looks_binary_flags_nul_bytes() -> None:
    assert looks_binary(b"\x00\x01\x02") is True
    assert looks_binary(b"plain text") is False


def test_text_starting_with_ascii_zero_is_not_der() -> None:
    """``0x30`` is both SEQUENCE and the digit '0' — a real false-positive trap.

    A git reflog, a checksum file and a timestamped log all begin with ``0x30``.
    Walking one as ASN.1 can "succeed" by accident, so the text check runs
    first; without it these would be reported as corrupt DER or, worse, as a
    container.
    """
    reflog = (
        b"0000000000000000000000000000000000000000 "
        b"bba7d8fda7b126c464ac45815b98b482f9549b30 "
        b"user <user@example.invalid> 1700000000 +0800\tcommit: initial\n"
    )
    result = sniff_bytes(reflog[:4096], full=reflog)
    assert result.failures == ()
    assert result.items == ()
    assert result.unknown is True
    assert result.binary is False


def test_utf8_text_with_non_ascii_is_still_text() -> None:
    """A log in Chinese must not be mistaken for binary or for corrupt DER."""
    from certledger.parsing.sniff import looks_textual

    assert looks_textual("0123 提交：初始化仓库\n".encode("utf-8")) is True
    assert looks_textual(b"0\x00binary") is False


def test_corrupt_der_still_reports_parse_failed() -> None:
    """The text check must not swallow the real corruption case.

    ``broken-der/broken.der`` is a truncated certificate: not text, so it still
    reaches the DER branch and is reported with ``stage=der``.
    """
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "fixtures" / "out" / "broken-der" / "broken.der"
    if not path.is_file():
        pytest.skip("fixtures/out 未生成")
    data = path.read_bytes()
    result = sniff_bytes(data[:4096], full=data)
    assert result.unknown is False
    assert len(result.failures) == 1
    assert result.failures[0].stage == "der"


def test_short_window_of_an_empty_file_is_unrecognised() -> None:
    assert sniff_bytes(b"").unknown is True


@pytest.mark.parametrize(
    "label,kind",
    [
        ("CERTIFICATE", "cert"),
        ("PRIVATE KEY", "pkcs8"),
        ("ENCRYPTED PRIVATE KEY", "pkcs8-encrypted"),
        ("RSA PRIVATE KEY", "key"),
        ("PUBLIC KEY", "public"),
        ("PKCS7", "pkcs7"),
        ("OPENSSH PRIVATE KEY", "openssh-key"),
    ],
)
def test_each_label_maps_to_its_kind(label: str, kind: str) -> None:
    blocks, _ = split_pem_blocks(pem(label, b"\x00"))
    assert blocks[0].kind == kind
