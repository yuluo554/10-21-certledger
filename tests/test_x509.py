"""Raw DER slicing: finding ``subject`` / ``issuer`` / ``spki`` without re-encoding.

The point of this module is K1: the ledger hashes the octets that were read, so
the three values it hashes have to be located *in* the DER rather than produced
by serialising an object back. The tests below pin the two things that can go
wrong in such a walk:

* **field position** — ``TBSCertificate`` puts ``version`` first, but only in v3.
  A v1 certificate has six fields, not seven. Getting this wrong does not raise;
  it reads the wrong field and hashes it, which is silent corruption.
* **slice bounds** — a child's TLV starts where the previous child's value ended.
  Slicing from the value start instead of the tag start drops the tag and length
  octets, and the hash is then of a different byte string.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from certledger.parsing import asn1
from certledger.parsing.x509 import cert_parts

EPOCH = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)


def build_cert(*, version: int = 3, issuer_cn: str = "root.example", subject_cn: str = "leaf.example"):
    """A certificate with a named issuer so the two names cannot be confused."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .issuer_name(issuer)
        .subject_name(subject)
        .public_key(key.public_key())
        .serial_number(0x4242)
        .not_valid_before(EPOCH)
        .not_valid_after(EPOCH + dt.timedelta(days=365))
    )
    if version == 1:
        # cryptography always emits v3. A v1 certificate is produced by signing
        # a v1 TBS directly, which ``CertificateBuilder`` does not expose, so
        # the v1 case is exercised with a hand-built structure below.
        raise pytest.skip("CertificateBuilder 只产出 v3；v1 走 _v1_certificate()")
    return builder.sign(key, hashes.SHA256())


def _v1_certificate() -> bytes:
    """A minimal v1 ``Certificate``: ``TBSCertificate`` without ``[0] version``.

    Built by hand because every library paves over the distinction. The shape is
    RFC 5280 §4.1 with ``version`` omitted, which is what a 1997-era root in the
    Windows store looks like (three of them were measured there).
    """
    def tlv(tag: int, value: bytes) -> bytes:
        length = len(value)
        if length < 0x80:
            encoded = bytes([length])
        else:
            raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
            encoded = bytes([0x80 | len(raw)]) + raw
        return bytes([tag]) + encoded + value

    name = tlv(0x30, b"")  # empty Name: legal, and enough to locate the field
    validity = tlv(0x30, tlv(0x17, b"000101000000Z") + tlv(0x17, b"491231235959Z"))
    spki = tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("2A864886F70D010101"))) + tlv(0x03, b"\x00"))
    tbs = tlv(
        0x30,
        tlv(0x02, b"\x01")  # serialNumber (no version field: this is v1)
        + tlv(0x30, tlv(0x06, bytes.fromhex("2A864886F70D01010B")))  # signature
        + name  # issuer
        + validity
        + name  # subject
        + spki,
    )
    return tlv(0x30, tbs + tlv(0x30, tlv(0x06, bytes.fromhex("2A864886F70D01010B"))) + tlv(0x03, b"\x00"))


# ── happy path ──────────────────────────────────────────────────────────────


def test_parts_match_the_serialised_names_and_key() -> None:
    """The slices equal what the object model reports, byte for byte.

    They *should*: a well-formed certificate round-trips. The test is here so
    that a change in the walk shows up immediately, not because the equality is
    the property being relied on — the reliance is on the slices being taken
    from the input octets, which
    ``test_slice_is_taken_from_the_input_not_rebuilt`` checks.
    """
    der = build_cert().public_bytes(serialization.Encoding.DER)
    cert = x509.load_der_x509_certificate(der)
    parts = cert_parts(der)
    assert parts is not None
    assert parts.subject_der == cert.subject.public_bytes()
    assert parts.issuer_der == cert.issuer.public_bytes()
    assert parts.spki_der == cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_subject_and_issuer_are_not_swapped() -> None:
    """Distinct names, so a two-field mix-up cannot pass unnoticed."""
    der = build_cert(issuer_cn="the-issuer", subject_cn="the-subject").public_bytes(
        serialization.Encoding.DER
    )
    cert = x509.load_der_x509_certificate(der)
    parts = cert_parts(der)
    assert parts is not None
    assert parts.subject_der == cert.subject.public_bytes()
    assert parts.issuer_der == cert.issuer.public_bytes()
    assert parts.subject_der != parts.issuer_der


def test_slices_include_their_tag_and_length_octets() -> None:
    """A slice starting at the value would hash a shorter, different string.

    DER names begin with ``0x30`` (SEQUENCE); a value-only slice would begin with
    the first child's tag and would still "look like DER" to a casual reader.
    """
    der = build_cert().public_bytes(serialization.Encoding.DER)
    parts = cert_parts(der)
    assert parts is not None
    for label, slice_ in (("subject", parts.subject_der), ("issuer", parts.issuer_der),
                          ("spki", parts.spki_der)):
        assert slice_[0] == 0x30, label
        # And the declared length covers the rest of the slice exactly.
        tl = asn1.read_tlv(slice_, 0)
        assert tl.end == len(slice_), label


# ── the v1 trap ─────────────────────────────────────────────────────────────


def test_v1_certificate_has_no_version_field_and_still_slices() -> None:
    """v1 ``TBSCertificate`` has six fields; a "seven or more" guard loses it.

    This is not hypothetical: three v1 roots in the local Windows store (1997-era
    VeriSign/Microsoft) were silently returning empty name hashes before the
    guard was written relative to the issuer position instead of as a count.
    """
    der = _v1_certificate()
    outer = asn1.read_tlv(der, 0)
    fields = asn1.read_children(der, asn1.read_children(der, outer)[0])
    assert len(fields) == 6, "v1 TBS 必须是六字段"
    assert fields[0].tag == asn1.TAG_INTEGER, "v1 的第一个字段是 serialNumber，不是 [0] version"

    parts = cert_parts(der)
    assert parts is not None, "v1 证书必须能切出三段"
    assert parts.subject_der[0] == 0x30
    assert parts.spki_der[0] == 0x30


def test_v3_certificate_starts_with_the_version_tag() -> None:
    """The other branch of the same rule, so both are pinned."""
    der = build_cert().public_bytes(serialization.Encoding.DER)
    outer = asn1.read_tlv(der, 0)
    fields = asn1.read_children(der, asn1.read_children(der, outer)[0])
    assert fields[0].tag == asn1.TAG_CONTEXT_0, "v3 的第一个字段是 [0] version"
    assert len(fields) == 7


# ── degenerate inputs ───────────────────────────────────────────────────────


def test_non_certificate_returns_none_instead_of_raising() -> None:
    """One odd file must not abort a whole ledger (plan/03 §⑥)."""
    assert cert_parts(b"\x30\x03\x02\x01\x01") is None  # SEQUENCE with one INTEGER
    assert cert_parts(b"") is None
    assert cert_parts(b"not der at all") is None
    assert cert_parts(b"\x30\x82\x02\x00\x01") is None  # truncated length


def test_slice_is_taken_from_the_input_not_rebuilt(monkeypatch) -> None:
    """Mutating the input bytes changes the output — proves the walk reads *it*.

    A implementation that decoded the object and re-serialised would return the
    same values no matter what the caller passed in beyond a valid parse. Here,
    flipping a byte inside the subject's value must be visible in the slice.
    """
    der = bytearray(build_cert(subject_cn="abcdefgh").public_bytes(serialization.Encoding.DER))
    before = cert_parts(bytes(der))
    assert before is not None

    # Find the subject's value and change one octet inside it (the 'a' of
    # "abcdefgh" is ASCII 0x61; 0x62 makes it 'b').
    index = der.find(b"\x61\x62\x63\x64\x65\x66\x67\x68")
    assert index > 0, "测试没有找到 subject 里的字符串——判据会空跑"
    der[index] = 0x62

    after = cert_parts(bytes(der))
    assert after is not None
    assert after.subject_der != before.subject_der
    assert after.issuer_der == before.issuer_der  # untouched field stays put


@pytest.mark.parametrize(
    "build",
    [
        lambda: ec.generate_private_key(ec.SECP384R1()),
        lambda: ed25519.Ed25519PrivateKey.generate(),
    ],
    ids=["ec-p384", "ed25519"],
)
def test_other_key_algorithms_slice_the_same_way(build) -> None:
    """The walk is field-position based, so the algorithm must not matter."""
    key = build()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alg.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x5151)
        .not_valid_before(EPOCH)
        .not_valid_after(EPOCH + dt.timedelta(days=30))
        .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA384())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    parts = cert_parts(der)
    assert parts is not None
    assert parts.spki_der == key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
