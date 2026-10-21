"""Raw DER slices out of a certificate: the bytes as stored, never re-encoded (K1).

``cryptography`` decodes a certificate into objects, and every object can be
serialised back — but a re-serialisation is a *new* encoding produced by this
parser version, not the bytes that were in the file. Hashing that would make a
fingerprint depend on the library build, which is exactly what K1 forbids.

So the three values the ledger hashes are cut out of the original DER:

* ``subject_der`` / ``issuer_der`` — the ``Name`` TLVs, used as an
  issuer-grouping key (two certificates from one CA share an issuer hash even
  when their display strings differ in escaping);
* ``spki_der`` — the ``SubjectPublicKeyInfo`` TLV, the pairing key between a
  private key and its certificate (K4).

### Why not just call ``public_key()`` and re-serialise?

Both paths give the same 32 bytes for every certificate measured here (20
fixture certificates and 81 real Windows store certificates, compared
byte-for-byte). Two reasons to prefer the slice anyway:

1. K1 says hash what was stored. "It happens to match today" is not the
   contract, and a library upgrade is enough to break the coincidence.
2. On the real store set, **one certificate in 81** carries a SubjectPublicKey
   that ``cryptography`` refuses to deserialise (``CryptographyDeprecationWarning``
   territory: a legacy ``md5WithRSAEncryption`` root). Its SPKI octets are
   perfectly intact. Deriving the pairing key from the raw slice keeps that
   certificate pairable instead of silently dropping it — the failure mode D5
   warns about, an incomplete ledger that looks complete.

This is deliberately **not** a general X.509 parser. It knows the field order
of ``TBSCertificate`` (RFC 5280 §4.1) and nothing else; the caller already has a
decoded certificate, so the only job is locating three byte ranges.
"""

from __future__ import annotations

from dataclasses import dataclass

from certledger.parsing import asn1

#: ``TBSCertificate`` is fixed-order (RFC 5280 §4.1), with ``version`` optional:
#:
#:     0 [0] version (optional)   1 serialNumber   2 signature   3 issuer
#:     4 validity                 5 subject        6 subjectPublicKeyInfo
_ISSUER_FROM_VERSION = 3
_ISSUER_FROM_DEFAULT = 2


@dataclass(frozen=True, slots=True)
class CertParts:
    """Three DER ranges, each including its own tag and length octets."""

    subject_der: bytes
    issuer_der: bytes
    spki_der: bytes


def cert_parts(der: bytes) -> CertParts | None:
    """Cut ``subject`` / ``issuer`` / ``spki`` out of a certificate's DER.

    Returns ``None`` when the structure is not a certificate this module can
    navigate. The caller already holds a decoded certificate, so this is a
    belt-and-braces path: a structural surprise must degrade to "hash unknown",
    never abort a whole ledger over one odd file.
    """
    try:
        outer = asn1.read_tlv(der, 0)
        if outer.tag != asn1.TAG_SEQUENCE:
            return None
        children = asn1.read_children(der, outer)
        if len(children) != 3:  # Certificate ::= SEQUENCE {tbs, sigAlg, sigValue}
            return None
        spans = _child_spans(der, children[0])
    except asn1.Asn1Error:
        return None

    # v3 certificates carry ``[0] version`` and have seven fields; **v1 has
    # six** and starts directly at ``serialNumber``. Measured on the real store
    # set: three v1 roots (1997-era VeriSign/Microsoft) under a "seven or more"
    # guard lost their issuer hash silently. The guard is therefore expressed
    # relative to where the issuer starts, not as a fixed count.
    has_version = bool(spans) and spans[0].tag == asn1.TAG_CONTEXT_0
    issuer_at = _ISSUER_FROM_VERSION if has_version else _ISSUER_FROM_DEFAULT
    if len(spans) < issuer_at + 4:  # issuer, validity, subject, spki
        return None

    issuer, validity, subject, spki = (
        spans[issuer_at],
        spans[issuer_at + 1],
        spans[issuer_at + 2],
        spans[issuer_at + 3],
    )
    # All four are SEQUENCEs; anything else means the walk landed somewhere
    # unexpected and the slices below would be silently wrong.
    if {issuer.tag, validity.tag, subject.tag, spki.tag} != {asn1.TAG_SEQUENCE}:
        return None

    return CertParts(
        subject_der=der[subject.start : subject.end],
        issuer_der=der[issuer.start : issuer.end],
        spki_der=der[spki.start : spki.end],
    )


@dataclass(frozen=True, slots=True)
class _Span:
    """One child TLV: ``start`` is its tag octet, ``end`` the end of its value."""

    tag: int
    start: int
    end: int


def _child_spans(data: bytes, parent: asn1.Tlv) -> list[_Span]:
    """Walk direct children, keeping each child's **TLV** bounds.

    ``asn1.read_children`` reports value bounds only. A child starts where the
    previous child's value ended, so the TLV start is carried forward from the
    parent's own value start — which is what makes the slices above include the
    tag and length octets, as DER requires.
    """
    spans: list[_Span] = []
    cursor = parent.start
    for child in asn1.read_children(data, parent):
        spans.append(_Span(tag=child.tag, start=cursor, end=child.end))
        cursor = child.end
    return spans


__all__ = ["CertParts", "cert_parts"]
