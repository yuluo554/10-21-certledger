"""Just enough ASN.1 to tell one container from another.

This is **not** an X.509 parser and must never grow into one: certificates and
keys are decoded by ``cryptography`` (decision D13), because a hand-rolled
parser's bugs would land directly in the fingerprint and the fingerprint has to
be recomputable (K1). What is needed here is the two or three levels of
structure that separate a PKCS#7 ``ContentInfo`` from a PKCS#12 ``PFX`` from an
``EncryptedPrivateKeyInfo`` — all of which start with the same ``0x30``.

Everything raises :class:`Asn1Error` on malformed input and never guesses.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Universal, constructed, SEQUENCE.
TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_BIT_STRING = 0x03
TAG_CONTEXT_0 = 0xA0


class Asn1Error(ValueError):
    """Structural problem: truncated, indefinite length, or not a TLV at all."""


@dataclass(frozen=True, slots=True)
class Tlv:
    """One tag-length-value triple. ``start``/``end`` bound the *value*."""

    tag: int
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


def read_tlv(data: bytes, offset: int) -> Tlv:
    """Read the TLV starting at ``offset``.

    Indefinite lengths (BER ``0x80``) are rejected: DER forbids them, and a
    file that uses them is not one of the formats this tool claims to read.
    """
    if offset < 0 or offset >= len(data):
        raise Asn1Error(f"偏移 {offset} 越界（共 {len(data)} 字节）")

    tag = data[offset]
    cursor = offset + 1

    # High-tag-number form: 0x1f in the low five bits means "tag continues".
    if tag & 0x1F == 0x1F:
        while True:
            if cursor >= len(data):
                raise Asn1Error("高位数标签在文件末尾截断")
            byte = data[cursor]
            cursor += 1
            if not byte & 0x80:
                break

    if cursor >= len(data):
        raise Asn1Error("长度字段缺失（文件在标签后结束）")

    first = data[cursor]
    cursor += 1
    if first == 0x80:
        raise Asn1Error("不定长（BER）不被接受：DER 要求确定长度")
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count > 8:
            raise Asn1Error(f"长度字段 {count} 字节，超出合理范围")
        if cursor + count > len(data):
            raise Asn1Error("长度字段被截断")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count

    end = cursor + length
    if end > len(data):
        raise Asn1Error(
            f"声明长度 {length} 字节，实际只剩 {len(data) - cursor} 字节（截断）"
        )
    return Tlv(tag=tag, start=cursor, end=end)


def read_children(data: bytes, parent: Tlv) -> list[Tlv]:
    """Every direct child of ``parent``, in order."""
    children: list[Tlv] = []
    cursor = parent.start
    while cursor < parent.end:
        child = read_tlv(data, cursor)
        children.append(child)
        cursor = child.end
    return children


def decode_oid(raw: bytes) -> str:
    """Dotted-decimal form of an OBJECT IDENTIFIER value."""
    if not raw:
        raise Asn1Error("空 OID")
    first = raw[0]
    if first < 80:
        parts = [str(first // 40), str(first % 40)]
    else:  # 2.x — the "40 * X + Y" shortcut only holds for X in {0, 1}
        parts = ["2", str(first - 80)]

    value = 0
    started = False
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
            started = False
    if started:
        raise Asn1Error("OID 以续接位结束（截断）")
    return ".".join(parts)


#: The OIDs the sniffer needs to name. Kept as literals because these are
#: wire-format identifiers, not tunable thresholds (K3 applies to numbers).
OID_PKCS7_DATA = "1.2.840.113549.1.7.1"
OID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_PKCS12_PFX = "1.2.840.113549.1.12.10"
OID_PBES2 = "1.2.840.113549.1.5.13"


def content_info_oid(data: bytes) -> str | None:
    """The OID of a PKCS#7/PKCS#12 ``ContentInfo``, or ``None``.

    ``ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER, ... }`` — the
    same shape opens PKCS#7 (``signedData``) and PKCS#12 (``data``), which is
    why the outer OID alone cannot tell them apart.
    """
    try:
        outer = read_tlv(data, 0)
        if outer.tag != TAG_SEQUENCE:
            return None
        children = read_children(data, outer)
        if not children or children[0].tag != TAG_OID:
            return None
        return decode_oid(data[children[0].start : children[0].end])
    except Asn1Error:
        return None


def looks_like_pfx(data: bytes) -> bool:
    """True when this is a PKCS#12 ``PFX``.

    ``PFX ::= SEQUENCE { version INTEGER {v3(3)}, authSafe ContentInfo, ... }``
    and ``authSafe`` is a ``ContentInfo`` whose ``contentType`` is ``data``
    (``1.2.840.113549.1.7.1``) — **not** the PKCS#12 OID. Matching on
    ``1.2.840.113549.1.12.10`` would never fire: that OID lives in
    ``AuthenticatedSafe``, several levels down. Hence this walk: integer
    version, then a ContentInfo carrying ``data``.
    """
    try:
        outer = read_tlv(data, 0)
        if outer.tag != TAG_SEQUENCE:
            return False
        children = read_children(data, outer)
        if len(children) < 2 or children[0].tag != TAG_INTEGER:
            return False
        version_raw = data[children[0].start : children[0].end]
        if len(version_raw) != 1 or version_raw[0] != 3:
            return False
        auth_safe = children[1]
        if auth_safe.tag != TAG_SEQUENCE:
            return False
        fields = read_children(data, auth_safe)
        if not fields or fields[0].tag != TAG_OID:
            return False
        return decode_oid(data[fields[0].start : fields[0].end]) == OID_PKCS7_DATA
    except Asn1Error:
        return False


def is_encrypted_pkcs8(data: bytes) -> bool:
    """``EncryptedPrivateKeyInfo ::= SEQUENCE { SEQUENCE {OID}, OCTET STRING }``."""
    try:
        outer = read_tlv(data, 0)
        if outer.tag != TAG_SEQUENCE:
            return False
        children = read_children(data, outer)
        return (
            len(children) == 2
            and children[0].tag == TAG_SEQUENCE
            and children[1].tag == TAG_OCTET_STRING
        )
    except Asn1Error:
        return False


def is_private_key_info(data: bytes) -> bool:
    """``PrivateKeyInfo ::= SEQUENCE { INTEGER version, SEQUENCE {OID}, OCTET STRING }``."""
    try:
        outer = read_tlv(data, 0)
        if outer.tag != TAG_SEQUENCE:
            return False
        children = read_children(data, outer)
        return bool(children) and children[0].tag == TAG_INTEGER
    except Asn1Error:
        return False


__all__ = [
    "Asn1Error",
    "OID_PBES2",
    "OID_PKCS7_DATA",
    "OID_PKCS7_SIGNED_DATA",
    "OID_PKCS12_PFX",
    "TAG_CONTEXT_0",
    "TAG_OCTET_STRING",
    "TAG_OID",
    "TAG_SEQUENCE",
    "Tlv",
    "content_info_oid",
    "decode_oid",
    "is_encrypted_pkcs8",
    "is_private_key_info",
    "looks_like_pfx",
    "read_children",
    "read_tlv",
]
