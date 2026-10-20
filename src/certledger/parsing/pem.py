"""PEM (RFC 7468) block splitting.

One file may hold many blocks — a CA bundle is the normal case, not the exotic
one — so splitting returns every block with its **0-based offset** inside the
file. ``offset`` is what lets a later layer say "block 2 of ``ca-bundle.pem``
failed", which is the difference between an actionable report and "something in
this file is broken".

The splitter never raises for bad input. A malformed block becomes an
:class:`PemError` carrying the offset and the stage (``pem`` for a missing END
line, ``base64`` for a body that does not decode), and the scan continues with
the next block: one corrupt block in a 150-block trust bundle must not hide the
other 149.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

#: RFC 7468 label grammar, loosened slightly (labels in the wild carry dots).
_BEGIN_RE = re.compile(rb"^-----BEGIN ([A-Za-z0-9 ._/-]+)-----[ \t]*$")
_END_RE = re.compile(rb"^-----END ([A-Za-z0-9 ._/-]+)-----[ \t]*$")

#: ``Name: value`` header lines (``Proc-Type`` / ``DEK-Info`` for encrypted PEM).
_HEADER_RE = re.compile(rb"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$")

#: Which label means what. Anything absent is an unknown label, reported rather
#: than guessed: mapping an unknown label onto a known one is how a report ends
#: up describing something it never read.
LABEL_KINDS: dict[str, str] = {
    "CERTIFICATE": "cert",
    "X509 CERTIFICATE": "cert",
    "TRUSTED CERTIFICATE": "cert",
    "PRIVATE KEY": "pkcs8",
    "ENCRYPTED PRIVATE KEY": "pkcs8-encrypted",
    "RSA PRIVATE KEY": "key",
    "EC PRIVATE KEY": "key",
    "DSA PRIVATE KEY": "key",
    "PUBLIC KEY": "public",
    "PKCS7": "pkcs7",
    "CMS": "pkcs7",
    "OPENSSH PRIVATE KEY": "openssh-key",
}


@dataclass(frozen=True, slots=True)
class PemBlock:
    """One decoded block. ``der`` is the base64 body, decoded, untouched."""

    label: str
    kind: str
    der: bytes
    offset: int
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class PemError:
    """A block that could not be decoded. ``offset`` is the block's position."""

    offset: int
    stage: str
    detail: str


def looks_like_pem(window: bytes) -> bool:
    """True when the window *starts* with a PEM marker (a UTF-8 BOM is allowed).

    Deliberately anchored to the start. A text file that merely mentions
    ``-----BEGIN CERTIFICATE-----`` in prose is not a certificate file, and
    treating it as one would turn a README into a ``PARSE_FAILED`` finding.
    """
    head = window.lstrip(b"\xef\xbb\xbf")
    head = head.lstrip(b" \t\r\n")
    return head.startswith(b"-----BEGIN ")


def split_pem_blocks(data: bytes) -> tuple[list[PemBlock], list[PemError]]:
    """Split every PEM block out of ``data``.

    Returns ``(blocks, errors)``; both lists are in file order. Never raises for
    malformed content — that is the point of the errors list.
    """
    blocks: list[PemBlock] = []
    errors: list[PemError] = []

    lines = data.splitlines()
    index = 0
    offset = 0
    while index < len(lines):
        begin = _BEGIN_RE.match(lines[index])
        if not begin:
            index += 1
            continue

        label = begin.group(1).decode("ascii", "replace").strip().upper()
        kind = LABEL_KINDS.get(label, "unknown")
        body: list[bytes] = []
        headers: list[tuple[str, str]] = []
        started = index + 1
        index += 1

        closed = False
        while index < len(lines):
            end = _END_RE.match(lines[index])
            if end:
                closed = True
                break
            line = lines[index]
            if not body:
                header = _HEADER_RE.match(line)
                if header:
                    headers.append(
                        (
                            header.group(1).decode("ascii", "replace"),
                            header.group(2).decode("ascii", "replace").strip(),
                        )
                    )
                    index += 1
                    continue
            body.append(line)
            index += 1

        if not closed:
            errors.append(
                PemError(
                    offset=offset,
                    stage="pem",
                    detail=f"{label} 块从第 {started + 1} 行开始但没有 END 行",
                )
            )
            offset += 1
            break

        # Move past the END line before the next iteration.
        index += 1

        payload = b"".join(body)
        payload = re.sub(rb"[ \t\r\n]", b"", payload)
        try:
            der = base64.b64decode(payload, validate=True) if payload else b""
        except (binascii.Error, ValueError) as error:
            errors.append(
                PemError(offset=offset, stage="base64", detail=f"{label} 块 base64 损坏: {error}")
            )
            offset += 1
            continue

        blocks.append(
            PemBlock(
                label=label,
                kind=kind,
                der=der,
                offset=offset,
                headers=tuple(headers),
            )
        )
        offset += 1

    return blocks, errors


__all__ = ["LABEL_KINDS", "PemBlock", "PemError", "looks_like_pem", "split_pem_blocks"]
