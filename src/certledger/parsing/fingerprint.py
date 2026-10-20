"""All SHA-256 computation lives here (K1).

The contract, fixed before any other module could grow a second hashing path:

* certificate fingerprint = SHA-256 over the **DER bytes as parsed**, never over
  a re-encoded certificate;
* SPKI hash = SHA-256 over the SubjectPublicKeyInfo DER, used as the pairing key
  between a private key and its certificate (K4).

Re-encoding before hashing would make a fingerprint depend on the parser
version, so the same certificate would hash differently on two machines and the
baseline diff would silently stop matching. That is why there is exactly one
function here and why it takes bytes, not an object: there is nothing to
re-encode.
"""

from __future__ import annotations

import hashlib


def der_sha256(der: bytes) -> str:
    """Lowercase hex SHA-256 of ``der`` exactly as it was read.

    No normalisation, no re-serialisation, no whitespace stripping: the bytes
    that arrived are the bytes that are hashed (K1).
    """
    return hashlib.sha256(der).hexdigest()


__all__ = ["der_sha256"]
