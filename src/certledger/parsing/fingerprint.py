"""All SHA-256 computation lives here (K1).

Not implemented yet (M3). The contract, decided now so no other module grows a
second hashing path in the meantime:

* certificate fingerprint = SHA-256 over the **DER bytes as parsed**, never over
  a re-encoded certificate;
* SPKI hash = SHA-256 over the SubjectPublicKeyInfo DER, used as the pairing key
  between a private key and its certificate (K4).
"""

from __future__ import annotations


def der_sha256(der: bytes) -> str:
    raise NotImplementedError("parsing.fingerprint.der_sha256 尚未实现")
