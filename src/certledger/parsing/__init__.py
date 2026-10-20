"""Parsers: PEM chunking, X.509, keys, PKCS#12, hashing (not implemented yet).

``fingerprint.py`` will be the **only** place computing SHA-256 over DER bytes
(K1); a second code path that re-encodes before hashing would make fingerprints
depend on the parser version.
"""
