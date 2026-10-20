"""Parsers: format sniffing, PEM chunking, ASN.1 peeking, hashing.

Layering, and why it is this shape:

* ``fingerprint.py`` is the **only** place computing SHA-256 over DER bytes
  (K1). A second code path that re-encodes before hashing would make a
  fingerprint depend on the parser version.
* ``asn1.py`` reads just enough structure to *name* a container family. It never
  becomes an X.509 parser: certificates and keys are decoded by
  ``cryptography`` (D13), because a hand-rolled parser's bugs land directly in
  the fingerprint.
* ``pem.py`` splits blocks and keeps their offsets; a corrupt block becomes a
  finding instead of taking the other blocks down with it.
* ``sniff.py`` turns bytes into named items, by content and never by extension.
"""
