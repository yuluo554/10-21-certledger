"""CertLedger — local cryptographic asset ledger.

Single source of truth for the version string: ``pyproject.toml`` reads it from here
(``dynamic = ["version"]``), and a test asserts the installed metadata matches.
Changes here must not be duplicated anywhere else.
"""

from __future__ import annotations

__all__ = ["__version__", "SCHEMA_VERSION"]

__version__ = "0.1.1"

#: Bumped whenever the report/inventory JSON shape changes in a way that would
#: invalidate a stored baseline. Independent from ``__version__`` (see plan/02 §四).
SCHEMA_VERSION = 1
