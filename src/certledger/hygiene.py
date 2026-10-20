"""Hygiene rules over the ledger (not implemented yet).

Every rule must carry a ``rule_source`` (plan/03 §③); thresholds come from the
policy file only (K3). See ``plan/03`` for the nine rule families.
"""

from __future__ import annotations

from typing import Iterable

from certledger.timebase import AsOf


def evaluate(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    inventory_path: str | None,
    as_of: AsOf,
    policy,
    source: str,
) -> dict:
    raise NotImplementedError("hygiene.evaluate 尚未实现")
