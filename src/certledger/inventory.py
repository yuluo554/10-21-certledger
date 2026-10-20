"""Normalized ledger: one record per fingerprint, sources merged (not implemented yet).

See plan/03 §②. Kept as a shell so the CLI surface is complete without
inventing answers.
"""

from __future__ import annotations

from typing import Iterable


def build(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    source: str,
    follow_symlinks: bool | None,
    policy,
) -> dict:
    raise NotImplementedError("inventory.build 尚未实现")
