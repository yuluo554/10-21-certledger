"""Collector entry point (not implemented yet).

Deliberately a shell: it raises instead of returning an empty result. An empty
result would be indistinguishable from "this machine has no certificates", which
is exactly the kind of confident wrong answer this project is meant to rule out
(plan/03 §M0 status, plan/06 R8).
"""

from __future__ import annotations

from typing import Iterable


def collect(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    source: str,
    follow_symlinks: bool | None,
    max_size: int | None,
    policy,
) -> dict:
    raise NotImplementedError("collectors.collect 尚未实现")
