"""Shared fixtures.

Tests never read real certificates from the host store and never write outside
``tmp_path`` (plan/04 §五).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:  # allow running pytest without an install
    sys.path.insert(0, str(SRC))

AS_OF = 1_900_000_000  # 2030-03-17T17:46:40Z, the sample baseline (plan/04 §四)


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def as_of() -> int:
    return AS_OF


@pytest.fixture
def policy():
    from certledger.policy.loader import load_policy

    return load_policy()
