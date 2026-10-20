"""Error types and the single exit-code boundary.

Every condition that maps to exit code 2 (input / policy / argument error) must
raise :class:`CliError`; ``cli.main`` is the only place that turns it into a
process exit code. Domain modules must never call ``sys.exit`` themselves.
"""

from __future__ import annotations

from dataclasses import dataclass

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2

#: Codes that mean "the input cannot be processed", not "the ledger found problems".
USAGE_CODES = (EXIT_USAGE,)


@dataclass(slots=True)
class CliError(Exception):
    """A user-facing input/policy/argument error (exit code 2).

    ``detail`` is shown to the user verbatim; it must never contain key
    material, passwords, host names or user names.
    """

    message: str
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.message}: {self.detail}" if self.detail else self.message
