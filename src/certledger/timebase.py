"""``--as-of``: the only notion of "now" in the whole program (K2).

No module may read ``datetime.now()`` / ``time.time()``; an AST-based gate test
asserts that. ``--as-of`` is mandatory and has no default: a report that silently
depends on the wall clock cannot be reproduced or diffed (plan/00 D7).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from certledger.errors import CliError

_EPOCH_RE = re.compile(r"^-?\d+$")


@dataclass(frozen=True, slots=True)
class AsOf:
    """A pinned instant.

    ``raw`` keeps the exact spelling the user typed (echoed verbatim in the
    report header); ``seconds`` is the integer Unix time used for all
    comparisons; ``iso`` is a canonical UTC rendering for display.
    """

    raw: str
    seconds: int

    @property
    def iso(self) -> str:
        return format_utc(self.seconds)

    @property
    def datetime(self) -> datetime:
        return datetime.fromtimestamp(self.seconds, tz=timezone.utc)


def format_utc(seconds: int) -> str:
    """Render integer seconds as ``YYYY-MM-DDTHH:MM:SSZ`` (no microseconds)."""
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_as_of(raw: str) -> AsOf:
    """Parse ``--as-of`` from Unix seconds or an ISO-8601 instant.

    An ISO timestamp must carry an explicit offset (``Z`` or ``±HH:MM``):
    a naive timestamp is ambiguous and silently guessing the local zone would
    make results depend on the machine.
    """
    if raw is None or not str(raw).strip():
        raise CliError("--as-of 必填", "该工具没有「当前时间」缺省值；请给出 Unix 秒或带时区的 ISO-8601 时刻")
    text = str(raw).strip()

    if _EPOCH_RE.match(text):
        return AsOf(raw=raw, seconds=int(text))

    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        moment = datetime.fromisoformat(candidate)
    except ValueError:
        raise CliError(
            "--as-of 无法解析",
            f"期望 Unix 秒或 ISO-8601（如 1900000000 或 2030-03-17T17:46:40Z），收到 {text!r}",
        ) from None

    if moment.tzinfo is None or moment.utcoffset() is None:
        raise CliError(
            "--as-of 缺少时区",
            f"{text!r} 没有时区偏移；请写成 2030-03-17T17:46:40Z 或带 +00:00 的形式",
        )
    return AsOf(raw=raw, seconds=int(moment.timestamp()))


def add_days(seconds: int, days: int) -> int:
    """Add whole days in UTC (used for ``EXPIRING`` windows)."""
    return int((datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(days=days)).timestamp())
