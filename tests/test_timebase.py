"""``--as-of`` semantics: mandatory, offset-required, the only clock (K2)."""

from __future__ import annotations

import pytest

from certledger.errors import CliError
from certledger.timebase import AsOf, add_days, format_utc, parse_as_of


def test_epoch_seconds_round_trip() -> None:
    moment = parse_as_of("1900000000")
    assert moment.seconds == 1_900_000_000
    assert moment.raw == "1900000000"
    assert moment.iso == "2030-03-17T17:46:40Z"


def test_iso_with_z() -> None:
    moment = parse_as_of("2030-03-17T17:46:40Z")
    assert moment.seconds == 1_900_000_000


def test_iso_with_numeric_offset() -> None:
    assert parse_as_of("2030-03-17T18:46:40+01:00").seconds == 1_900_000_000


def test_raw_spelling_is_preserved_for_the_report_header() -> None:
    """The report echoes the value as typed, not a normalized form."""
    assert parse_as_of("2030-03-17T17:46:40Z").raw == "2030-03-17T17:46:40Z"


def test_naive_iso_is_rejected() -> None:
    with pytest.raises(CliError) as error:
        parse_as_of("2030-03-17T17:46:40")
    assert "时区" in str(error.value)


@pytest.mark.parametrize("value", ["", "   ", None])
def test_empty_is_rejected(value) -> None:
    with pytest.raises(CliError):
        parse_as_of(value)


@pytest.mark.parametrize("value", ["tomorrow", "2030-13-01T00:00:00Z", "1900000000.5"])
def test_garbage_is_rejected(value: str) -> None:
    with pytest.raises(CliError):
        parse_as_of(value)


def test_as_of_is_frozen_and_comparable_by_value() -> None:
    assert parse_as_of("1900000000") == AsOf(raw="1900000000", seconds=1_900_000_000)


def test_format_utc_has_second_precision_only() -> None:
    """No microseconds, no local timezone: the rendering must be reproducible."""
    assert format_utc(1_900_000_000) == "2030-03-17T17:46:40Z"
    assert format_utc(0) == "1970-01-01T00:00:00Z"


def test_add_days_handles_month_and_leap_boundaries() -> None:
    """Hand-checked against the stdlib rather than asserted from the same code."""
    from datetime import datetime, timedelta, timezone

    for start in (0, 1_900_000_000, 951_782_400, 1_709_164_800):
        for days in (-366, -31, -1, 0, 1, 30, 366):
            expected = int(
                (datetime.fromtimestamp(start, tz=timezone.utc) + timedelta(days=days)).timestamp()
            )
            assert add_days(start, days) == expected
