"""Policy loading: zero literals in code, citations required, errors are exit-2."""

from __future__ import annotations

import json

import pytest

from certledger.errors import CliError
from certledger.policy.loader import load_policy


def test_bundled_policy_loads(policy) -> None:
    assert policy.version
    assert policy.get("hygiene.expiring.warn_days") == 30
    assert policy.get("report.default_fail_on") == "ERROR"


def test_policy_digest_is_stable(policy) -> None:
    """The report echoes a policy digest; it must be a function of the bytes only."""
    again = load_policy()
    assert policy.sha256 == again.sha256
    assert len(policy.sha256) == 64


def test_every_threshold_block_has_a_citation(policy) -> None:
    for block in (
        "hygiene.expiring",
        "hygiene.cliff",
        "hygiene.weak_key.rsa",
        "hygiene.weak_key.ec",
        "hygiene.weak_sig",
        "hygiene.nist_2031",
        "hygiene.permissions",
    ):
        assert policy.get(f"{block}.source"), block


def test_missing_threshold_is_rejected(tmp_path) -> None:
    data = json.loads(load_policy().raw)
    del data["hygiene"]["cliff"]["min_count"]
    path = tmp_path / "p.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CliError) as error:
        load_policy(path)
    assert "min_count" in str(error.value)


def test_uncited_threshold_is_rejected(tmp_path) -> None:
    """A judgement without a citation may not become a default (plan/01 §六)."""
    data = json.loads(load_policy().raw)
    data["hygiene"]["weak_key"]["rsa"]["source"] = ""
    path = tmp_path / "p.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CliError) as error:
        load_policy(path)
    assert "出处" in str(error.value)


def test_malformed_citation_shape_is_rejected(tmp_path) -> None:
    data = json.loads(load_policy().raw)
    data["hygiene"]["weak_sig"]["source"] = "because I said so"
    path = tmp_path / "p.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CliError):
        load_policy(path)


def test_wrong_type_is_rejected(tmp_path) -> None:
    data = json.loads(load_policy().raw)
    data["hygiene"]["expiring"]["warn_days"] = "thirty"
    path = tmp_path / "p.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CliError):
        load_policy(path)


def test_boolean_is_not_accepted_as_int(tmp_path) -> None:
    """``True`` is an ``int`` in Python; the validator must not be fooled."""
    data = json.loads(load_policy().raw)
    data["collect"]["max_file_bytes"] = True
    path = tmp_path / "p.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CliError):
        load_policy(path)


def test_invalid_json_is_rejected(tmp_path) -> None:
    path = tmp_path / "p.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(CliError) as error:
        load_policy(path)
    assert "JSON" in str(error.value)


def test_missing_file_is_rejected(tmp_path) -> None:
    with pytest.raises(CliError) as error:
        load_policy(tmp_path / "absent.json")
    assert "不存在" in str(error.value)


def test_default_policy_matches_documented_numbers() -> None:
    """The two documents that state the sample numbers must agree.

    plan/04 §四 lists the values used by fixtures; data/README.md §五 is the
    single definition point. This test pins the JSON to both.
    """
    policy = load_policy()
    assert policy.get("hygiene.expiring.warn_days") == 30
    assert policy.get("hygiene.cliff.window_days") == 30
    assert policy.get("hygiene.cliff.min_count") == 3
    assert policy.get("hygiene.weak_key.rsa.min_bits") == 2048
    assert policy.get("collect.max_file_bytes") == 8 * 1024 * 1024
    assert policy.get("collect.sniff_bytes") == 4096
