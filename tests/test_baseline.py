"""``--baseline``: what changed between two snapshots, and why it is called that.

Three categories, and the boundary between the last two is the whole point
(``plan/03`` §④):

* **added** — a certificate in the new report that the old one did not have;
* **removed** — the reverse;
* **rotated** — the *same name carried by the same public key* under a new
  fingerprint. The key survived, the certificate did not, which is what a renewal
  usually is. Re-issuing under a new key as well is **not** a rotation: it is one
  certificate gone and another arrived, and calling that a rotation would hide a
  key change inside a routine word.

Pairing is on ``(subject_der_sha256, spki_sha256)`` — the DER name hash, not the
display string, because two different names can render identically.

A baseline that is missing, is not JSON, or is a different document is exit 2
(see ``test_exit_codes``): diffing against an empty report would print every
certificate as "added" and call it a finding.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from certledger.pipeline import report
from certledger.policy.loader import load_policy
from certledger.timebase import parse_as_of

AS_OF = parse_as_of("1900000000")


def snapshot(*, roots, out_path, baseline=None):
    """Write one report and return the parsed document."""
    code = report(
        roots=[str(item) for item in roots],
        files=(),
        inventory_path=None,
        as_of=AS_OF,
        policy=load_policy(),
        json_path=str(out_path),
        markdown_path=None,
        baseline=str(baseline) if baseline else None,
        fail_on="none",
        top=None,
        redact=True,
        source="none",
    )
    assert code == 0
    return json.loads(out_path.read_text(encoding="utf-8"))


def roots_of(entry) -> set[str]:
    return {item["fingerprint_sha256"] for item in entry}


def rsa_key():
    """One key object, so two ``issue_certificate`` calls can build one identity.

    A fresh key per call would make the "unchanged" certificate a *different* one,
    and every diff assertion would then be measuring the key generation rather
    than the diff.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


KEPT_KEY = rsa_key()


def test_added_is_a_certificate_the_baseline_did_not_have(issue_certificate, tmp_path) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    issue_certificate(before_dir, name="old", cn="old.example", serial=0xA1, key=KEPT_KEY)
    issue_certificate(after_dir, name="old", cn="old.example", serial=0xA1, key=KEPT_KEY)
    issue_certificate(after_dir, name="new", cn="new.example", serial=0xA2)

    base = snapshot(roots=[before_dir], out_path=tmp_path / "base.json")
    now = snapshot(roots=[after_dir], out_path=tmp_path / "now.json", baseline=tmp_path / "base.json")

    diff = now["diff"]
    assert len(diff["added"]) == 1 and diff["added"][0]["subject"] == "CN=new.example"
    assert diff["removed"] == []
    assert diff["rotated"] == []
    # The rest of the report is untouched by the baseline: a diff is an addition
    # to the document, never a substitute for it.
    assert len(now["findings"]) > 0
    assert roots_of(base["certificates"]) < roots_of(now["certificates"])


def test_removed_is_a_certificate_the_new_report_lost(issue_certificate, tmp_path) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    issue_certificate(before_dir, name="kept", cn="kept.example", serial=0xB1, key=KEPT_KEY)
    issue_certificate(before_dir, name="gone", cn="gone.example", serial=0xB2)
    issue_certificate(after_dir, name="kept", cn="kept.example", serial=0xB1, key=KEPT_KEY)

    snapshot(roots=[before_dir], out_path=tmp_path / "base.json")
    now = snapshot(roots=[after_dir], out_path=tmp_path / "now.json", baseline=tmp_path / "base.json")

    diff = now["diff"]
    assert len(diff["removed"]) == 1 and diff["removed"][0]["subject"] == "CN=gone.example"
    assert diff["added"] == []
    assert diff["rotated"] == []


def test_rotated_is_the_same_key_under_a_new_certificate(issue_certificate, tmp_path) -> None:
    """One key, two certificates: a renewal, and it must be named as one.

    Both certificates are issued for the *same* key with the same subject, and
    differ only in serial and validity — so the DER differs, the SPKI does not.
    """
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"

    key = rsa_key()
    issue_certificate(
        before_dir,
        name="renew",
        cn="renew.example",
        serial=0xC1,
        key=key,
        not_valid_after=dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc),
    )
    reissued = issue_certificate(
        after_dir,
        name="renew",
        cn="renew.example",
        serial=0xC2,
        key=key,
        not_valid_after=dt.datetime(2034, 1, 1, tzinfo=dt.timezone.utc),
    )

    base = snapshot(roots=[before_dir], out_path=tmp_path / "base.json")
    now = snapshot(roots=[after_dir], out_path=tmp_path / "now.json", baseline=tmp_path / "base.json")

    diff = now["diff"]
    assert diff["added"] == [] and diff["removed"] == []
    assert len(diff["rotated"]) == 1
    entry = diff["rotated"][0]
    assert entry["subject"] == "CN=renew.example"
    assert entry["spki_sha256"] == reissued["spki_sha256"]
    assert entry["from"] == base["certificates"][0]["fingerprint_sha256"]
    assert entry["to"] == reissued["fingerprint_sha256"]
    assert entry["from"] != entry["to"], "重签必须换证书"


def test_a_new_key_is_removed_plus_added_not_rotated(issue_certificate, tmp_path) -> None:
    """Same subject, **different** key: one certificate gone, one arrived.

    This is the boundary the definition exists for. The subject string is
    identical, so a naive "same name ⇒ rotation" rule would call it a rotation and
    quietly hide the key change — which is the one fact about it that matters.
    """
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    old = issue_certificate(before_dir, name="swap", cn="swap.example", serial=0xD1)
    new = issue_certificate(after_dir, name="swap", cn="swap.example", serial=0xD2)

    assert old["subject"] == new["subject"]
    assert old["spki_sha256"] != new["spki_sha256"]

    snapshot(roots=[before_dir], out_path=tmp_path / "base.json")
    now = snapshot(roots=[after_dir], out_path=tmp_path / "now.json", baseline=tmp_path / "base.json")

    diff = now["diff"]
    assert diff["rotated"] == [], "换了密钥就不叫轮换"
    assert [item["subject"] for item in diff["added"]] == ["CN=swap.example"]
    assert [item["subject"] for item in diff["removed"]] == ["CN=swap.example"]
    assert diff["added"][0]["fingerprint_sha256"] == new["fingerprint_sha256"]
    assert diff["removed"][0]["fingerprint_sha256"] == old["fingerprint_sha256"]


def test_an_unchanged_snapshot_produces_an_empty_diff(issue_certificate, tmp_path) -> None:
    """Nothing changed must read as nothing changed, in all three categories."""
    root = tmp_path / "same"
    issue_certificate(root, name="one", cn="one.example", serial=0xE1)
    issue_certificate(root, name="two", cn="two.example", serial=0xE2)

    snapshot(roots=[root], out_path=tmp_path / "base.json")
    now = snapshot(roots=[root], out_path=tmp_path / "now.json", baseline=tmp_path / "base.json")

    assert now["diff"] == {"added": [], "removed": [], "rotated": []}


def test_the_diff_is_deterministic(issue_certificate, tmp_path) -> None:
    """Two runs against one baseline produce equal ``diff`` sections."""
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    issue_certificate(before_dir, name="a", cn="a.example", serial=0xF1)
    issue_certificate(after_dir, name="a", cn="a.example", serial=0xF1)
    issue_certificate(after_dir, name="b", cn="b.example", serial=0xF2)

    snapshot(roots=[before_dir], out_path=tmp_path / "base.json")
    first = snapshot(roots=[after_dir], out_path=tmp_path / "first.json",
                     baseline=tmp_path / "base.json")
    second = snapshot(roots=[after_dir], out_path=tmp_path / "second.json",
                      baseline=tmp_path / "base.json")
    assert first["diff"] == second["diff"]


def test_baseline_diff_survives_a_round_trip_through_disk(issue_certificate, tmp_path) -> None:
    """The baseline is read from the file the previous run wrote, not from memory.

    The previous run is deliberately a *real* report file — masked, key-ordered,
    written by ``render`` — so the reader is exercised against its own output
    rather than against a hand-built dict that could be shaped more conveniently
    than the real thing.
    """
    before_dir = tmp_path / "before"
    issue_certificate(before_dir, name="persisted", cn="persisted.example", serial=0x11)
    base_path = tmp_path / "base.json"
    snapshot(roots=[before_dir], out_path=base_path)

    stored = json.loads(base_path.read_text(encoding="utf-8"))
    assert stored["kind"] == "report"
    assert stored["certificates"][0]["fingerprint_sha256"]

    now = snapshot(roots=[tmp_path / "empty"], out_path=tmp_path / "now.json", baseline=base_path)
    assert len(now["diff"]["removed"]) == 1


@pytest.mark.parametrize("payload", ["not json at all", '{"kind": "collect"}'])
def test_a_baseline_that_is_not_a_report_is_exit_two(payload, tmp_path) -> None:
    from certledger.errors import CliError

    broken = tmp_path / "broken.json"
    broken.write_text(payload, encoding="utf-8")
    with pytest.raises(CliError):
        report(
            roots=[str(tmp_path)],
            files=(),
            inventory_path=None,
            as_of=AS_OF,
            policy=load_policy(),
            json_path=None,
            markdown_path=None,
            baseline=str(broken),
            fail_on="none",
            top=None,
            redact=True,
            source="none",
        )


def test_a_missing_baseline_is_exit_two(tmp_path) -> None:
    from certledger.errors import CliError

    with pytest.raises(CliError):
        report(
            roots=[str(tmp_path)],
            files=(),
            inventory_path=None,
            as_of=AS_OF,
            policy=load_policy(),
            json_path=None,
            markdown_path=None,
            baseline=str(tmp_path / "nope.json"),
            fail_on="none",
            top=None,
            redact=True,
            source="none",
        )