"""Container view: alias tables, degradation, and the password's route.

``plan/00`` 招牌动词表 names this file against ``certledger containers
--show-aliases``, and the claims are the ones that would be easy to fake:

* a multi-alias store lists **every** alias, with the duplicated fingerprint
  visible in ``same_fingerprint_aliases`` — the column nothing outside the file
  can compute;
* a store that cannot be opened degrades to ``CONTAINER_UNREADABLE`` and the
  process still exits 0 (D2/D11): a machine without a JDK is not a machine whose
  certificates are wrong;
* the password never reaches ``argv``, disk or a report — asserted by looking at
  the actual ``argv`` a child process is handed;
* PKCS#12 and JKS go through different readers, and the PKCS#12 reader is the one
  that sees the bag structure ``keytool`` folds away.

The PKCS#12 samples are built here with ``cryptography`` so the tests run
everywhere. The JKS ones need a JDK and skip without one — a skip is honest here
because the *product* degrades in exactly that situation, and that degradation is
itself asserted.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from certledger.containers import (
    DEFAULT_PASSWORD_ENV,
    KEYTOOL_ENV,
    find_keytool,
    inspect,
    read_container,
)
from certledger.errors import CliError
from certledger.policy.loader import load_policy

PASSWORD = "fixture-container-pass"


def run_cli(*argv: str) -> tuple[int, str, str]:
    import io
    import sys

    from certledger.cli import main

    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = main(list(argv))
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return code, out.getvalue(), err.getvalue()


# ── sample material ─────────────────────────────────────────────────────────


def make_key():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_certificate(key, cn: str, serial: int):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(dt.datetime(2029, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2034, 1, 1, tzinfo=dt.timezone.utc))
        .sign(key, hashes.SHA256())
    )


def write_multi_alias_p12(path, *, password: bytes, aliases) -> bytes:
    """One certificate under several aliases, and no key — the ``multi-alias`` shape.

    Built the way ``fixtures/gen.py`` builds the sample: every alias is an
    additional certificate bag, which is exactly how one file comes to hold one
    asset twice. A store built the other way (one key bag plus one extra) could
    not show the duplication at all.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    certificate = make_certificate(make_key(), "multi-alias.example", 0x1006)
    extra = [
        pkcs12.PKCS12Certificate(certificate, friendly_name=alias.encode()) for alias in aliases
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            None, None, None, extra, serialization.BestAvailableEncryption(password)
        )
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def write_key_with_trusted_p12(path, *, password: bytes, alias: str, trusted_alias: str) -> bytes:
    """A key bag plus an unrelated trusted certificate — the ``truststore-with-key`` shape.

    The extra certificate has a **different public key**, which is what
    distinguishes "a trust store that accidentally holds a key" from "a key store
    with a chain".
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    key = make_key()
    certificate = make_certificate(key, "key-entry.example", 0x1007)
    trusted = make_certificate(make_key(), "trusted-only.example", 0x1008)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            alias.encode(),
            key,
            certificate,
            [pkcs12.PKCS12Certificate(trusted, friendly_name=trusted_alias.encode())],
            serialization.BestAvailableEncryption(password),
        )
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def write_jks(path, *, password: str, alias: str = "jks-entry", store_type: str = "JKS"):
    """Create a keystore with ``keytool``, keeping the password out of ``argv``.

    Even the *fixture* is built with ``-storepass:env``: a test that published the
    password in its own process list would be demonstrating the thing the product
    is asserted not to do.
    """
    keytool = find_keytool()
    assert keytool is not None
    variable = "CONTAINER_TEST_KEYPASS"
    env = dict(os.environ)
    env[variable] = password
    argv = [
        keytool,
        "-genkeypair",
        "-alias",
        alias,
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-dname",
        f"CN={alias}.example",
        "-validity",
        "365",
        "-storetype",
        store_type,
        "-keystore",
        str(path),
        "-storepass:env",
        variable,
        "-keypass:env",
        variable,
        "-noprompt",
    ]
    completed = subprocess.run(argv, capture_output=True, timeout=120, env=env)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return path


needs_keytool = pytest.mark.skipif(
    find_keytool() is None, reason="本机没有 keytool：容器视图按设计降级，另有专门用例"
)


# ── the alias table ─────────────────────────────────────────────────────────


def test_a_multi_alias_store_lists_every_alias(monkeypatch, tmp_path) -> None:
    """Two aliases, one certificate: the table must show both and connect them."""
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, PASSWORD)
    path = tmp_path / "multi.p12"
    write_multi_alias_p12(
        path, password=PASSWORD.encode(), aliases=["multi-primary", "multi-secondary"]
    )
    document = inspect(
        paths=[str(path)], show_aliases=True, password_env=None,
        policy=load_policy(), json_path=None,
    )
    container = document["containers"][0]
    assert container["format"] == "pkcs12"
    assert container["password"] == "set"
    assert container["has_private_key"] is False

    entries = container["entries"]
    assert [item["alias"] for item in entries] == ["multi-primary", "multi-secondary"]
    fingerprints = {item["fingerprint_sha256"] for item in entries}
    assert len(fingerprints) == 1, "同一证书两个 alias 必须共用同一指纹"
    for item in entries:
        assert set(item["same_fingerprint_aliases"]) == {
            other["alias"] for other in entries if other["alias"] != item["alias"]
        }
    assert document["summary"] == {
        "containers": 1,
        "entries": 2,
        "with_private_key": 0,
        "unreadable": 0,
    }


def test_show_aliases_off_reports_a_count_instead_of_the_table(monkeypatch, tmp_path) -> None:
    """"Three entries" and "we did not list them" must stay different answers."""
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, PASSWORD)
    path = tmp_path / "multi.p12"
    write_multi_alias_p12(path, password=PASSWORD.encode(), aliases=["a", "b"])
    document = inspect(
        paths=[str(path)], show_aliases=False, password_env=None,
        policy=load_policy(), json_path=None,
    )
    container = document["containers"][0]
    assert "entries" not in container
    assert container["entry_count"] == 2
    assert document["summary"]["entries"] == 2


def test_an_empty_password_store_says_so(tmp_path) -> None:
    """A store that opens with no password is the signal, so it is named.

    The store here holds a key and no certificate, which is deliberate: a key bag
    without its certificate is a legitimate store, and a reader that required the
    certificate would drop the key and report an empty box. The entry is therefore
    asserted too, not only the password state.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    key = make_key()
    path = tmp_path / "open.p12"
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"open", key, None, None, serialization.NoEncryption()
        )
    )
    reading = read_container(str(path))
    assert reading.password == "empty"
    assert reading.unreadable is None
    assert reading.has_private_key is True
    assert [entry.entry_type for entry in reading.entries] == ["privateKey"]
    assert reading.entries[0].key is not None, "有私钥就必须留下私钥"
    assert reading.entries[0].cert_der == b""
    # No certificate means no fingerprint is claimed — an empty string, not a
    # value manufactured from the key.
    table = reading.entry_dicts()[0]
    assert table["fingerprint_sha256"] == ""
    assert table["spki_sha256"] == "", "SPKI 从证书切片来；没有证书就不得凭空给出"


def test_the_pkcs12_reader_sees_what_keytool_folds_away(tmp_path) -> None:
    """A key entry plus an unrelated trusted certificate is two entries, not one.

    ``keytool`` folds the extra certificate into the key entry's chain and reports
    a single ``PrivateKeyEntry`` (measured on this machine). The PKCS#12 reader
    keeps the bag structure, which is what makes
    ``CONTAINER_TRUSTSTORE_WITH_KEY`` detectable at all — the two formats
    therefore deliberately do not share a reader (``plan/03`` §⑤, D2).
    """
    path = tmp_path / "mixed.p12"
    write_key_with_trusted_p12(
        path, password=PASSWORD.encode(), alias="key-entry", trusted_alias="trusted-only"
    )
    reading = read_container(str(path), password=PASSWORD.encode())
    assert reading.has_private_key is True
    types = [entry.entry_type for entry in reading.entries]
    assert types == ["privateKey", "trustedCert"]
    aliases = {entry.alias for entry in reading.entries}
    assert aliases == {"key-entry", "trusted-only"}
    spkis = {item["spki_sha256"] for item in reading.entry_dicts()}
    assert len(spkis) == 2, "两把不同的公钥：私钥条目与外来可信证书"


# ── degradation ─────────────────────────────────────────────────────────────


def test_no_jdk_degrades_to_unreadable_and_still_exits_zero(monkeypatch, tmp_path) -> None:
    """D2/D11: an optional external capability downgrades, it does not fail.

    ``keytool`` is made unreachable rather than absent, so the test is about the
    *degradation path* and not about this machine's JDK.
    """
    monkeypatch.setenv(KEYTOOL_ENV, str(tmp_path / "no-such-keytool"))
    path = tmp_path / "store.jks"
    path.write_bytes(b"\xfe\xed\xfe\xed" + b"\x00" * 64)

    assertion = inspect(
        paths=[str(path)], show_aliases=True, password_env=None,
        policy=load_policy(), json_path=None,
    )
    container = assertion["containers"][0]
    assert container["format"] == "jks"
    assert container["unreadable"] == "keytool 不可用（未探测到 JDK）"
    assert container["password"] == "unknown"
    assert container["entries"] == []
    assert assertion["summary"]["unreadable"] == 1

    code, out, err = run_cli("containers", str(path))
    assert code == 0, err
    payload = json.loads(out)
    assert payload["kind"] == "containers"
    assert payload["containers"][0]["unreadable"]


def test_a_wrong_password_is_a_reason_not_a_crash(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, "definitely-not-the-password")
    path = tmp_path / "sealed.p12"
    write_key_with_trusted_p12(
        path, password=PASSWORD.encode(), alias="sealed", trusted_alias="sealed-extra"
    )

    reading = read_container(str(path), password=b"definitely-not-the-password")
    assert reading.password == "unknown"
    assert reading.unreadable
    assert reading.entries == ()
    # And the password itself is nowhere in the sentence that is shown to a user.
    assert "definitely-not-the-password" not in reading.unreadable


def test_a_path_that_does_not_exist_is_an_input_error(tmp_path) -> None:
    """Naming a file that is not there is exit 2 — not an unreadable container."""
    with pytest.raises(CliError):
        inspect(
            paths=[str(tmp_path / "missing.p12")], show_aliases=False, password_env=None,
            policy=load_policy(), json_path=None,
        )
    code, out, err = run_cli("containers", str(tmp_path / "missing.p12"))
    assert code == 2
    assert out == ""
    assert "Traceback" not in err


def test_a_non_container_file_is_named_as_such(tmp_path) -> None:
    plain = tmp_path / "notes.txt"
    plain.write_text("not a container\n", encoding="utf-8")
    reading = read_container(str(plain))
    assert reading.format == "unknown"
    assert reading.password == "unknown"
    assert "不是 PKCS#12 / JKS / JCEKS" in reading.unreadable


# ── the password's route ────────────────────────────────────────────────────


@needs_keytool
def test_the_password_never_reaches_a_child_process_argv(monkeypatch, tmp_path) -> None:
    """The secret travels in the child's environment, never in ``argv``.

    ``argv`` is world-readable on every platform, so a password there is a
    published password. The assertion is on the *actual* argument vector handed to
    ``subprocess.run``, captured by wrapping it — a comment claiming the same
    thing would be worth nothing. ``keytool`` here is the real one: the store
    bytes are junk, so the call fails, which is all that is needed for the call to
    have happened.
    """
    import certledger.containers as containers_module

    path = tmp_path / "store.jks"
    path.write_bytes(b"\xfe\xed\xfe\xed" + b"\x00" * 64)

    seen_argv: list[list[str]] = []
    seen_env: list[dict] = []
    real_run = containers_module.subprocess.run

    def recording_run(argv, **kwargs):
        seen_argv.append(list(argv))
        seen_env.append(dict(kwargs.get("env") or {}))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(containers_module.subprocess, "run", recording_run)
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, PASSWORD)

    reading = read_container(str(path), password=PASSWORD.encode())
    assert reading.unreadable, "这一步只需要 keytool 被调用过"

    assert seen_argv, "keytool 从未被调用——判据是空跑"
    for argv in seen_argv:
        assert PASSWORD not in " ".join(argv)
        assert "storepass:env" in " ".join(argv)
    assert any(PASSWORD in env.values() for env in seen_env), "口令没有走环境变量"


def test_the_password_is_not_in_the_document(monkeypatch, tmp_path) -> None:
    """Only ``set`` / ``empty`` / ``unknown`` ever appear in a report."""
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, PASSWORD)
    path = tmp_path / "hidden.p12"
    write_key_with_trusted_p12(
        path, password=PASSWORD.encode(), alias="hidden", trusted_alias="hidden-extra"
    )

    code, out, _ = run_cli("containers", str(path), "--show-aliases")
    assert code == 0
    assert PASSWORD not in out
    assert PASSWORD not in json.dumps(json.loads(out))
    assert json.loads(out)["containers"][0]["password"] == "set"


# ── JKS / JCEKS through keytool ──────────────────────────────────────────────


@needs_keytool
@pytest.mark.parametrize("store_type", ["JKS", "JCEKS"])
def test_a_keytool_readable_store_is_read_by_keytool(store_type, tmp_path) -> None:
    """The JKS route really runs when a JDK is present: aliases, types, certs.

    The delivery claim is "JKS/JCEKS through the JDK's own implementation", so the
    test exercises the whole path — ``-list -v`` parsed by label, then one
    ``-exportcert`` per entry — and checks the entry's fingerprint against a
    value computed from the certificate the test itself created.
    """
    tags = tmp_path / f"store-{store_type}"
    tags.mkdir()
    path = write_jks(tags / f"demo.{store_type.lower()}", password=PASSWORD, store_type=store_type)

    reading = read_container(str(path), password=PASSWORD.encode())
    assert reading.format == store_type.lower()
    assert reading.password == "set"
    assert reading.unreadable is None
    assert len(reading.entries) == 1

    entry = reading.entries[0]
    assert entry.alias == "jks-entry"
    assert entry.entry_type == "privateKey"
    assert entry.chain_length == 1
    assert entry.cert_der, "证书没有被导出：条目就没有指纹"
    assert len(entry.cert_der) > 100

    table = reading.entry_dicts()[0]
    assert len(table["fingerprint_sha256"]) == 64
    assert len(table["spki_sha256"]) == 64
    assert table["same_fingerprint_aliases"] == []


@needs_keytool
def test_a_jks_store_with_the_wrong_password_is_unreadable_not_wrong(tmp_path) -> None:
    path = write_jks(tmp_path / "locked.jks", password=PASSWORD, store_type="JKS")
    reading = read_container(str(path), password=b"not-the-password")
    assert reading.password == "unknown"
    assert reading.unreadable
    assert reading.entries == ()
    assert PASSWORD not in reading.unreadable


def test_containers_json_output_is_a_document(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, PASSWORD)
    path = tmp_path / "multi.p12"
    write_multi_alias_p12(path, password=PASSWORD.encode(), aliases=["one", "two"])
    target = tmp_path / "containers.json"
    code, out, err = run_cli(
        "containers", str(path), "--show-aliases", "--json", str(target)
    )
    assert code == 0, err
    assert "wrote" in out
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert list(payload) == [
        "schema_version",
        "kind",
        "policy_version",
        "policy_sha256",
        "containers",
        "summary",
    ]
    container = payload["containers"][0]
    assert list(container) == [
        "path",
        "format",
        "password",
        "has_private_key",
        "entries",
        "unreadable",
    ]
    assert list(container["entries"][0]) == [
        "alias",
        "entry_type",
        "fingerprint_sha256",
        "spki_sha256",
        "chain_length",
        "same_fingerprint_aliases",
    ]


def test_the_reader_uses_two_readers_and_says_which(tmp_path) -> None:
    """PKCS#12 never shells out; JKS/JCEKS always does (``plan/03`` §⑤).

    Asserted by watching the subprocess boundary rather than by reading the code:
    a PKCS#12 read must make no child process at all, and a JKS read must make at
    least one.
    """
    import certledger.containers as containers_module

    calls: list = []
    real_run = containers_module.subprocess.run

    def recording_run(argv, **kwargs):
        calls.append(list(argv))
        return real_run(argv, **kwargs)

    maybe_keytool = find_keytool()
    if maybe_keytool is None:
        pytest.skip("本机没有 keytool：JKS 那一半无法执行")

    monkeypatch_target = containers_module.subprocess
    original = monkeypatch_target.run
    monkeypatch_target.run = recording_run
    try:
        p12 = tmp_path / "no-child.p12"
        write_key_with_trusted_p12(
            p12, password=PASSWORD.encode(), alias="quiet", trusted_alias="quiet-extra"
        )
        read_container(str(p12), password=PASSWORD.encode())
        assert calls == [], "PKCS#12 走 cryptography，不得起子进程"

        jks = write_jks(tmp_path / "child.jks", password=PASSWORD)
        before = len(calls)
        read_container(str(jks), password=PASSWORD.encode())
        assert len(calls) > before, "JKS 必须走 keytool"
    finally:
        monkeypatch_target.run = original