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

#: The sample containers' password (``fixtures/expected.json`` →
#: ``generator.container_password``). Public sample material, deliberately not a
#: secret: the fixtures are generated on demand and never committed, and the
#: whole point of the ``empty-pass`` sample is that a real store can be open.
#: The reader itself has no product default — this constant exists in the tests
#: because the *customer* of the reader is the one who supplies the password.
FIXTURE_CONTAINER_PASSWORD = "changeit"


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


@pytest.fixture
def container_password(monkeypatch):
    """Put the sample password where the container reader looks for it.

    Where it looks is a *variable name* (``containers.DEFAULT_PASSWORD_ENV``),
    never a value, so the secret stays out of ``argv``, off disk and out of every
    report — including in the tests, which is the only way that claim is worth
    anything.
    """
    from certledger.containers import DEFAULT_PASSWORD_ENV

    monkeypatch.setenv(DEFAULT_PASSWORD_ENV, FIXTURE_CONTAINER_PASSWORD)
    return FIXTURE_CONTAINER_PASSWORD


@pytest.fixture
def issue_certificate():
    """Return a factory that writes a self-signed certificate into a directory.

    The tests that assert exit codes, baselines and redaction need a certificate
    whose validity and key they control. ``fixtures/out`` cannot serve them: it is
    generated on demand and **CI never generates it**, so a test built on it
    silently skips exactly where it matters. Building the certificate here makes
    those tests run on every platform in every job.

    The returned callable writes ``<name>.der`` and, on request, ``<name>.key``,
    and answers with the facts the caller would otherwise have to recompute:
    the DER, both fingerprints, and the key object.
    """
    import datetime as dt
    from pathlib import Path as _Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from certledger.parsing.fingerprint import der_sha256

    def build(
        directory,
        *,
        name: str = "cert",
        cn: str = "test.example",
        serial: int = 1,
        not_valid_before=None,
        not_valid_after=None,
        key=None,
        write_key: bool = False,
        bits: int = 2048,
    ) -> dict:
        directory = _Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        key = key if key is not None else rsa.generate_private_key(public_exponent=65537, key_size=bits)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        not_before = not_valid_before or dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
        not_after = not_valid_after or dt.datetime(2035, 1, 1, tzinfo=dt.timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256())
        )
        der = certificate.public_bytes(serialization.Encoding.DER)
        der_path = directory / f"{name}.der"
        der_path.write_bytes(der)
        spki = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if write_key:
            key_path = directory / f"{name}.key"
            key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            # Owner-only, like ``fixtures/gen.py::write_private_key``. Without
            # this the file lands at the umask default (0644 on POSIX) and every
            # test that only wants "a key that pairs" also gets
            # ``PERMISSION_TOO_OPEN`` — a finding the test never asked for, and
            # one that appears on Linux/macOS but not on Windows. That is how a
            # green Windows run hid a red CI run.
            try:
                key_path.chmod(0o600)
            except OSError:  # pragma: no cover - filesystems without POSIX modes
                pass
        return {
            "path": der_path,
            "der": der,
            "key": key,
            "fingerprint_sha256": der_sha256(der),
            "spki_sha256": der_sha256(spki),
            "subject": f"CN={cn}",
            "subject_der_sha256": der_sha256(subject.public_bytes()),
        }

    return build
