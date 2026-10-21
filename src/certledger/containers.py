"""Container view: alias tables and container-level signals.

A PKCS#12 or a JKS/JCEKS store is a *box*, and the box is the finding. A
certificate inside a trust store that opens with an empty password, or a private
key sitting in a store everything on the machine can read, says something no
per-file rule can: the asset is not where it looks like it is. So this module
answers two questions the rest of the tool cannot:

* **what is inside** — the alias table (``alias`` / ``entry_type`` /
  ``fingerprint_sha256`` / ``chain_length`` / ``same_fingerprint_aliases[]``);
* **how it opened** — ``password`` ∈ ``set`` / ``empty`` / ``unknown``, plus one
  reason when it did not open at all.

Two readers, deliberately not shared (``plan/03`` §⑤, ``plan/00`` D2):

* **PKCS#12** goes through ``cryptography``, the only reader that exposes the
  *bag structure*. ``keytool`` folds the extra certificate of the
  ``truststore-with-key`` sample into the key entry's chain and reports a single
  entry — measured on this machine, and the reason the two formats must not
  share a reader.
* **JKS / JCEKS** go through ``keytool -list -v``, because those formats are
  reverse-engineered with no specification behind them, and the JDK's own
  implementation is the one that stays current (``pyjks`` stopped in 2024).

``keytool`` is an **optional external capability** (D2/D11): with no JDK a store
degrades to one ``CONTAINER_UNREADABLE`` record and the process still exits 0.
"This machine has no JDK" is not a collection failure.

No password reaches ``argv``, disk, or a report. ``keytool`` is invoked with
``-storepass:env <VAR>``, so the secret travels in the child's environment
(JDK's own mechanism for this) instead of the process list; the report only ever
says ``set`` / ``empty`` / ``unknown``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization

from certledger.errors import CliError
from certledger.model import SCHEMA_VERSION
from certledger.parsing.fingerprint import der_sha256

#: Where the container password is read from when ``--password-env`` does not
#: name another variable. A *variable name*, never a value: the secret is read
#: from the environment, so it never appears in ``argv``, on disk, or in a
#: report. A container with an empty password still opens without this.
DEFAULT_PASSWORD_ENV = "CERTLEDGER_CONTAINER_PASSWORD"

#: An explicit ``keytool`` path, for a machine whose JDK the probes below miss.
KEYTOOL_ENV = "CERTLEDGER_KEYTOOL"

#: ``plan/03`` §⑤ 纪律: a container child process gets 20 seconds, no more.
KEYTOOL_TIMEOUT_SECONDS = 20

PKCS12 = "pkcs12"
JKS = "jks"
JCEKS = "jceks"

#: The store types ``keytool`` is asked for, keyed by what the **bytes** say the
#: file is (``MAGIC_JKS`` / ``MAGIC_JCEKS``; the two magics differ, measured on
#: this machine, so no ambiguity has to be reported).
KEYTOOL_STORE_TYPES = {JKS: "JKS", JCEKS: "JCEKS"}

#: ``keytool`` entry-type strings → the spelling the rest of the project uses.
_KEYTOOL_ENTRY_TYPES = {
    "privatekeyentry": "privateKey",
    "trustedcertentry": "trustedCert",
    "secretkeyentry": "secretKey",
}

#: ``keytool`` labels, English and the JVM's localized Chinese. Matched by *key
#: name*, never by column width or line shape: ``LC_ALL=C`` does **not** switch
#: a JVM's locale (measured on this machine — the output stayed Chinese), so both
#: spellings have to be understood rather than assumed.
_ALIAS_LABELS = ("Alias name:", "别名:")
_ENTRY_TYPE_LABELS = ("Entry type:", "条目类型:")
_CHAIN_LABELS = ("Certificate chain length:", "证书链长度:")

#: Ask the JVM for English labels, which it honours where the platform allows.
_KEYTOOL_LOCALE_FLAGS = ("-J-Duser.language=en", "-J-Duser.country=US", "-J-Dfile.encoding=UTF-8")

#: The variable ``keytool`` reads the store password from, for the lifetime of
#: one child process. Named apart from the user-facing variable so nothing already
#: in the environment can be mistaken for it.
_PASSWORD_VAR = "CERTLEDGER_KEYTOOL_STORE_PASSWORD"


@dataclass(frozen=True, slots=True)
class ContainerEntry:
    """One alias in one container.

    ``certificate`` / ``key`` are the decoded objects, carried so ``inventory``
    can fold container contents into the same ``certs[]`` / ``keys[]`` tables as
    everything else (one asset, wherever it was found). ``cert_der`` is the
    certificate's own bytes, so every hash is over what was stored (K1).
    """

    alias: str
    entry_type: str
    certificate: Any = None
    key: Any = None
    cert_der: bytes = b""
    chain_length: int = 0


@dataclass(frozen=True, slots=True)
class ContainerReading:
    """What one container turned out to be."""

    path: str
    format: str
    password: str
    entries: tuple[ContainerEntry, ...] = ()
    unreadable: str | None = None

    @property
    def has_private_key(self) -> bool:
        return any(entry.entry_type == "privateKey" for entry in self.entries)

    def entry_dicts(self) -> list[dict[str, Any]]:
        """The alias table, sorted by ``alias`` (``plan/03`` §⑤ 纪律).

        ``same_fingerprint_aliases`` is the column that makes duplication *inside*
        a container visible: two aliases carrying one certificate is the
        ``DUPLICATE_CERT`` case, and nothing outside the store can see it.
        """
        by_fingerprint: dict[str, list[str]] = {}
        for entry in self.entries:
            fingerprint = entry_fingerprint(entry)
            if fingerprint:
                by_fingerprint.setdefault(fingerprint, []).append(entry.alias)

        rows: list[dict[str, Any]] = []
        for entry in sorted(self.entries, key=lambda item: (item.alias, item.entry_type)):
            fingerprint = entry_fingerprint(entry)
            rows.append(
                {
                    "alias": entry.alias,
                    "entry_type": entry.entry_type,
                    "fingerprint_sha256": fingerprint,
                    "spki_sha256": entry_spki(entry),
                    "chain_length": entry.chain_length,
                    "same_fingerprint_aliases": sorted(
                        name for name in by_fingerprint.get(fingerprint, []) if name != entry.alias
                    ),
                }
            )
        return rows

    def to_dict(self, *, include_entries: bool = True) -> dict[str, Any]:
        """The document shape, one entry point, whatever the reader was.

        ``entries`` is the alias table; without ``--show-aliases`` the count
        stands in for it, so "three entries" and "we did not list them" stay
        distinguishable.
        """
        document: dict[str, Any] = {
            "path": self.path,
            "format": self.format,
            "password": self.password,
            "has_private_key": self.has_private_key,
        }
        if include_entries:
            document["entries"] = self.entry_dicts()
        else:
            document["entry_count"] = len(self.entries)
        document["unreadable"] = self.unreadable
        return document


# ── password source ─────────────────────────────────────────────────────────


def password_from_env(password_env: str | None = None) -> bytes | None:
    """The container password as bytes, or ``None`` when the variable is unset.

    ``None`` and ``b""`` are different answers: unset means "no password was
    given" (the empty password is still tried, because a store that opens
    without one is the finding this module exists for), while an empty string is
    a *stated* empty password. Keeping them apart is what lets the report say
    ``unknown`` instead of guessing.
    """
    name = password_env or DEFAULT_PASSWORD_ENV
    value = os.environ.get(name)
    if value is None:
        return None
    return value.encode("utf-8")


def _password_candidates(password: bytes | None) -> tuple[bytes | None, ...]:
    """Which passwords to try, in order, without inventing secrets.

    Only two *values* are ever tried: the password the caller supplied, and the
    **empty** password. The empty password is neither a secret nor a guess — a
    store opened with one is a real and common accident, and it is exactly the
    ``CONTAINER_EMPTY_PASSWORD`` signal this module exists to produce. No
    dictionary, no product default, no "changeit".

    The empty password is tried twice, as ``b""`` and as ``None``, because the
    two libraries express it differently: ``keytool`` and OpenSSL-written PFX
    files take an empty string, while ``cryptography``'s own ``NoEncryption``
    bags are opened by passing ``None``. Both mean "there is no password on this
    box", so both are tried, and either success is reported as ``empty``.
    """
    candidates: list[bytes | None] = []
    if password is not None:
        candidates.append(password)
    for candidate in (b"", None):
        if candidate not in candidates:
            candidates.append(candidate)
    return tuple(candidates)


def _keytool_password(candidate: bytes | None) -> bytes:
    """``keytool`` is handed ``b""`` for the empty password, never ``None``.

    There is no way to tell ``keytool`` "use no password": the store's password
    *is* the empty string, and an empty variable value is how that is said.
    """
    return b"" if candidate is None else candidate


# ── the CLI view ────────────────────────────────────────────────────────────


def inspect(
    *,
    paths: Sequence[str],
    show_aliases: bool,
    password_env: str | None,
    policy,
    json_path: str | None,
) -> dict:
    """Build the ``containers`` document for the listed paths.

    A path that does not exist is an **input error** (exit 2): the user named a
    file that is not there. A path that exists and does not open is one
    ``CONTAINER_UNREADABLE`` record with exit 0 — different answers that must not
    look the same (``plan/03`` §⑥).
    """
    if not paths:
        raise CliError("缺少输入", "containers 至少需要一个容器路径")

    password = password_from_env(password_env)
    readings: list[ContainerReading] = []
    for raw in paths:
        target = Path(raw)
        if not target.is_file():
            raise CliError("容器文件不存在", str(target))
        readings.append(read_container(str(target), password=password))

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "containers",
        "policy_version": getattr(policy, "version", ""),
        "policy_sha256": getattr(policy, "sha256", ""),
        "containers": [reading.to_dict(include_entries=show_aliases) for reading in readings],
        "summary": {
            "containers": len(readings),
            "entries": sum(len(reading.entries) for reading in readings),
            "with_private_key": sum(1 for reading in readings if reading.has_private_key),
            "unreadable": sum(1 for reading in readings if reading.unreadable),
        },
    }


# ── reading one container ───────────────────────────────────────────────────


def read_container(path: str, *, password: bytes | None = None) -> ContainerReading:
    """Read one container. Never raises for a file that is merely unreadable.

    Only the bytes decide which reader runs; ``--source`` and ``--roots`` have
    nothing to do with it. ``password=None`` means "none was supplied" and the
    empty password is still tried (see :func:`_password_candidates`).
    """
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as error:
        return ContainerReading(
            path=path,
            format="unknown",
            password="unknown",
            unreadable=_short_reason(error),
        )

    fmt = format_from_bytes(raw)
    if fmt == PKCS12:
        return _read_pkcs12(path, raw, password)
    if fmt in KEYTOOL_STORE_TYPES:
        return _read_keystore(path, fmt, password)
    return ContainerReading(
        path=path,
        format="unknown",
        password="unknown",
        unreadable="不是 PKCS#12 / JKS / JCEKS 容器（按字节判定）",
    )


def format_from_bytes(raw: bytes) -> str:
    """Name the container family from its bytes — the same test the sniffer uses.

    Sharing the magic constants keeps one definition of "what a JCEKS looks
    like": two spellings of ``CECECECE`` is how a format drifts.
    """
    from certledger.parsing import asn1
    from certledger.parsing.sniff import MAGIC_JCEKS, MAGIC_JKS

    if raw.startswith(MAGIC_JKS):
        return JKS
    if raw.startswith(MAGIC_JCEKS):
        return JCEKS
    if asn1.looks_like_pfx(raw):
        return PKCS12
    return "unknown"


# ── PKCS#12 ─────────────────────────────────────────────────────────────────


def _read_pkcs12(path: str, raw: bytes, password: bytes | None) -> ContainerReading:
    """Read a PKCS#12 through ``cryptography`` (bag structure, not line parsing)."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    parsed = None
    used: bytes | None = None
    opened = False
    why = ""
    for candidate in _password_candidates(password):
        try:
            parsed = pkcs12.load_pkcs12(raw, candidate)
        except (ValueError, TypeError) as error:  # wrong password, or not a PFX
            why = _short_reason(error)
            continue
        except Exception as error:  # noqa: BLE001 - unsupported algorithm, corrupt bag
            return ContainerReading(
                path=path, format=PKCS12, password="unknown", unreadable=_short_reason(error)
            )
        used = candidate
        opened = True
        break

    if not opened or parsed is None:
        return ContainerReading(
            path=path, format=PKCS12, password="unknown", unreadable=why or "容器无法打开"
        )

    entries: list[ContainerEntry] = []
    if parsed.key is not None:
        # A key bag. Its certificate rides on the bag's own friendly name and the
        # additional certificates keep theirs. A key bag **without** a
        # certificate is still an entry — a key store need not ship its own
        # certificate, and a reader that required one would drop the key
        # silently, which is the failure this module exists to prevent. Such an
        # entry has no alias to report: the PKCS#12 key bag carries no friendly
        # name that ``cryptography`` exposes, and inventing one would put a value
        # in the report that is not in the file.
        #
        # ``chain_length`` stays 0: a PKCS#12 bag does not say whether an extra
        # certificate is a chain member or an unrelated trusted anchor, and
        # reporting the count as a chain is precisely the mistake ``keytool``
        # makes on the sample where it matters most (``truststore-with-key``). A
        # store's contents are listed; a chain is not invented.
        leaf = parsed.cert.certificate if parsed.cert is not None else None
        entries.append(
            ContainerEntry(
                alias=_friendly_name(parsed.cert) if parsed.cert is not None else "",
                entry_type="privateKey",
                certificate=leaf,
                key=parsed.key,
                cert_der=leaf.public_bytes(serialization.Encoding.DER) if leaf is not None else b"",
            )
        )
    elif parsed.cert is not None:
        # A leaf certificate with no key beside it: a trusted anchor, which is
        # what a certificate-only bag is.
        leaf = parsed.cert.certificate
        entries.append(
            ContainerEntry(
                alias=_friendly_name(parsed.cert),
                entry_type="trustedCert",
                certificate=leaf,
                cert_der=leaf.public_bytes(serialization.Encoding.DER),
            )
        )
    for extra in parsed.additional_certs or ():
        entries.append(
            ContainerEntry(
                alias=_friendly_name(extra),
                entry_type="trustedCert",
                certificate=extra.certificate,
                cert_der=extra.certificate.public_bytes(serialization.Encoding.DER),
            )
        )

    return ContainerReading(
        path=path,
        format=PKCS12,
        password="empty" if used == b"" else "set",
        entries=tuple(entries),
    )


def _friendly_name(bag: Any) -> str:
    """The bag's alias, decoded; ``""`` when the bag never carried one.

    An unnamed bag is not a missing entry — it is an entry without a name, and
    inventing one (``"unnamed-1"``) would put a value in the report that nobody
    can find in the file.
    """
    raw = getattr(bag, "friendly_name", None) or b""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


# ── JKS / JCEKS ─────────────────────────────────────────────────────────────


def _read_keystore(path: str, fmt: str, password: bytes | None) -> ContainerReading:
    """Read a JKS/JCEKS store through ``keytool -list -v``.

    The password reaches the child through ``-storepass:env``: ``argv`` is
    world-readable on every platform, and a password in a process list is a
    published password. The variable name is ours, not the user's, so an absent
    or empty password is tried the same way.
    """
    keytool = find_keytool()
    if keytool is None:
        return ContainerReading(
            path=path,
            format=fmt,
            password="unknown",
            unreadable="keytool 不可用（未探测到 JDK）",
        )

    store_type = KEYTOOL_STORE_TYPES[fmt]
    last_reason = ""
    tried: list[bytes] = []
    for candidate in _password_candidates(password):
        attempt = _keytool_password(candidate)
        if attempt in tried:
            continue
        tried.append(attempt)
        listing = _run_keytool(
            keytool,
            ["-list", "-v", "-storetype", store_type, "-keystore", path],
            password=attempt,
        )
        if listing.reason:
            last_reason = listing.reason
            continue
        return ContainerReading(
            path=path,
            format=fmt,
            password="empty" if attempt == b"" else "set",
            entries=_entries_from_listing(keytool, path, store_type, attempt, listing.text),
        )

    return ContainerReading(
        path=path, format=fmt, password="unknown", unreadable=last_reason or "容器无法打开"
    )


@dataclass(frozen=True, slots=True)
class _ChildRun:
    """One ``keytool`` invocation: either its text, or why it failed."""

    text: str = ""
    reason: str = ""


def _run_keytool(keytool: str, args: Sequence[str], *, password: bytes) -> _ChildRun:
    """Run ``keytool`` with a fixed argv, ``shell=False`` and a hard timeout.

    On failure only the first line of ``keytool``'s own message is kept — and
    never the password, which was never in ``argv`` to begin with.
    """
    env = dict(os.environ)
    env[_PASSWORD_VAR] = password.decode("utf-8", "replace")
    argv = [keytool, *_KEYTOOL_LOCALE_FLAGS, *args, "-storepass:env", _PASSWORD_VAR]
    try:
        completed = subprocess.run(
            argv, shell=False, capture_output=True, timeout=KEYTOOL_TIMEOUT_SECONDS, env=env
        )
    except subprocess.TimeoutExpired:
        return _ChildRun(reason=f"timeout（>{KEYTOOL_TIMEOUT_SECONDS}s）")
    except OSError as error:  # not executable, or it vanished mid-run
        return _ChildRun(reason=_short_reason(error))

    if completed.returncode != 0:
        lines = _decode(completed.stderr).strip().splitlines()
        head = lines[0] if lines else f"keytool 退出码 {completed.returncode}"
        return _ChildRun(reason=_sanitize(head, password))
    return _ChildRun(text=_decode(completed.stdout))


def _decode(raw: bytes) -> str:
    """Decode a child's output; UTF-8 is requested, not assumed.

    ``keytool``'s console encoding is the JVM's, which on this machine is the
    local code page. ``errors="replace"`` keeps one undecodable byte from turning
    a readable store into a failure.
    """
    return raw.decode("utf-8", "replace")


def _sanitize(text: str, password: bytes) -> str:
    """Never let a secret ride out inside an error message.

    ``keytool`` does not echo the password on a wrong-password failure, but this
    module must not depend on a third party's discretion: if the value ever
    appears, it is replaced before the sentence is used.
    """
    if password:
        secret = password.decode("utf-8", "replace")
        if secret:
            return text.replace(secret, "<redacted>")
    return text


def _entries_from_listing(
    keytool: str, path: str, store_type: str, password: bytes, listing: str
) -> tuple[ContainerEntry, ...]:
    """Alias/entry-type pairs from ``-list -v``, plus each entry's certificate.

    The alias table alone would say a store holds three entries; without the
    certificates it cannot be folded into ``certs[]``, and a store that is never
    folded in is exactly the "we did not look" answer this module exists to
    avoid. So each certificate entry costs one ``-exportcert -rfc`` call.
    """
    entries: list[ContainerEntry] = []
    for alias, entry_type, chain_length in _parse_listing(listing):
        entry = ContainerEntry(alias=alias, entry_type=entry_type, chain_length=chain_length)
        if entry_type in ("privateKey", "trustedCert"):
            exported = _export_certificate(keytool, path, store_type, password, alias)
            if exported is not None:
                cert, der = exported
                entry = ContainerEntry(
                    alias=alias,
                    entry_type=entry_type,
                    certificate=cert,
                    cert_der=der,
                    chain_length=chain_length,
                )
        entries.append(entry)
    return tuple(entries)


def _parse_listing(listing: str) -> list[tuple[str, str, int]]:
    """``(alias, entry_type, chain_length)`` per entry, by **label**, not layout.

    Three labels are read, each matched as a key name at the start of a line.
    Column positions, indentation and the surrounding prose are all ignored: a
    JVM printing in another language still prints these keys (both spellings are
    listed above), and a keytool that reflows its columns cannot change the
    answer.
    """
    entries: list[tuple[str, str, int]] = []
    alias: str | None = None
    entry_type = ""
    chain = 0

    def flush() -> None:
        if alias is not None:
            entries.append((alias, entry_type or "unknown", chain))

    for line in listing.splitlines():
        stripped = line.strip()
        value = _label_value(stripped, _ALIAS_LABELS)
        if value is not None:
            flush()
            alias, entry_type, chain = value, "", 0
            continue
        if alias is None:
            continue
        value = _label_value(stripped, _ENTRY_TYPE_LABELS)
        if value is not None:
            entry_type = _KEYTOOL_ENTRY_TYPES.get(value.lower(), value)
            continue
        value = _label_value(stripped, _CHAIN_LABELS)
        if value is not None:
            chain = _as_int(value)
    flush()
    return entries


def _label_value(line: str, labels: Sequence[str]) -> str | None:
    for label in labels:
        if line.startswith(label):
            return line[len(label) :].strip()
    return None


def _as_int(text: str) -> int:
    try:
        return int(text.strip())
    except (TypeError, ValueError):
        return 0


def _export_certificate(
    keytool: str, path: str, store_type: str, password: bytes, alias: str
) -> tuple[Any, bytes] | None:
    """The entry's certificate as ``(certificate, der)``, or ``None``.

    ``None`` is not fatal: the entry stays in the alias table with its type and
    an empty fingerprint, which is honest ("this alias exists; its certificate
    could not be read"). Dropping the entry would make the table lie.
    """
    from cryptography import x509

    run = _run_keytool(
        keytool,
        ["-exportcert", "-rfc", "-alias", alias, "-storetype", store_type, "-keystore", path],
        password=password,
    )
    if run.reason or "-----BEGIN CERTIFICATE-----" not in run.text:
        return None
    try:
        cert = x509.load_pem_x509_certificate(run.text.encode("utf-8"))
    except Exception:  # noqa: BLE001 - one unreadable certificate is not a store failure
        return None
    return cert, cert.public_bytes(serialization.Encoding.DER)


def find_keytool() -> str | None:
    """Locate ``keytool``, or return ``None`` (no JDK → degrade, D2).

    ``PATH`` is not enough: on this machine ``java`` has a shim but ``keytool``
    does not, and the JDK's ``bin`` is not on ``PATH`` at all. So the search runs
    ``CERTLEDGER_KEYTOOL`` → ``PATH`` → ``JAVA_HOME`` → the usual JDK
    installation roots, most explicit first so a machine with several JDKs can
    say which one to use.
    """
    override = os.environ.get(KEYTOOL_ENV)
    if override:
        return override if Path(override).is_file() else None

    found = shutil.which("keytool")
    if found:
        return found

    executable = "keytool.exe" if os.name == "nt" else "keytool"
    candidates: list[Path] = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(Path(java_home) / "bin" / executable)
    if os.name == "nt":
        java_root = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Java"
    else:
        java_root = Path("/usr/lib/jvm")
    if java_root.is_dir():
        candidates.extend(sorted(path for path in java_root.glob(f"*/bin/{executable}")))
        candidates.extend(sorted(path for path in java_root.glob(f"*/*/bin/{executable}")))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


# ── shared helpers ──────────────────────────────────────────────────────────


def entry_fingerprint(entry: ContainerEntry) -> str:
    """SHA-256 of the entry's certificate DER, in the ledger's fingerprint space."""
    return der_sha256(entry.cert_der) if entry.cert_der else ""


def entry_spki(entry: ContainerEntry) -> str:
    """The entry's SPKI hash, or ``""`` when no certificate was read (K4).

    Taken from ``parsing/x509.py``'s raw slice when it can walk the structure, so
    the hash input is the certificate's own SPKI octets rather than a re-encoding
    (K1). An unwalkable certificate yields ``""`` — "not derived" is honest, and
    a fabricated pairing key would silently match nothing anyway.
    """
    if not entry.cert_der:
        return ""
    from certledger.parsing.x509 import cert_parts

    parts = cert_parts(entry.cert_der)
    if parts is not None and parts.spki_der:
        return der_sha256(parts.spki_der)
    return ""


def _short_reason(error: BaseException) -> str:
    """First line of an exception, trimmed. Never carries key material."""
    lines = str(error).strip().splitlines()
    head = lines[0] if lines else type(error).__name__
    return head[:200]


__all__ = [
    "DEFAULT_PASSWORD_ENV",
    "JCEKS",
    "JKS",
    "KEYTOOL_ENV",
    "KEYTOOL_TIMEOUT_SECONDS",
    "PKCS12",
    "ContainerEntry",
    "ContainerReading",
    "entry_fingerprint",
    "entry_spki",
    "find_keytool",
    "format_from_bytes",
    "inspect",
    "password_from_env",
    "read_container",
]
