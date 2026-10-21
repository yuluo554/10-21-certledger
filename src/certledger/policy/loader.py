"""Strategy loader: thresholds and their sources live in a JSON policy file (K3).

There are **no default literals in code**. A missing or malformed policy is an
input error (exit code 2), never a silent fallback. Every threshold carries a
``source`` string so a finding can cite where the number comes from
(``plan/00`` D3 / D10, ``data/README.md`` §五).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from certledger.errors import CliError

#: How a threshold source must look. A judgement without a citation is not
#: allowed into the rule set (plan/03 §③).
_SOURCE_RE = (
    "RFC ",
    "CA/B",
    "NIST",
    "SP 800",
    "本项目定义",
)


@dataclass(frozen=True, slots=True)
class Policy:
    """A loaded, validated policy document."""

    path: Path
    raw: bytes
    data: dict[str, Any]

    @property
    def sha256(self) -> str:
        return sha256(self.raw).hexdigest()

    @property
    def version(self) -> str:
        return str(self.data.get("policy_version", ""))

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def require(self, dotted: str) -> Any:
        value = self.get(dotted, _MISSING)
        if value is _MISSING:
            raise CliError("策略文件缺字段", f"{self.path.name} 缺少 {dotted}")
        return value


_MISSING = object()

#: Required top-level structure. Kept declarative so the validator and the
#: docs cannot drift apart without a test noticing.
REQUIRED_PATHS = (
    "policy_version",
    "hygiene.expired.level",
    "hygiene.expiring.warn_days",
    "hygiene.cliff.window_days",
    "hygiene.cliff.min_count",
    "hygiene.weak_key.rsa.min_bits",
    "hygiene.weak_key.ec.allowed_curves",
    "hygiene.weak_sig.forbidden_digests",
    "hygiene.nist_2031.enabled",
    "hygiene.nist_2031.bits",
    "hygiene.private_key.level",
    "hygiene.permissions.max_posix_mode",
    "hygiene.orphans.level",
    "hygiene.duplicates.level",
    "hygiene.container_truststore.level",
    "hygiene.container_password.level",
    "hygiene.diagnostics.default",
    "hygiene.diagnostics.codes",
    "collect.max_file_bytes",
    "collect.sniff_bytes",
    "collect.follow_symlinks_default",
    "report.default_fail_on",
)

#: The only severities a rule may be set to, plus the switch that turns it off.
LEVELS = ("ERROR", "WARN", "INFO", "off")

#: The nine rule families of ``plan/03`` §③, by the policy block that owns them.
#: Named here so ``hygiene`` can iterate and a deletion is a red test.
RULE_BLOCKS = (
    "hygiene.expired",
    "hygiene.expiring",
    "hygiene.cliff",
    "hygiene.weak_key.rsa",
    "hygiene.weak_key.ec",
    "hygiene.weak_sig",
    "hygiene.nist_2031",
    "hygiene.private_key",
    "hygiene.permissions",
    "hygiene.orphans",
    "hygiene.duplicates",
    "hygiene.container_truststore",
    "hygiene.container_password",
)

#: The failure-path block. It owns a *default* level plus a per-code override
#: table, because the collector's code vocabulary is open (a new ``SKIP_*`` must
#: not silently become an unclassified finding) while the severities must still
#: be reviewable data rather than code.
DIAGNOSTICS_BLOCK = "hygiene.diagnostics"


def bundled_policy_path() -> Path:
    """Path of the policy shipped inside the package.

    Uses ``importlib.resources`` semantics via ``__file__`` so an installed wheel
    finds the file; reading a source-relative path would break once installed.
    """
    return Path(__file__).resolve().parent.parent / "data" / "default-policy.json"


def load_policy(path: str | Path | None = None) -> Policy:
    """Load and validate a policy file.

    ``path=None`` means "the bundled default". Any structural problem raises
    :class:`CliError` (exit code 2).
    """
    target = Path(path) if path is not None else bundled_policy_path()
    if not target.is_file():
        raise CliError("策略文件不存在", str(target))
    try:
        raw = target.read_bytes()
    except OSError as error:
        raise CliError("策略文件不可读", f"{target.name}: {error.strerror}") from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CliError("策略文件不是合法 JSON", f"{target.name}: {error}") from None
    if not isinstance(data, dict):
        raise CliError("策略文件根节点必须是对象", target.name)

    policy = Policy(path=target, raw=raw, data=data)
    _validate(policy)
    return policy


def _validate(policy: Policy) -> None:
    for dotted in REQUIRED_PATHS:
        policy.require(dotted)

    for dotted in ("hygiene.expiring.warn_days", "hygiene.cliff.window_days"):
        _require_int(policy, dotted, minimum=0)
    _require_int(policy, "hygiene.cliff.min_count", minimum=1)
    _require_int(policy, "hygiene.weak_key.rsa.min_bits", minimum=1)
    _require_int(policy, "hygiene.nist_2031.bits", minimum=1)
    _require_int(policy, "collect.max_file_bytes", minimum=1)
    _require_int(policy, "collect.sniff_bytes", minimum=16)

    enabled = policy.require("hygiene.nist_2031.enabled")
    if not isinstance(enabled, bool):
        raise CliError("策略字段非法", "hygiene.nist_2031.enabled 必须是布尔值")

    # Every rule carries its own severity or ``off``; an unknown word here would
    # silently sort to the bottom of the report and never gate anything.
    for block in RULE_BLOCKS:
        level = policy.get(f"{block}.level", _MISSING)
        if level is _MISSING:
            continue
        if level not in LEVELS:
            raise CliError(
                "策略字段非法",
                f"{block}.level 必须是 {' / '.join(LEVELS)} 之一，收到 {level!r}",
            )

    diagnostics_default = policy.require(f"{DIAGNOSTICS_BLOCK}.default")
    if diagnostics_default not in LEVELS:
        raise CliError(
            "策略字段非法",
            f"{DIAGNOSTICS_BLOCK}.default 必须是 {' / '.join(LEVELS)} 之一，收到 {diagnostics_default!r}",
        )
    overrides = policy.require(f"{DIAGNOSTICS_BLOCK}.codes")
    if not isinstance(overrides, dict):
        raise CliError("策略字段非法", f"{DIAGNOSTICS_BLOCK}.codes 必须是对象")
    for code, level in overrides.items():
        if level not in LEVELS:
            raise CliError(
                "策略字段非法",
                f"{DIAGNOSTICS_BLOCK}.codes.{code} 必须是 {' / '.join(LEVELS)} 之一，收到 {level!r}",
            )

    _require_octal_mode(policy, "hygiene.permissions.max_posix_mode")

    curves = policy.require("hygiene.weak_key.ec.allowed_curves")
    if not isinstance(curves, list) or not curves or not all(isinstance(c, str) for c in curves):
        raise CliError("策略字段非法", "hygiene.weak_key.ec.allowed_curves 必须是非空字符串数组")

    digests = policy.require("hygiene.weak_sig.forbidden_digests")
    if not isinstance(digests, list) or not all(isinstance(d, str) for d in digests):
        raise CliError("策略字段非法", "hygiene.weak_sig.forbidden_digests 必须是字符串数组")

    fail_on = policy.require("report.default_fail_on")
    if fail_on not in {"ERROR", "WARN", "INFO", "none"}:
        raise CliError(
            "策略字段非法",
            "report.default_fail_on 必须是 ERROR / WARN / INFO / none 之一",
        )

    _check_sources(policy)


def _require_octal_mode(policy: Policy, dotted: str) -> str:
    """A POSIX mode must be an octal *string* — ``640`` reads as decimal 640.

    Storing it as a JSON number would make ``"640"`` and ``640`` mean different
    things depending on who parses it; the string form is unambiguous.
    """
    value = policy.require(dotted)
    if not isinstance(value, str) or not value or any(ch not in "01234567" for ch in value):
        raise CliError("策略字段非法", f"{dotted} 必须是八进制数字组成的字符串，收到 {value!r}")
    return value


def _require_int(policy: Policy, dotted: str, *, minimum: int) -> int:
    value = policy.require(dotted)
    if isinstance(value, bool) or not isinstance(value, int):
        raise CliError("策略字段非法", f"{dotted} 必须是整数，收到 {type(value).__name__}")
    if value < minimum:
        raise CliError("策略字段非法", f"{dotted} 必须 ≥ {minimum}，收到 {value}")
    return value


def _check_sources(policy: Policy) -> None:
    """Every threshold block must declare a ``source`` with a real citation.

    This is the machine-side half of "无出处的阈值不得成为默认值"
    (``plan/01`` §六). The check is deliberately shallow — it verifies a
    citation *shape* (RFC/CA-B/NIST/本项目定义 + section), not that the citation
    is semantically correct; the latter is a review item recorded in
    ``data/README.md`` §二.
    """
    blocks = RULE_BLOCKS + (DIAGNOSTICS_BLOCK,)
    for block in blocks:
        source = policy.get(f"{block}.source")
        if not isinstance(source, str) or not source.strip():
            raise CliError("阈值缺出处", f"{block}.source 为空——无出处的判据不得进入规则集")
        if not any(token in source for token in _SOURCE_RE):
            raise CliError(
                "阈值出处形态非法",
                f"{block}.source 需含 RFC/CA-B/NIST/SP 800/本项目定义 之一，收到 {source!r}",
            )
