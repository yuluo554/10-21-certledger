# CertLedger

**ChainWarden audits one PEM file. CertLedger takes stock of one machine** — aliases inside
containers, entries in the system trust store, and a private key that has been sitting alone in a
backup directory for years all land in the same table, cross-referenced by one set of fingerprints.

A certificate expiry table is one column of that table, not the product. This is a ledger, not an
expiry notifier: telling you a certificate is about to expire is a solved problem; knowing how many
you have, which key pairs with which, and which nobody owns is the one that is still open.

> **Privacy: purely local, zero network, zero telemetry.** CertLedger never opens a socket, never
> talks to a remote service, and never writes a host name or a user name into a report. Real
> certificates and private keys never enter this repository.

`Status: v0.1.0.dev0 — skeleton (command surface only)`

---

## What it answers

| Question | Command |
|---|---|
| What certificates and keys are on this machine? | `certledger collect` |
| One record per distinct certificate/key, however many places it lives | `certledger inventory` |
| Who pairs with whom, who expired, who is weak, who is duplicated, who is orphaned | `certledger hygiene` |
| A deterministic JSON + Markdown report with an exit code for CI | `certledger report` |
| Aliases and signals inside PKCS#12 / JKS / JCEKS | `certledger containers` |

## Install

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"      # Windows: .venv\Scripts\python.exe
certledger --version
```

Requires Python ≥ 3.10 and `cryptography` (installed automatically). `keytool` from a JDK is
**optional**: without it the container view degrades to a `CONTAINER_UNREADABLE` record instead of
failing.

## Usage

> The analysis modules are not wired up in this version. Every command parses and validates its
> arguments and exits `2` with a plain "not available in this version" message instead of printing
> an empty ledger. `--help` and `--version` work fully.

```bash
# Scan a directory tree plus the system trust store
certledger collect --roots ./pki --source auto --json -

# One record per fingerprint, sources merged
certledger inventory --roots ./pki --json ledger.json

# Findings, pinned to an explicit instant (there is no "now" default)
certledger hygiene --inventory ledger.json --as-of 1900000000

# Deterministic report; exit 1 when anything reaches ERROR (default)
certledger report --inventory ledger.json --as-of 2030-03-17T17:46:40Z \
  --json report.json --markdown report.md

# Diff against the previous snapshot
certledger report --inventory ledger.json --as-of 1900000000 --baseline prev.json
```

`--as-of` is mandatory on every time-sensitive command and accepts Unix seconds or ISO-8601 with an
explicit offset. The report echoes it back verbatim.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | nothing reached the `--fail-on` threshold (default `ERROR`) |
| `1` | at least one finding reached the threshold |
| `2` | input, policy or argument error (missing `--as-of`, unreadable policy, bad path) |

A missing system backend does **not** change the exit code: it produces a `SOURCE_UNAVAILABLE`
record, because "not looked at" and "nothing there" are different answers.

## How it differs

| | Scope | Private keys | Containers | Dedup / orphans |
|---|---|---|---|---|
| CertLedger | one machine (directories + system stores) | yes, paired by SPKI hash | PKCS#12, JKS, JCEKS | yes |
| ChainWarden | one PEM file | no | no | no |
| certigo | one file | no | partial (read-only) | no |
| x509-certificate-exporter | disk glob, K8s-first | no | yes | no |

## Strength policy

Thresholds are **not** hard-coded. They live in `src/certledger/data/default-policy.json`, each with
a citation, and every finding repeats that citation in its `rule_source` field.

RSA 2048 is **not** "weak today": under NIST SP 800-57 Part 1 Rev. 5 it is 112-bit strength, and
Table 4 allows it "through 2030", disallowing it "2031 and beyond". The tool therefore reports it at
`INFO` behind an opt-in policy switch, and reports keys below 2048 bits (`WARN`) citing
CA/B Forum TLS BR v2.3.1 §6.1.5 and NIST SP 800-131A Rev. 2.

## Not in this version

No chain verification, no revocation checking, no remote TLS scanning, no SBOM/CBOM output, no
daemon, no alerting, no web UI. See `plan/01-题目文档.md` §六 for the reasoning behind each boundary.

## Development

```bash
py -3.12 tools/check-sprint-layout.py     # methodology layout gate
py -3.12 tools/check-desensitized.py      # no host paths / usernames / proxy ports
py -3.12 -m pytest -q
```

`AGENTS.md` is the entry point for any new session: **run the layout gate first**.

---

## 状态

| 里程碑 | 主题 | 状态 |
|---|---|---|
| M0 | 方法论装订 + 计划套件 + 可运行骨架 | ✅ 已完成 |
| M1 | 数据先行：样本生成器 + 八类样本 + 真值 | ⬜ 未开始 |
| M2 | 采集器：遍历 + 嗅探 + 后端 + 降级 | ⬜ 未开始 |
| M3 | 归一化台账：合并 + 双指纹 + SPKI 配对 | ⬜ 未开始 |
| M4 | 卫生规则：九类 finding + 策略 | ⬜ 未开始 |
| M5 | 报告 + 容器：双格式 + 退出码 + baseline | ⬜ 未开始 |
| M6 | 发布：tag + Release + 留档 | ⬜ 未开始 |

> 状态行只写"版本 + 能力"。是否已发布、CI 是否绿，以 Release 页与 `plan/` 为准——
> 随包读者手里没有 Release 页，不该靠这一行判断发布状态。
