# HANDOFF-M4 · 卫生规则（九类 finding + 策略驱动 + `--as-of`）

> 用法：以 `plan/HANDOFF-M4.md` 为入口续接本棒。**第一动作 = 跑两条门**（见 §7）。
> 本文件写于 2026-10-21（M3 收尾）。库内一律相对路径。

---

## 一、当前进度 + 证据

M0、M1、M2、M3 已完成并本地验证。M4 **未开始**。

| 已落地 | 证据（可复跑） |
|---|---|
| 方法论装订三件 | `AGENTS.md`、`tools/check-sprint-layout.py`、`tools/check-desensitized.py`、`plan/00` 顶部装订行 |
| 两道门全绿 | `py -3.12 -X utf8 tools/check-sprint-layout.py` → 10 项 PASS；`tools/check-desensitized.py` → 0 命中（67 文件） |
| 门自身可跑红 | `py -3.12 -X utf8 tools/selftest-gates.py` → 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 |
| 计划套件 | `plan/00`–`06`、`data/README.md` |
| 样本与真值 | `fixtures/gen.sh`（+`gen.py`）+ `fixtures/expected.json`（17 用例） |
| 嗅探器 | `parsing/{pem,asn1,sniff,fingerprint}.py` + **`parsing/x509.py`（M3 新增）** |
| 遍历器 | `collectors/walker.py`：NFC + casefold 排序键；六个跳过原因码；环检测用祖先链 |
| 三平台后端 | `collectors/backends.py`：linux 读 PEM bundle；windows 走 `certutil -split -store`；macOS 恒 `SOURCE_UNAVAILABLE` |
| 采集入口 | `collectors.collect` 返回 `{schema_version, kind, candidates, diagnostics, backends, summary}` |
| **采集器的第二出口** | `collectors.collect_with_items` 返回 `(payload, list[DecodedCandidate])`——同一遍读取，附带已解码对象 |
| **归一化台账** | `inventory.build()` 返回 `{schema_version, kind, certs[], keys[], diagnostics[], summary}` |
| 测试 | `PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q` → **232 passed / 1 skipped**（233 项收集）；`test_inventory.py` 27 例、`test_x509.py` 9 例 |
| 台账实测（夹具） | `inventory --roots fixtures/out` → 16 证书 / 13 私钥 / 11 配对 / 3 条 `PARSE_UNSUPPORTED`（P12 未展开） |
| 台账实测（真机存储） | `inventory --source windows` → 81 张证书**合并为 77 条**（4 张 Root/AuthRoot 重叠） |
| 隐私红线 | `git status --porcelain --untracked-files=all` 无任何 `*.pem/*.key/*.p12/*.jks/*.der/*.crt` |

**未发生的事**：CI 从未实跑（无远端）。M0–M3 的 CI 项一律记为"本地等价校验，未接远端，CI 待首推验证"。
**本机从未跑过 Linux 真实路径与 macOS 后端**（见 §二 第 3 条）。

---

## 二、当前事实·状态不变量（下一棒动手前必须知道）

1. **版本号只有一处**：`src/certledger/__init__.py::__version__`。`pyproject.toml` 用
   `dynamic = ["version"]`，**不要**加 `version = "…"`（`test_version_has_one_source` 会红）。
   `SCHEMA_VERSION` 也在 `__init__.py`，改台账/报告结构时要同步评估。

2. **状态副本有四个**：`plan/00` 里程碑表、`plan/05` 状态表、`README.md` 的「状态」表、
   `plan/00` 承诺-证据台账。**翻一个必须翻四个**。

3. **后端"真跑"到什么程度（务必照实引用，不要拔高）**：
   - **windows**：真跑。`certutil -split -store` 汇总 Root=18、AuthRoot=58、CA=5、My=0，共 81 张。
   - **linux**：**读取与 PEM 拆分路径**用真实 multi-block bundle 实测（注入路径）；
     **`/etc/ssl/certs/ca-certificates.crt` 这个真实位置在本机不存在，从未被读过**。
   - **macOS**：从未执行。代码恒返回 `SOURCE_UNAVAILABLE` + `unverified_backend: true`（D4）。

4. **`certutil -store Root` 只看到 18 张，合并视图是 76 张**。差额是 `AuthRoot` 自动更新配置单元
   （58 张，与 Root 有 4 张重叠）。只读 Root 会静默漏报 58 张根证书——**这是特性，不是 bug**。
   **M3 在台账层复现了同一现象**：81 张来源 → **77 条记录**（`test_windows_root_view_includes_authroot`
   与 `inventory` 的 77 条互为印证）。

5. **JCEKS 魔数是 `CECECECE`，JKS 是 `FEEDFEED`**（JDK 26 `keytool` 建库实测）。
   `plan/03` 原文的"同魔数"是错的，已在文档里划掉并注明。`CONTAINER_FORMAT_AMBIGUOUS` 因此不产出。

6. **`0x30` 也是 ASCII 的 `'0'`**。嗅探器**先判文本、再进 ASN.1**。

7. **`inventory.build` 已不是空壳**。`test_shells_raise_instead_of_returning_empty` 已把它摘出去；
   正向断言在 `test_inventory_returns_a_ledger_instead_of_raising`。
   **剩下三个空壳**（`hygiene` / `containers` / `render`）**仍必须抛 `NotImplementedError`**。
   `test_cli.py` 的 K7 断言已改指 `hygiene`。

8. **`--json` 两个位置都接受**；子命令侧用 `default=argparse.SUPPRESS`（argparse 经典陷阱）。
   `main()` 里补 `if not hasattr(args, "json"): args.json = None` 做归一。

9. **`summary` 的计数是不同单位**，不可相加：
   - 采集器：`visited` / `scanned` / `skipped` / `skip_records` / `deduplicated`；
     **恒等式只有一条：`visited == scanned + skipped`**。
   - 台账：`certs` / `keys` / `cert_sources` / `key_sources` / `paired_keys` / `locked_keys`，
     另嵌 `collect{visited,scanned,skipped}`。**没有任何两条可以相加**。

10. **环检测用祖先链，不用全局集合**；`_is_link_like()` 读 `st_reparse_tag`（Python 把
    Windows 联接报成普通目录）。

11. **`fixtures/expected.json` 的形状**（M4 直接拿它当输入）：
    `{schema_version, kind, as_of, as_of_utc, generator, policy_numbers_used,
      cases:[{case, group, index?, platform?, purpose, as_of, as_of_utc,
              inputs:[相对路径], artifacts:[{path,kind,format,reproducible,sha256,...}],
              expect:{findings:[{code,severity,count}], absent:[code], container?}}]}`
    `artifacts[].kind ∈ {cert, key, container, broken, noise}`；
    `reproducible ∈ {bytes, alias_table}`。

12. **台账记录的形状（M3 落地，M4 直接消费）**：
    ```
    certs[]: {fingerprint_sha256, spki_sha256,
              subject:{display,der_sha256}, issuer:{display,der_sha256},
              san:{dns,ip,email,uri}, not_before, not_after,
              key_algo, key_bits, curve, sig_algo, key_usage[], extended_key_usage[],
              is_ca, subject_key_id, sources[]}
    keys[]:  {spki_sha256, key_algo, key_bits, curve, encrypted,
              paired_cert_fingerprint, sources[]}
    diagnostics[]: {code, path, stage, detail}
    ```
    **`not_before` / `not_after` 已格式化为 `%Y-%m-%dT%H:%M:%SZ`**，可直接按字符串比较
    （ISO-8601 字典序 = 时间序），也可以 `parse_stamp()` 转秒。

13. **`spki_sha256` 只从原始 DER 切片来**（`parsing/x509.py::cert_parts`），不是
    `public_key().public_bytes()`。两者在 101 张证书上逐字节相等，但 K1 的契约是前者。
    `test_hash_inputs_are_the_block_bytes_we_read` 钉住**输入**；
    `test_fingerprints_match_an_independent_tool` 用 `openssl` 做独立交叉校验。

14. **v1 证书的 `TBSCertificate` 只有 6 个字段**（无 `[0] version`）。按"≥7"守卫会静默丢
    issuer/subject 哈希——本机 3 张 1997 年 v1 根证书就是这么丢的。守卫按 issuer 起点算偏移。

15. **本机 81 张真实存储证书里有 1 张解不出公钥**（`CN=Root Agency`，`1.2.840.113549.1.1.4`
    md5WithRSAEncryption）。它的 **指纹与 `spki_sha256` 正确**，`key_algo`/`key_bits` 为空字符串。
    **丢记录是错的**：那会让台账少一张。`_public_key()` 返回 `None` 而不是抛。

16. **未展开的容器产 `PARSE_UNSUPPORTED`（`stage=container`）**，不静默消失。
    M5 落地 `containers` 后这条应消失；在那之前它必须存在。

17. **加密私钥（`key_locked`）的 `spki_sha256 = null`，且按路径而非 SPKI 归并**。
    用 `""` 之类的哨兵会把机器上所有加锁私钥并成一条——比不合并更糟，因为它**断言了一个
    未经验证的身份**。`test_two_locked_keys_do_not_merge_into_one_record` 钉住。

18. **同 SPKI 多证书时，`paired_cert_fingerprint` 取最小指纹**。台账里两张证书都保留，
    只是指针按字典序钉死（否则两次运行会不同）。`test_one_key_shared_by_two_certificates_*` 钉住。

19. **`MANIFEST.in` 已含 `fixtures *.sh *.py *.md *.json`**（M1 已补，无需再动）。

20. **生成器刻意不造 ECDSA 与 JKS 样本**。M4 若需要 ECDSA 输入，用 `tmp_path` 现造。

21. **`tools/selftest-gates.py` 的 M9 变异已改为"插入一行"**，不再改写既有台账行。
    旧写法绑定了某一行文本，那一行随 M3 落地而合法变化，变异随即无法施加。
    **改台账内容不必再担心打挂自检**；改台账**结构**（表头列名）仍会。

22. **`containers <path>` 的崩溃已修（M0 遗留缺陷，M3 顺手补）**：
    旧 `_validate()` 用「是否有 `policy` 参数」判断要不要要求 `--roots`，而 `containers`
    只有 `--policy` 和位置参数 `paths`，于是落进 `--roots` 分支，`args.roots` 不存在 →
    `AttributeError` traceback + **退出码 1**。退出码契约只有 0/1/2，traceback 不是其中任何一个。
    判据已改成「是否真的有 `roots`/`files` 属性」；`test_containers_with_a_path_exits_two_without_a_traceback` 钉住。
    **M4 不要再动 `_validate` 的这段判断**，除非同时改这条测试。

---

## 三、下一棒待办（M4）

按 `plan/03` §③ 执行，顺序建议：

1. **`hygiene.evaluate()`**：输入 = 台账（`inventory.build()` 的结果，或 `--inventory <path>` 读回）
   + 策略 + `as_of`（`timebase.AsOf`，**必填**）。
   - 九类规则见 `plan/03` §③ 规则表；**每条 finding 必须带 `rule_source`**。
   - 阈值全部走 `policy.require(...)`，**零代码字面量**（K3）。
   - `level: off` 时不产 finding，但计入 `summary.suppressed`。

2. **`ORPHAN_*` / `DUPLICATE_*` 直接读台账字段**，不要重新判定配对：
   - `ORPHAN_CERT` ⟺ 证书的 `spki_sha256` 不在任何 `keys[].spki_sha256` 里；
   - `ORPHAN_KEY` ⟺ 私钥的 `spki_sha256` 不在任何 `certs[].spki_sha256` 里；
     **`spki_sha256 is None` 的加锁私钥不算孤儿**（不知道它的 SPKI，就不能断言它没有证书）；
   - `DUPLICATE_CERT` ⟺ `sources` 长度 > 1；`DUPLICATE_KEY` 同理。

3. **`EXPIRY_CLIFF` 按去重指纹计数**：窗口内 `EXPIRING + EXPIRED` 的**唯一 `fingerprint_sha256`**
   ≥ `cliff_min_count`。多副本不放大（`test_fixtures_truth.py` 已有独立复算，
   `hygiene` 若与之不一致，**其中一个错了**）。

4. **`PARSE_FAILED` / `SOURCE_UNAVAILABLE` / `PARSE_UNSUPPORTED` 也要变成 finding**，
   否则"没找到"与"没看"在报告里无法区分（`plan/03` §③ 补充）。

5. **`--as-of` 缺失 → 退出码 2**（parser 已 `required=True`，M0 已落）；`hygiene` 缺 `--roots`
   但有 `--inventory` 时**不得**报"缺少输入"（`test_cli.py::test_inventory_path_does_not_require_roots` 已在）。

6. **`tests/test_hygiene.py`**（`plan/06` 点名的文件名，请照用）：
   - 17 个真值用例逐条对账（`expect.findings` 的 code+count、`expect.absent`）；
   - 策略改阈值 → severity 翻转（同一 fixture，两份策略）；
   - `rule_source` 非空且匹配 `RFC|CA/B|NIST|SP 800|本项目定义`；
   - `POLICY_NIST_2031` 文案不含"当前已弱"（`test_strength.py` 可并入或单开，`plan/06` 点了两个名）。

7. **改 `test_architecture.py::test_shells_raise_instead_of_returning_empty`**：
   把 `hygiene.evaluate` 摘出去，换成正向断言（照 M2 对 `collect`、M3 对 `inventory` 的做法）。

8. 回写四个状态副本；同步 `plan/06` 缺口表（G1/G3/G4/G5/G7 仍开着，**不要**动它们的状态；
   G5「Windows ACL 判定细则」在 M4 定稿）。

9. **写 `plan/HANDOFF-M5.md`（七节）**。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| 编号 | 约定 | 断言位置 |
|---|---|---|
| K1 | 指纹只对 DER 原始字节做 SHA-256 | `parsing/fingerprint.py::der_sha256`（唯一入口）；`test_only_parsing_computes_hashes`（`policy/loader.py` 是白名单例外）；`test_hash_inputs_are_the_block_bytes_we_read`（M3 钉住输入）；`test_fingerprints_match_an_independent_tool`（openssl 交叉校验） |
| K2 | `--as-of` 必填，不许回退到 `now()` | `test_architecture.py::test_single_clock_source`、`tests/test_timebase.py` |
| K3 | 阈值只从策略文件读；缺失/非法 → 退出 2 | `tests/test_policy.py`；`test_collect_requires_a_policy`；`test_inventory_requires_a_policy`（M3 新增）；`test_sniff_window_comes_from_policy` |
| K4 | 配对键 = `spki_sha256`，不用文件名 / subject / SKI | `test_certificate_and_key_pair_on_spki` / `test_same_cn_with_different_keys_is_not_paired` / `test_orphan_case_pairs_neither_side`；**配对键变异会打红 3 个用例**（M3 实测） |
| K5 | 报告无时间戳 / 主机名 / 用户名；键序固定 | `tests/test_model.py`；`test_key_order_is_declared_not_alphabetical`；`test_ledger_carries_no_host_name_or_timestamp` |
| K6 | 后端不可用 → `SOURCE_UNAVAILABLE`，退出码不变 | `test_unavailable_backend_keeps_exit_code_zero`、`test_macos_backend_is_always_unavailable_and_flagged` |
| K7 | 不设"未实现"退出码；未落地能力 → 可见记录或退出 2 | `test_cli.py::test_unimplemented_module_exits_two_without_claiming_success`（现指 `hygiene`）+ `test_inventory_answers_instead_of_claiming_unimplemented` |

数值口径的唯一权威是 `data/README.md` §五。`src/certledger/data/default-policy.json` 是它的机器副本。
**`fixtures/expected.json::policy_numbers_used` 是第三份副本**——改策略必须同轮重跑
`bash fixtures/gen.sh` 重新生成真值，否则 `test_every_expectation_recomputes_from_recorded_inputs` 会红。

---

## 五、本机环境坑（只写实测过的）

- **Windows + Git Bash**：`py -3.12`（3.12.10）与 `py -3.8`（3.8.8）。项目下界 3.10，
  3.8 通道**跑不了本项目**。
- **`py -X utf8` 是本机习惯**：不加它时中文控制台是 cp936。CI 里已设 `PYTHONUTF8=1`。
- **Git Bash 的 `/tmp` 与 Windows Python 路径不通**：`/tmp/x` 传给 `py` 会找不到。
  用 `cygpath -w /tmp/x` 转换。
- **`cd /tmp` 再跑 `py` 会被 `/tmp/*.py` 遮蔽 stdlib**。
- **`certutil` 的输出编码是 `mbcs`（本机 cp936）**。M2 因此不解析控制台文本，改用 `-split` 落 DER。
- **`certutil -split -store <name>` 把文件写到当前工作目录**。正确用法：
  `subprocess.run(..., cwd=<临时目录>)` 然后 glob `*.crt`。
- **Windows 上 `Path.symlink_to` 需要管理员权限**；`mklink /J` 建目录联接不需要。
- **Python 把 Windows 目录联接报成普通目录**：只能靠 `st_reparse_tag`（`0xA0000003`）分辨。
- **`cryptography` 对非正序列号证书发 `CryptographyDeprecationWarning`**。那是文件的属性。
  M3 的 `inventory.py` 不额外捕获它（`sniff._load_certificate()` 已局部静音）；
  跑手工脚本时用 `-W ignore` 或 `warnings.simplefilter`。
- **`cryptography` 50.0.2 的 `public_key()` 会对 md5WithRSA 证书抛 `ValueError`**
  （实测 `CN=Root Agency`）。这不是本工具的缺陷，但任何"遍历所有证书并解公钥"的新代码
  都必须能容忍它——`inventory._public_key()` 已做。
- **`ObjectIdentifier` 没有公开的 `.name` 属性**；短名只在 `_name` 上
  （`sig_algo` 因此存 dotted string，`extended_key_usage` 存 `_name`）。升级 `cryptography`
  时要复测这两处。
- **OpenSSL 3.5.6（本机）**：`req -x509` 支持 `-not_before` / `-not_after` / `-set_serial`。
- **JDK 26 的 `keytool`** 在 `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`，**不在 PATH 上**。
- **本机没有 `python` 别名**，用 `py -3.12`。

---

## 六、DoD 逐项 checklist（M3，已验）

- [x] 同证书 3 处来源 → 1 条记录、`sources` 长 3
      → `test_three_copies_merge_into_one_record_with_three_sources`
      **变异**：把归并键改成 path → 5 个用例变红（实测）
- [x] 双指纹由 `parsing/fingerprint.py` 单一入口产出
      → `test_hash_inputs_are_the_block_bytes_we_read`（钉住**输入**，不是值）
      + `test_fingerprints_match_an_independent_tool`（`openssl` 交叉校验）
      **变异**：改成对整文件字节求哈希 → 6 个用例变红（实测）
- [x] SPKI 配对正确；同 CN 不同密钥对不误配
      → `test_certificate_and_key_pair_on_spki` / `test_same_cn_with_different_keys_is_not_paired`
      / `test_orphan_case_pairs_neither_side`
      **变异**：按 CN 配对 → 3 个用例变红（实测）
- [x] JSON 键序固定；两次运行字节级相同
      → `test_key_order_is_declared_not_alphabetical` / `test_two_runs_are_byte_identical`
      / `test_record_order_does_not_depend_on_walk_order`
- [x] `PARSE_FAILED` 带 `path` + `stage`
      → `test_broken_der_is_parse_failed_with_path_and_stage`
- [x] 记录模型补齐 `subject`/`issuer` 的 `der_sha256`（`plan/03` §② 原样）
      → `test_subject_and_issuer_hashes_are_over_the_der_name` + `tests/test_x509.py`（9 例）
- [x] v1 证书可切片（本机 3 张 1997 年根证书的教训）
      → `test_v1_certificate_has_no_version_field_and_still_slices`
      **变异**：假定恒为 v3 → 该用例变红（实测）
- [x] 未展开容器可见 → `test_container_that_was_not_opened_is_reported_not_dropped`
- [x] 加密私钥保留记录且不误并 → `test_encrypted_key_without_a_passphrase_keeps_a_record`
      + `test_two_locked_keys_do_not_merge_into_one_record`
- [x] 三个空壳仍抛 `NotImplementedError`；CLI 的 K7 断言改指 `hygiene`
      → `test_shells_raise_instead_of_returning_empty` + `test_unimplemented_module_exits_two_without_claiming_success`
- [x] `inventory` 无 `--max-size`（`collect` 独有） → `certledger inventory --help` 实测无该项
- [x] 四个状态副本同轮翻 M3 为 ✅；`tools/check-sprint-layout.py` 全绿
- [x] `tools/selftest-gates.py` 仍全红（10 + 4），且 M9 变异已改为不依赖台账文字
- [x] 隐私：`git status --porcelain --untracked-files=all` 无证书类文件
- [x] `containers <path>` 不再 traceback（M0 遗留缺陷）：退出 2 而非 1
      → `test_containers_with_a_path_exits_two_without_a_traceback`（变异回旧判据会变红，实测）
- [x] `plan/HANDOFF-M4.md` 七节齐并已落盘

---

## 七、关键命令速查

```bash
# 门（任何新对话的第一件事）
py -3.12 -X utf8 tools/check-sprint-layout.py
py -3.12 -X utf8 tools/check-desensitized.py
py -3.12 -X utf8 tools/selftest-gates.py

# 测试（源码树，无需安装）
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q -m system -v   # 碰宿主存储的用例

# 只看台账
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest tests/test_inventory.py tests/test_x509.py -q

# 样本（M1 产出；后续拿来当输入）
bash fixtures/gen.sh --list
bash fixtures/gen.sh
bash fixtures/gen.sh --check
bash fixtures/gen.sh --determinism
bash fixtures/gen.sh --only healthy --out <dir>

# 采集 / 台账冒烟
PYTHONPATH=src py -3.12 -X utf8 -m certledger collect  --roots fixtures/out --source none
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --roots fixtures/out --source none
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --source windows          # 真读 Windows 存储
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --roots . --source none --json out.json

# 安装 + CLI 冒烟
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/certledger.exe inventory --roots fixtures/out --source none

# 打包
./.venv/Scripts/python.exe -m build --sdist --wheel --outdir <空目录>
```

> Windows 上 `git status --porcelain` 里出现 `__pycache__` 时，先 `PYTHONDONTWRITEBYTECODE=1` 重跑；
> CI 的 `no-residue` job 会在干净树上断言行数不变。
