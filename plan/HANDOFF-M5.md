# HANDOFF-M5 · 报告与容器（JSON + Markdown + 退出码 + baseline + keytool）

> 用法：以 `plan/HANDOFF-M5.md` 为入口续接本棒。**第一动作 = 跑两条门**（见 §七）。
> 本文件写于 2026-10-21（M4 收尾）。库内一律相对路径。

---

## 一、当前进度 + 证据

M0、M1、M2、M3、M4 已完成并本地验证。M5 **未开始**。

| 已落地 | 证据（可复跑） |
|---|---|
| 方法论装订三件 | `AGENTS.md`、`tools/check-sprint-layout.py`、`tools/check-desensitized.py`、`plan/00` 顶部装订行 |
| 两道门全绿 | `py -3.12 -X utf8 tools/check-sprint-layout.py` → 10 项 PASS；`tools/check-desensitized.py` → 0 命中（70 文件） |
| 门自身可跑红 | `py -3.12 -X utf8 tools/selftest-gates.py` → 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 |
| 计划套件 | `plan/00`–`06`、`data/README.md` |
| 样本与真值 | `fixtures/gen.sh`（+`gen.py`）+ `fixtures/expected.json`（17 用例） |
| 嗅探器 | `parsing/{pem,asn1,sniff,fingerprint,x509}.py` |
| 遍历器 | `collectors/walker.py`：NFC + casefold 排序键；六个跳过原因码；环检测用祖先链 |
| 三平台后端 | `collectors/backends.py`：linux 读 PEM bundle；windows 走 `certutil -split -store`；macOS 恒 `SOURCE_UNAVAILABLE` |
| 采集入口 | `collectors.collect` / `collectors.collect_with_items` |
| 归一化台账 | `inventory.build()`；**M4 新增 `sources[].posix_mode`** |
| **卫生规则** | `hygiene.evaluate()`：九类规则 + 失败路径成 finding + `level: off` 计数 |
| **策略校验** | `policy/loader.py`：`RULE_BLOCKS` 11 块 + `hygiene.diagnostics`（`default` + `codes`）；`level` ∈ {ERROR,WARN,INFO,off}；`max_posix_mode` 必须是八进制字符串 |
| **时间戳解析** | `timebase.parse_stamp()`（台账 `%Y-%m-%dT%H:%M:%SZ` → 秒；失败返回 `None`，不抛） |
| 测试 | `PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q` → **303 passed / 1 skipped**（304 项收集）；`test_hygiene.py` 48 例、`test_strength.py` 14 例、`test_asof.py` 7 例 |
| 17 用例对账 | **code + severity + count** 13 条端到端一致；**`absent` 与 `rule_source` 两族断言覆盖 17 条**；余 4 条的差集被测试逐名钉住（见 §二 第 7 条） |
| 变异实测（M4 新增 9 组） | 计数单位 / 加锁私钥 / 未解码算法 / 丢弃诊断 / 忽略 `off` / 边界含等号 / 丢 `rule_source` / 掩码取反 / 摘要表失效——每组都打红对应用例 |
| 隐私红线 | `git status --porcelain --untracked-files=all` 无任何 `*.pem/*.key/*.p12/*.jks/*.der/*.crt` |

**未发生的事**：CI 从未实跑（无远端）。M0–M4 的 CI 项一律记为"本地等价校验，未接远端，CI 待首推验证"。
**本机从未跑过 Linux 真实路径与 macOS 后端**（见 §二 第 3 条）。

---

## 二、当前事实·状态不变量（下一棒动手前必须知道）

1. **版本号只有一处**：`src/certledger/__init__.py::__version__`。`pyproject.toml` 用
   `dynamic = ["version"]`，**不要**加 `version = "…"`。`SCHEMA_VERSION` 也在 `__init__.py`
   与 `model.py`（两处都是 `1`；M4 未动它，因为是**加字段**不是改形状——若 M5 改报告结构，
   先决定是否要把它抬到 2，并同步两个定义点）。

2. **状态副本有四个**：`plan/00` 里程碑表、`plan/05` 状态表、`README.md` 的「状态」表、
   `plan/00` 承诺-证据台账。**翻一个必须翻四个**。

3. **后端"真跑"到什么程度（务必照实引用，不要拔高）**：
   - **windows**：真跑。`certutil -split -store` 汇总 Root=18、AuthRoot=58、CA=5、My=0，共 81 张。
   - **linux**：读取与 PEM 拆分路径用真实 multi-block bundle 实测（注入路径）；
     **`/etc/ssl/certs/ca-certificates.crt` 这个真实位置在本机不存在，从未被读过**。
   - **macOS**：从未执行。代码恒返回 `SOURCE_UNAVAILABLE` + `unverified_backend: true`（D4）。

4. **`certutil -store Root` 只看到 18 张，合并视图是 76 张**。差额是 `AuthRoot` 自动更新配置单元
   （58 张，与 Root 有 4 张重叠）。只读 Root 会静默漏报 58 张根证书——**这是特性，不是 bug**。
   台账层复现同一现象：81 张来源 → **77 条记录**。

5. **JCEKS 魔数是 `CECECECE`，JKS 是 `FEEDFEED`**（JDK 26 `keytool` 建库实测）。
   `plan/03` 原文的"同魔数"是错的，已在文档里划掉并注明。`CONTAINER_FORMAT_AMBIGUOUS` 因此不产出。

6. **`0x30` 也是 ASCII 的 `'0'`**。嗅探器**先判文本、再进 ASN.1**。

7. **M4 之后还剩两个空壳**：`containers.inspect` 与 `render.render`，**都仍必须抛
   `NotImplementedError`**。`test_architecture.py::test_shells_raise_instead_of_returning_empty`
   现在只断这两个；`test_cli.py` 的 K7 断言已改指 `report`。
   **`hygiene.evaluate` 已不是空壳**，正向断言在 `test_hygiene_returns_findings_instead_of_raising`。

8. **`--json` 两个位置都接受**；子命令侧用 `default=argparse.SUPPRESS`；
   `main()` 里补 `if not hasattr(args, "json"): args.json = None` 做归一。

9. **`summary` 的计数单位不可相加**：
   - 采集器：`visited == scanned + skipped`（唯一恒等式）。
   - 台账：`certs` / `keys` / `cert_sources` / `key_sources` / `paired_keys` / `locked_keys`，
     **没有任何两条可以相加**。
   - **卫生输出（M4 新增）**：`summary.records.{certs,keys,diagnostics}`（台账条数）
     vs `summary.findings`（判定条数）——一个是"有多少资产"，一个是"有多少结论"，
     一条记录可带多条 finding 或零条。断言只写"恒等式是集合划分"：
     `sum(summary.by_severity.values()) == summary.findings`。
   - `summary.suppressed` / `suppressed_by_code`：被 `level: off` 关掉的规则**本会**产出的条数。

10. **环检测用祖先链，不用全局集合**；`_is_link_like()` 读 `st_reparse_tag`。

11. **`fixtures/expected.json` 的形状（M5 直接拿它当输入）**：
    `{schema_version, kind, as_of, as_of_utc, generator, policy_numbers_used,
      cases:[{case, group, index?, platform?, purpose, as_of, as_of_utc,
              inputs:[相对路径], artifacts:[{path,kind,format,reproducible,sha256,...}],
              expect:{findings:[{code,severity,count}], absent:[code], container?}}]}`。
    `artifacts[].kind ∈ {cert, key, container, broken, noise}`；
    `reproducible ∈ {bytes, alias_table}`；`platform ∈ {None, "posix"}`。

12. **台账记录的形状**：
    ```
    certs[]: {fingerprint_sha256, spki_sha256, subject:{display,der_sha256},
              issuer:{display,der_sha256}, san:{dns,ip,email,uri}, not_before, not_after,
              key_algo, key_bits, curve, sig_algo, key_usage[], extended_key_usage[],
              is_ca, subject_key_id, sources[]}
    keys[]:  {spki_sha256, key_algo, key_bits, curve, encrypted,
              paired_cert_fingerprint, sources[]}
    sources[]: {kind, path, container_format, alias, entry_type, store_name, posix_mode}
    diagnostics[]: {code, path, stage, detail}
    ```
    `not_before` / `not_after` 是 `%Y-%m-%dT%H:%M:%SZ`，可用 `timebase.parse_stamp()` 转秒
    （**不要**自己 `strptime`，那是第二个时间解析入口）。
    **`posix_mode` 是 M4 新增字段**：八进制字符串或 `None`（见第 13 条）。

13. **`sources[].posix_mode` 只在 POSIX 平台有值**（`inventory._posix_mode`）。
    由采集器在**读到文件的那一刻**取值，之后不再重读——台账可能在另一台机器上被 `hygiene`
    消费，在那里 `stat` 描述的是另一个文件系统。
    **Windows 记 `null`**：Python 在 Windows 上把只读位报成 `0o666`，若照记会让**每一个**
    私钥都判成 `PERMISSION_TOO_OPEN`。这是 G5 的定稿结论（不做 ACL 判定），理由写在
    `data/README.md` §六。**`gen.py::write_private_key` 现在会 `chmod 0600`**，`perm`
    用例在其后显式设 `0644`——所以 `healthy` 之类的用例在 POSIX 上不会因 umask 而"不健康"。

14. **`hygiene.evaluate` 的签名与输入**：`(roots, files, inventory_path, as_of, policy, source)`。
    `inventory_path` 给了就**只读台账**（不再扫盘）；否则走一次 `inventory.build()`。
    台账文件的 `kind` 必须是 `"inventory"`，否则退出 2——把 `collect` 的输出喂进来会丢掉
    全部记录，那是"看起来跑通了"的失败。
    `as_of` 与 `policy` 都是必填，引擎层各自抛 `CliError`（不只是 parser 拦）。

15. **`sig_algo` 是 dotted OID，不是算法名**（`ObjectIdentifier` 没有公开 `.name`）。
    `hygiene._signature_name()` 查私有 `_name` 后与策略 `forbidden_digests`（`sha1` / `md5`）
    做小写子串比对；查不到名字就退化成 dotted 串 → **匹配不上任何摘要名 → 不产 `WEAK_SIG`**。
    升级 `cryptography` 时要复测这一处与 `inventory._extended_key_usage()`。

16. **未知 ≠ 弱**（三条，都有测试钉住）：
    - `key_algo == ""`（本机 81 张真实存储证书里 1 张，`CN=Root Agency`，MD5 签发）→ 不判 `WEAK_KEY`；
    - `not_after` 解不出来 → 不判 `EXPIRED` / `EXPIRING`（记录仍在 `summary.records` 里）；
    - `spki_sha256 is None` 的加锁私钥 → 不判 `ORPHAN_KEY`（"查不了"不是"没有"）。

17. **`level: off` 的语义**：不产 finding，但**按码计数**进 `summary.suppressed_by_code`。
    没有这个计数，"规则被关了"与"机器上没问题"会渲染成同一份报告。

18. **失败路径全部成 finding**，级别在策略 `hygiene.diagnostics.codes` 里逐码给定，
    未列出的码取同块 `default`（现为 `INFO`）。采集器的码表是开放的（`SKIP_*` 会随遍历器增长），
    **硬化成代码分支会让新码静默消失**——M5 加新的 `CONTAINER_*` 码时，想清楚要不要给 override。

19. **`CONTAINER_*` 三条规则已经实现，消费台账的 `containers[]` 段**（M5 负责填充）：
    ```jsonc
    {"path": "…", "format": "pkcs12|jks|jceks", "password": "set|empty|unknown",
     "has_private_key": true,
     "entries": [{"alias": "…", "entry_type": "privateKey|trustedCert|secretKey"}],
     "unreadable": null}   // 读不了时给一句 reason，entries 为空
    ```
    规则细节：`CONTAINER_TRUSTSTORE_WITH_KEY` ⟺ 有私钥条目**且**有非私钥条目；
    `CONTAINER_EMPTY_PASSWORD` ⟺ `password == "empty"`；
    `unreadable` 非空 → `CONTAINER_UNREADABLE`（走 `emit_failure`，级别取 `diagnostics.codes`）。
    **该段缺席时规则不产 finding，容器本身仍以 `PARSE_UNSUPPORTED`（`stage=container`）可见**。

20. **`inventory` 对未展开的容器产 `PARSE_UNSUPPORTED`（`stage=container`）**。
    M5 展开容器后这条**应当消失**——`tests/test_inventory.py::
    test_container_that_was_not_opened_is_reported_not_dropped` 会变红，那是提醒，不是故障。
    同时 `tests/test_hygiene.py::test_the_unreconciled_cases_are_exactly_the_documented_ones`
    也会变红（它断言"恰好 multi-alias / truststore-with-key / empty-pass / perm 这 4 条没对上"）。
    **两条测试一起改，不要只改一条。**

21. **`hygiene` 没有自己的退出码阈值**：它在能跑时恒返回 0（CLI `_emit`）。
    `--fail-on` 与 1 号退出码是 `report` 的职责（`plan/03` §④），M5 落地。

22. **`hygiene` 的输出头部回显 `as_of` / `as_of_utc` / `policy_version` / `policy_sha256`**，
    顶层键序 = `["schema_version","kind","as_of","as_of_utc","policy_version",
    "policy_sha256","findings","summary"]`；finding 键序 = `["code","severity","subject",
    "fingerprint","evidence","rule_source"]`。**M5 的 report 头要回显 `tool_version` 与
    `as_of` 原样**（`plan/03` §④）——hygiene 现在没带 `tool_version`，report 自己补。

23. **`policy_version` 已是 `1.1.0`**（M4 加了 level / diagnostics / statement 等块）。
    策略文件是**唯一**数值与级别口径（`data/README.md` §五.1–§五.14）。
    **改策略必须同轮重跑 `bash fixtures/gen.sh`** 重新生成 `expected.json`，
    否则 `test_every_expectation_recomputes_from_recorded_inputs` 会红——
    它记的 `policy_numbers_used` 只有 4 个数（warn_days / cliff_window_days /
    cliff_min_count / weak_key_rsa_min_bits），改这 4 个之外的块不必重生成。

24. **`tools/selftest-gates.py` 的 M9 变异是"插入一行"**，不再改写既有台账行。
    改台账内容不必再担心打挂自检；改台账**结构**（表头列名）仍会。

25. **`evaluate` 直接把 finding 排好序输出**（`model.sorted_findings`：
    severity → code → subject → fingerprint）。两次运行字节级相同已测
    （`test_two_runs_are_byte_identical`）。M5 的 JSON/Markdown 两格式必须共用这一序。

26. **容器用例的真值形状（M5 对账时直接用）**：`expect.container` 给
    `{format, password: "set"|"empty", has_private_key, entries:[{alias, entry_type,
    fingerprint_sha256, spki_sha256}]}`。三个用例的期望 finding：
    - `multi-alias`：`DUPLICATE_CERT` 1 + `ORPHAN_CERT` 1（两个 alias 同一指纹）；
    - `truststore-with-key`：`ORPHAN_CERT` 1 + `CONTAINER_TRUSTSTORE_WITH_KEY` 1；
    - `empty-pass`：`CONTAINER_EMPTY_PASSWORD` 1。
    **注意 `entries[].fingerprint_sha256` 是证书 DER 的哈希**，与台账 `certs[].fingerprint_sha256`
    同一空间；`spki_sha256` 与 `keys[]` 同一空间。M5 展开容器后应能直接复用这两列做交叉核对。

27. **`PUBLIC_VALIDITY_HINT` 已决定不做**（`plan/03` §③ 规则表第 10 行，标"不参与合规判定"）。
    它的判据是 CA/B BR §6.3.2 的 200/100/47 天日期表，夹具证书的有效期（730 / 375 天）会**全部**命中，
    而真值文件是在没有这条规则的前提下生成的——做进 `findings` 会让 17 条真值全部失真。
    要做的唯一合法路径：**展示层**（不进 `findings`、不影响退出码）+ 先把日期表写进策略文件。
    `test_fixtures_truth.py::KNOWN_CODES` 里保留该码，是给将来留的位置，不是遗漏。

---

## 三、下一棒待办（M5）

按 `plan/03` §④⑤ 执行，顺序建议：

1. **`render.render()`**：输入 = (台账 或 roots/files) + 策略 + `as_of`
   + `json_path` / `markdown_path` / `baseline` / `fail_on` / `top` / `redact`。
   - 内部先调 `hygiene.evaluate`（**渲染层零判定**：`render/` 不得 import `hygiene`——
     AST 守门已在 `test_architecture.py::test_render_layer_does_not_judge`。
     也就是说 report 要么自己调 hygiene 并把结果传进 render，要么让 render 只做渲染）。
   - 报告头回显：`as_of`（**原样**）、`policy_version`、`policy_sha256`、`tool_version`、
     `schema_version`。
   - 退出码：`--fail-on ERROR|WARN|INFO|none`，缺省取策略 `report.default_fail_on`；
     `none` 时恒 0（仍输出 finding）。**1 号码只在这里产生**。
   - `--top N` **只影响展示**：`findings` 全集与退出码不变（`plan/03` §③ 过期表）。
     写一条断言钉住——截断门禁 = CI 后门。
   - `--baseline prev.json` 三类 diff：`added` / `removed` / `rotated`。
     **轮换判定**：同 `subject` 且同 `spki_sha256` 但 `fingerprint_sha256` 不同 → 同一密钥重签；
     同 `subject` 且 `spki_sha256` 也不同 → `removed` + `added`（**不叫轮换**）。
   - 绝对路径默认打码（`render/redact.py`，**按路径形态判断**而非前缀硬编码）；
     `--no-redact` 关掉。Markdown 正文**零外链**（不得出现 `http(s)://`；
     `rule_source` 里的规范号是文本不是链接）。
   - **多格式同源**：JSON 与 Markdown 由同一个内存模型渲染；Markdown 表格行数 = `findings` 条数。

2. **`containers.inspect()`**：PKCS#12 走
   `cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates`；
   JKS / JCEKS 走 `keytool -list -v`，**按 `Alias name:` / `Entry type:` 等键取值**，
   不依赖列宽与本地化排版（`LC_ALL=C`）。
   - `keytool` 缺失/超时/非零退出 → `CONTAINER_UNREADABLE`（含 stderr 首行，
     **口令不得出现在 detail 里**）；子进程超时 20s，超时 → `reason=timeout`。
   - 口令只从 `--password-env` 读；**不进 args**（ps 可见）、**不落盘**、**不进报告**。
   - 别名条目按 alias 排序；`same_fingerprint_aliases[]` 一列。
   - 输出里**另给 `containers[]` 段**（形状见 §二 第 19 条），供 `hygiene` 消费。

3. **把 `containers[]` 接进台账**：`inventory.build`（或 report 的取数路径）填这一段，
   同时让未展开容器的 `PARSE_UNSUPPORTED` **消失**（§二 第 20 条的两条测试一起改）。
   容器内条目要归并进 `certs[]` / `keys[]`：`sources[].kind="container"`、
   `container_format`、`alias`、`entry_type` 都填上——`Source` 这三个字段 M3 就留好了，
   一直没人填。

4. **`tests/test_determinism.py`**（`plan/06` 点名）：同输入同 `--as-of` 两次运行，
   JSON 与 Markdown **都**字节级相同（`sha256` 相等）。

5. **`tests/test_exit_codes.py`**（`plan/06` 点名）：0/1/2 三条用例 + `--fail-on none` 恒 0。

6. **`tests/test_baseline.py`**（`plan/06` 点名）：`added` / `removed` / `rotated` 各一用例。

7. **`tests/test_containers.py`**（`plan/00` 招牌动词表点名）：多别名样本列出全部 alias；
   无 JDK 环境降级为 `CONTAINER_UNREADABLE` 且退出 0。
   **P12 真跑**（`fixtures/out/multi-alias/*.p12` 本机可读，M4 已实测过
   `pkcs12.load_key_and_certificates`）；JKS 走 keytool，本机 `keytool` 在
   `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`（**不在 PATH 上**）。

8. **改 `test_architecture.py::test_shells_raise_instead_of_returning_empty`**：
   把 `render.render`（和 `containers.inspect`）摘出去，换成正向断言（照 M2 对 `collect`、
   M3 对 `inventory`、M4 对 `hygiene` 的做法）。
   同时 `test_cli.py` 的 K7 断言（现指 `report`）**没有空壳可指了**——
   改成断言"未落地能力"的语义已退役（G1 的复核动作），或指向一个新空壳。

9. **回写四个状态副本**；同步 `plan/06` 缺口表（G1 / G3 / G4 / G7 仍开着，**不要**动它们的状态；
   G1 的关闭条件是"M5 复核文案并确认无需退役动作"——**这就是本棒要做的事**。G5 与 G8 已关闭，
   别把它们翻回 ⬜）。

10. **`plan/05` §五「已知未验证项」里那条"三个容器用例与 `perm` 用例尚未端到端对账"**：
    容器三条在这一棒应该能关掉；`perm` 那条要写明平台前提（POSIX 机器上跑
    `bash fixtures/gen.sh` 后 `test_case_matches_the_truth_file` 才能涵盖它）。

11. **写 `plan/HANDOFF-M6.md`（七节）**。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| 编号 | 约定 | 断言位置 |
|---|---|---|
| K1 | 指纹只对 DER 原始字节做 SHA-256 | `parsing/fingerprint.py::der_sha256`（唯一入口）；`test_only_parsing_computes_hashes`（`policy/loader.py` 是白名单例外）；`test_hash_inputs_are_the_block_bytes_we_read`；`test_fingerprints_match_an_independent_tool`（openssl 交叉校验） |
| K2 | `--as-of` 必填，不许回退到 `now()` | `test_architecture.py::test_single_clock_source`、`tests/test_timebase.py`、`test_hygiene.py::test_as_of_is_mandatory` |
| K3 | 阈值/级别只从策略文件读；缺失/非法 → 退出 2 | `tests/test_policy.py`；`test_collect_requires_a_policy`；`test_inventory_requires_a_policy`；`test_hygiene.py::test_policy_is_mandatory`；`test_strength.py` 的 4 组策略变体 |
| K4 | 配对键 = `spki_sha256`，不用文件名 / subject / SKI | `test_certificate_and_key_pair_on_spki` / `test_same_cn_with_different_keys_is_not_paired` / `test_orphan_case_pairs_neither_side`；`hygiene._pairing_rules` 只读台账字段 |
| K5 | 报告无时间戳 / 主机名 / 用户名；键序固定 | `tests/test_model.py`；`test_key_order_is_declared_not_alphabetical`；`test_hygiene.py::test_key_order_is_declared` / `test_the_document_carries_no_host_name_or_timestamp` |
| K6 | 后端不可用 → `SOURCE_UNAVAILABLE`，退出码不变 | `test_unavailable_backend_keeps_exit_code_zero`、`test_macos_backend_is_always_unavailable_and_flagged`；`test_hygiene.py::test_source_unavailable_becomes_a_finding_without_changing_anything` |
| K7 | 不设"未实现"退出码；未落地能力 → 可见记录或退出 2 | `test_cli.py::test_unimplemented_module_exits_two_without_claiming_success`（现指 `report`）+ `test_hygiene_answers_instead_of_claiming_unimplemented` |

数值口径的唯一权威是 `data/README.md` §五（现为 1–14 条）。
`src/certledger/data/default-policy.json` 是它的机器副本。
**`fixtures/expected.json::policy_numbers_used` 是第三份副本**——改那 4 个数必须同轮重跑
`bash fixtures/gen.sh`。

---

## 五、本机环境坑（只写实测过的）

- **Windows + Git Bash**：`py -3.12`（3.12.10）与 `py -3.8`（3.8.8）。项目下界 3.10，
  3.8 通道**跑不了本项目**。
- **`py -X utf8` 是本机习惯**：不加它时中文控制台是 cp936。CI 里已设 `PYTHONUTF8=1`。
- **Windows 上 `os.chmod` 只切只读位**：`os.stat().st_mode` 恒报 `0o666`（实测
  `fixtures/out/healthy/healthy.key`）。所以 `posix_mode` 在 Windows 上**必须记 `null`**，
  否则每个私钥都会被判成"权限过宽"。`test_collectors.py` 里那条 chmod 测试也因此 skip。
- **Git Bash 的 `/tmp` 与 Windows Python 路径不通**：`/tmp/x` 传给 `py` 会找不到。
  用 `cygpath -w /tmp/x` 转换。
- **`cd /tmp` 再跑 `py` 会被 `/tmp/*.py` 遮蔽 stdlib**。
- **`certutil` 的输出编码是 `mbcs`（本机 cp936）**。因此不解析控制台文本，改用 `-split` 落 DER。
- **`certutil -split -store <name>` 把文件写到当前工作目录**。正确用法：
  `subprocess.run(..., cwd=<临时目录>)` 然后 glob `*.crt`。
- **Windows 上 `Path.symlink_to` 需要管理员权限**；`mklink /J` 建目录联接不需要。
- **Python 把 Windows 目录联接报成普通目录**：只能靠 `st_reparse_tag`（`0xA0000003`）分辨。
- **`cryptography` 对非正序列号证书发 `CryptographyDeprecationWarning`**。那是文件的属性。
  跑手工脚本时用 `-W ignore` 或 `warnings.simplefilter`。
- **`cryptography` 50.0.2 的 `public_key()` 会对 md5WithRSA 证书抛 `ValueError`**
  （实测 `CN=Root Agency`）。任何"遍历所有证书并解公钥"的新代码都必须容忍它
  ——`inventory._public_key()` 已做。
- **`ObjectIdentifier` 没有公开的 `.name` 属性**；短名只在 `_name` 上（已实测：
  `1.2.840.113549.1.1.5` → `sha1WithRSAEncryption`，`1.2.840.10045.4.3.2` →
  `ecdsa-with-SHA256`）。升级 `cryptography` 时复测 `inventory._extended_key_usage()`
  与 `hygiene._signature_name()` 两处。
- **OpenSSL 3.5.6（本机）**：`req -x509` 支持 `-not_before` / `-not_after` / `-set_serial`。
- **JDK 26 的 `keytool`** 在 `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`，**不在 PATH 上**。
- **本机没有 `python` 别名**，用 `py -3.12`。
- **`fixtures/out/` 不入仓**：改 `gen.py` 后要跑 `bash fixtures/gen.sh` 才有产物；
  测试在无产物时整体 skip（`_HAVE_ARTIFACTS`），**不是 fail**——注意别把 skip 当绿。

---

## 六、DoD 逐项 checklist（M4，已验）

- [x] 九类 finding 全部可产出，每条带 `rule_source`
      → `hygiene.evaluate`；`test_hygiene.py::test_every_finding_carries_a_citation`
- [x] 无出处判据被测试拒绝
      → `test_strength.py::test_the_engine_refuses_an_uncited_rule`（手工构造 `Policy`）
      + `test_policy.py::test_uncited_threshold_is_rejected`
      **变异**：把 `rule_source` 改成 `""` → 3 个用例变红（实测）
- [x] `--as-of` 缺失 → 2；策略缺失/非法 → 2
      → `test_cli.py::test_missing_as_of_is_usage_error` + `test_hygiene.py::test_as_of_is_mandatory`
      / `test_policy_is_mandatory`
- [x] `EXPIRY_CLIFF` 按去重指纹计数
      → `test_cliff_counts_distinct_fingerprints_not_records`（合成台账，两单位唯一分歧处）
      + `test_cliff_counts_deduplicated_copies_as_one`（真实管线）
      + `test_cliff_fires_exactly_at_the_policy_minimum`
      **变异**：改成按记录计数 → 该用例变红（实测）
- [x] 策略改阈值/级别 → 结论翻转
      → `test_strength.py` 5 组（min_bits 升/降、`level` 升级、warn_days、禁止摘要表）
      **变异**：`level` 写死 `"WARN"` → 4 个用例变红（实测）
- [x] `POLICY_NIST_2031` 文案不含"当前已弱"
      → `test_nist_2031_text_says_2031_not_weak_today`（含 5 个禁用词）+ 默认关闭用例
- [x] 失败路径成 finding（`PARSE_FAILED` / `SOURCE_UNAVAILABLE` / `PARSE_UNSUPPORTED` / `SKIP_*`）
      → `test_parse_failed_becomes_a_finding` 等三例
      **变异**：去掉诊断转换 → 7 个用例变红（实测）
- [x] `level: off` 不产 finding 但计入 `summary.suppressed`
      → `test_level_off_removes_findings_but_counts_them`
      **变异**：忽略 `off` → 该用例变红（实测）
- [x] 边界：`not_after == as_of` 仍有效
      → `test_not_after_equal_to_as_of_is_still_valid`
      **变异**：改成 `<=` → 该用例变红（实测）
- [x] 未知 ≠ 弱（三条）
      → `test_a_certificate_without_a_decodable_key_is_not_weak` /
      `test_an_unparseable_date_is_not_evidence_of_expiry` / `test_a_locked_key_is_not_an_orphan`
      **变异**：去掉加锁私钥守卫 / 把空算法当 rsa → 各自变红（实测）
- [x] `PERMISSION_TOO_OPEN` 走策略掩码；无 mode 不判定
      → `test_permission_rule_compares_against_the_policy_mask` /
      `test_a_key_without_a_recorded_mode_is_not_judged`
      **变异**：掩码取反 → 该用例变红（实测）
- [x] 容器三条规则在合成 `containers[]` 上可产出
      → `test_truststore_with_a_private_key_fires` / `test_an_empty_password_container_fires` /
      `test_an_unreadable_container_is_reported_not_guessed` /
      `test_two_alias_in_one_container_is_one_duplicate_not_two_sources`
- [x] 17 个真值用例对账：**code + severity + count** 13 条完整；**`absent` 与 `rule_source` 覆盖全部 17 条**；
      余 4 条的差集被一条测试**逐名钉住**
      → `test_case_matches_the_truth_file[13 例]` / `test_absent_codes_really_do_not_fire[17 例]` /
      `test_the_citation_shape_is_one_of_the_documented_forms[17 例]` /
      `test_the_unreconciled_cases_are_exactly_the_documented_ones`
- [x] `--inventory` 真读台账，且与现场扫描同结论
      → `test_a_stored_ledger_gives_the_same_answer_as_a_fresh_scan`；
      文件缺失 / `kind` 不符各一条退出 2 用例
- [x] 输出确定性：两次运行字节级相同；键序固定；无主机名/时间戳
      → `test_two_runs_are_byte_identical` / `test_key_order_is_declared` /
      `test_the_document_carries_no_host_name_or_timestamp`
- [x] 两个空壳仍抛 `NotImplementedError`；CLI 的 K7 断言改指 `report`
      → `test_shells_raise_instead_of_returning_empty` +
      `test_unimplemented_module_exits_two_without_claiming_success`
- [x] `tests/test_hygiene.py`（48 例）+ `tests/test_strength.py`（14 例）+ `tests/test_asof.py`（7 例）落盘
- [x] `gen.py::write_private_key` 改成 0600（`perm` 用例其后显式 0644）
- [x] 四个状态副本同轮翻 M4 为 ✅；`tools/check-sprint-layout.py` 全绿
- [x] `tools/selftest-gates.py` 仍全红（10 + 4）
- [x] `plan/06` 缺口表 G5 关闭；`plan/05` §五 增一行写明 4 条未对账用例的平台/结构前提
- [x] 隐私：`git status --porcelain --untracked-files=all` 无证书类文件
- [x] `plan/HANDOFF-M5.md` 七节齐并已落盘

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
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest tests/test_hygiene.py tests/test_strength.py -q

# 样本（M1 产出；后续拿来当输入）
bash fixtures/gen.sh --list
bash fixtures/gen.sh
bash fixtures/gen.sh --check
bash fixtures/gen.sh --determinism
bash fixtures/gen.sh --only healthy --out <dir>

# 采集 / 台账 / 卫生规则冒烟
PYTHONPATH=src py -3.12 -X utf8 -m certledger collect   --roots fixtures/out --source none
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --roots fixtures/out --source none
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --source windows          # 真读 Windows 存储
PYTHONPATH=src py -3.12 -X utf8 -m certledger hygiene   --roots fixtures/out --as-of 1900000000 --source none

# 卫生规则：先落台账，再从台账判定（同结论；不重扫盘）
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --roots fixtures/out --source none --json /tmp/ledger.json
PYTHONPATH=src py -3.12 -X utf8 -m certledger hygiene --inventory /tmp/ledger.json --as-of 1900000000 --source none

# 安装 + CLI 冒烟
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/certledger.exe hygiene --roots fixtures/out --as-of 1900000000 --source none

# 打包
./.venv/Scripts/python.exe -m build --sdist --wheel --outdir <空目录>
```

> Windows 上 `git status --porcelain` 里出现 `__pycache__` 时，先 `PYTHONDONTWRITEBYTECODE=1` 重跑；
> CI 的 `no-residue` job 会在干净树上断言行数不变。