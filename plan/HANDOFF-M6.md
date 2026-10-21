# HANDOFF-M6 · 发布（tag + GitHub Release + 留档）

> 用法：以 `plan/HANDOFF-M6.md` 为入口续接本棒。**第一动作 = 跑两条门**（见 §七）。
> 本文件写于 2026-10-21（M5 收尾）。库内一律相对路径。

---

## 一、当前进度 + 证据

M0、M1、M2、M3、M4、M5 已完成并本地验证。**M6 未开始**（发布是最后一棒）。

| 已落地 | 证据（可复跑） |
|---|---|
| 两道门全绿 | `py -3.12 -X utf8 tools/check-sprint-layout.py` → 10 项 PASS（状态副本 4 / 交接单 5 / 缺口 8 行 / 台账 31 行）；`tools/check-desensitized.py` → 0 命中（78 文件） |
| 门自身可跑红 | `py -3.12 -X utf8 tools/selftest-gates.py` → 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 |
| 测试 | `PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q` → **358 passed / 1 skipped**（359 项收集） |
| 样本可复现 | `bash fixtures/gen.sh --check` → 17 用例 / 字节级 31 项 / alias 表 3 项 / 容器字节跳过 3 项，`fixtures/expected.json` **字节未变** |
| **报告双格式** | `render/`（`__init__` 装配 + `markdown_out` + `redact`）；`tests/test_determinism.py`（10 例，**含跨进程确定性**） |
| **退出码** | `render._exit_code`（1 号码唯一产地）；`tests/test_exit_codes.py`（10 例） |
| **baseline 三类 diff** | `render._diff_against`；`tests/test_baseline.py`（10 例） |
| **容器视图** | `containers.py`（PKCS#12 走 `cryptography`；JKS/JCEKS 走 `keytool -list -v`）；`tests/test_containers.py`（15 例） |
| **容器内容进台账** | `inventory._absorb_container`；`containers[]` 段；`sources[].kind="container"` 带 `container_format`/`alias`/`entry_type` |
| **编排** | `pipeline.report`：建台账 → `hygiene.evaluate(ledger=…)` → `render.render(findings_document=…)`；一次 `report` 只读机器一次 |
| 17 用例对账 | **16 条逐条对上真值（code + severity）**；唯一余项 `perm` 是 POSIX-only（本机 Windows 上 `posix_mode` 记 `null`，规则按设计静默）——见 §二 第 3 条 |
| 隐私红线 | `git status --porcelain --untracked-files=all` 无任何 `*.pem/*.key/*.p12/*.pfx/*.jks/*.jceks/*.der/*.crt` |
| 装好的 CLI 真跑 | `.venv` 里 `certledger containers fixtures/out/truststore-with-key/mixed.p12 --show-aliases` → 2 条 alias 表；`certledger report … --fail-on none` 三容器用例 findings = `DUPLICATE_CERT`1 + `ORPHAN_CERT`2 + `CONTAINER_TRUSTSTORE_WITH_KEY`1 + `CONTAINER_EMPTY_PASSWORD`1 |

**未发生的事**：
- **CI 从未实跑**（无远端）。M0–M5 的 CI 项一律记为"本地等价校验，未接远端，CI 待首推验证"。
- **本机从未跑过 Linux 真实路径与 macOS 后端**（§二 第 4 条）。
- **BKS / UBER 等非 JDK 格式从未验证**（§二 第 5 条）。

---

## 二、当前事实·状态不变量（下一棒动手前必须知道）

1. **版本号只有一处**：`src/certledger/__init__.py::__version__`（现为 `0.1.0.dev0`）。
   `pyproject.toml` 用 `dynamic = ["version"]`，**不要**加 `version = "…"`。
   M6 发布时若要把版本从 `0.1.0.dev0` 定到 `0.1.0`，改这一处即可；
   `tests/test_architecture.py::test_installed_metadata_matches_module` 会核对装出来的元数据。

2. **`SCHEMA_VERSION` 仍是 `1`**（`model.py`）。M5 加的是**段**（台账 `containers[]`）与**新文档类型**
   （`kind: "report"` / `kind: "containers"`），不是改既有形状，所以不抬版本。**M6 不要再动它**。

3. **17 条真值用例：16 条端到端对上，余 `perm` 一条**。
   `perm` 是 `platform: "posix"` 用例：Windows 上 `posix_mode` 记 `null`，`PERMISSION_TOO_OPEN`
   按设计静默。`tests/test_hygiene.py::test_the_only_unreconciled_case_is_the_posix_only_one`
   把差集钉成**恰好 `["perm"]`**——M6 若在 POSIX 机器上跑 `bash fixtures/gen.sh` 后该测试会红，
   那是"平台前提满足了"的提醒，不是故障（届时把该测试改成断言空集）。
   **容器三条能对上有一个前提**：容器口令必须在环境变量里（夹具是公开的 `changeit`）。
   口令是**输入的一部分**，不是缺口。

4. **后端"真跑"到什么程度（照实引用，不要拔高）**：
   - **windows**：真跑。`certutil -split -store` 汇总 Root=18、AuthRoot=58、CA=5、My=0，共 81 张；
     台账层 81 张来源 → **77 条记录**。
   - **linux**：读取与 PEM 拆分路径用真实 multi-block bundle 实测（注入路径）；
     **`/etc/ssl/certs/ca-certificates.crt` 这个真实位置在本机不存在，从未被读过**。
   - **macOS**：从未执行。代码恒返回 `SOURCE_UNAVAILABLE` + `unverified_backend: true`（D4）；
     `tests/test_exit_codes.py::test_an_unavailable_backend_does_not_change_the_exit_code`
     钉住"降级不改退出码"。

5. **容器这条路"真跑"到什么程度**：
   - **PKCS#12**：真跑。三个夹具 `.p12` 本机可读，条目逐条对上真值（含 `same_fingerprint_aliases`）。
   - **JKS / JCEKS**：真跑。本机 JDK 26 用 `keytool -genkeypair -storetype JKS|JCEKS` **真建库**再
     真读（`tests/test_containers.py` 两个参数化用例）；`chain_length` 取 `keytool` 报的值。
     **没有 JDK 的机器上这条测试 skip**，而"无 JDK 降级"另有专门用例（`KEYTOOL_ENV` 指向不存在路径）。
   - **BKS / UBER**：从未验证，会落成 `CONTAINER_UNREADABLE`。
   - **本机 `keytool` 不在 `PATH` 上**：位于 `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`，
     靠 `find_keytool()` 的探测顺序找到（见第 8 条）。

6. **容器口令只有一个来源：环境变量**（**这是 M5 新引入的接口事实，M6 引用时不要写错**）：
   - 变量名由 `--password-env <VAR>` 指定，**缺省 `CERTLEDGER_CONTAINER_PASSWORD`**；
     `inventory` / `hygiene` / `report` 没有这个参数，它们读**同名变量的缺省值**。
   - **除用户给的口令外只额外试空口令**（`b""` 与 `None` 两种写法：`keytool`/OpenSSL 用前者，
     `cryptography` 自造的无加密包用后者）。**代码里没有产品默认口令、没有口令字典、没有 `changeit`。**
   - 口令**不进 `argv`**（`keytool` 用 `-storepass:env`，父进程只给出变量名）、**不落盘**、
     **不进报告**（报告里只有 `password ∈ {set, empty, unknown}`）。
   - 测试侧的公开夹具口令是 `changeit`，写在 `tests/conftest.py::FIXTURE_CONTAINER_PASSWORD`，
     由 `container_password` 夹具塞进环境变量。

7. **`find_keytool()` 的探测顺序**：`CERTLEDGER_KEYTOOL`（显式路径，**文件不存在则直接返回 None**）
   → `PATH` → `JAVA_HOME` → JDK 安装根（Windows 取 `%ProgramFiles%/Java/*/bin`，
   POSIX 取 `/usr/lib/jvm/*/bin`）。**`LC_ALL=C` 不会切换 JVM 语言**（本机实测仍是中文），
   因此 `keytool` 输出**按标签名**解析，英文与中文标签都认；并尽量用
   `-J-Duser.language=en -J-Duser.country=US -J-Dfile.encoding=UTF-8` 要英文。

8. **报告文档的形状（M6 若要拿它做发布示例，照抄这一份键序）**：
   `{schema_version, kind:"report", tool_version, as_of, as_of_utc, policy_version, policy_sha256,
   fail_on, exit_code, summary, certificates[], findings[], expiries[], diff?}`；
   `summary` 多出 `certificates` / `expiries_total` / `expiries_shown` 三个计数；
   `certificates[]` = `{fingerprint_sha256, spki_sha256, subject, subject_der_sha256}`，
   **是 baseline 的输入**（轮换判定要 SPKI，而 SPKI 不在任何 finding 里）。
   键序由 `render._build_document` 显式声明，**不要加 `sort_keys`**（K5）。

9. **baseline 的轮换判定键是 `(subject_der_sha256, spki_sha256)`**：
   同 name（DER 哈希）+ 同公钥 + 不同指纹 → `rotated`；换了公钥 → `removed` + `added`，
   **不叫轮换**（`tests/test_baseline.py::test_a_new_key_is_removed_plus_added_not_rotated` 钉住）。
   基线文件的 `kind` 必须是 `"report"`，否则退出 2。

10. **`--top N` 只裁 `expiries[]` 展示表**：`findings` 全集、`certificates`、`exit_code` 都不动；
    裁了多少写在 `summary.expiries_total` / `expiries_shown` 里。
    `tests/test_determinism.py::test_top_trims_the_expiry_table_only` 同时断两侧。

11. **打码是"按路径形态"判断**（`render/redact.py`）：盘符 `X:\` / UNC `\\host` / 前导 `/`
    → 换成 `<redacted>/<basename>`；`store:Root` 这类**不是路径**的字符串不动。
    **basename 是故意留的**：诊断类 finding 里"哪个文件"是它唯一可执行的部分。
    打码施加在**成稿文档**上、**两个格式同一遍**（`--no-redact` 关掉）。

12. **两个格式同源、零外链**：`render_markdown` 拿的是同一份成稿文档的字典，不排序/不计数/不截断；
    正文出现 `http://` / `https://` 会**抛 `ValueError`**（policy 里的出处都是文本，无 URL）。

13. **退出码**：`0` 无 finding 达 `--fail-on`；`1` 有（**只在 `render._exit_code` 产生**）；
    `2` 输入/策略/参数错（`CliError` 唯一出口，`cli.main` 归一）。
    `--fail-on none` 关的是门禁、不是报告（findings 照常输出）。
    `--fail-on WARN` 语义 = "ERROR 或 WARN 都算达到门槛"。
    **`SOURCE_UNAVAILABLE` 不改退出码**（K6/D11）。

14. **`hygiene.evaluate` 新增 `ledger=` 关键字**（内存台账），使 `report` 一次只读机器一次；
    同时给 `ledger` 与 `--inventory`/`--roots`/`--files` 会抛"台账来源冲突"。
    现存所有调用（`roots=/files=/inventory_path=`）**签名不变**，M4 的测试一条没动语义。

15. **`inventory` 的顶层键序变了**：`[schema_version, kind, certs, keys, containers, diagnostics, summary]`
    （`containers` 插在 `keys` 与 `diagnostics` 之间）；
    `summary` 多出 `containers` / `containers_unreadable` 两个计数。
    **`containers` 与 `containers_unreadable` 是不同单位**（"几个盒子" vs "几个没打开"）。

16. **容器条目的私钥记 `encrypted: true`**：它在容器里受容器口令保护，不是明文散落的文件；
    "这层保护够不够"由 `CONTAINER_EMPTY_PASSWORD` 回答。所以**容器来源的私钥不产
    `PRIVATE_KEY_UNENCRYPTED`**（真值复算也是这么算的：该码只对 `kind: "key"` 的 artifact 计）。
    JKS 的 `PrivateKeyEntry` 拿不到私钥本体（要 key 口令），故 SPKI 从**该条目的证书**取——
    "这个 store 里有一把对应这张证书的私钥"是 store 自己的声明，不是猜。

17. **`PARSE_UNSUPPORTED` (`stage=container`) 现在只对 PKCS#7 这类真正不读的格式保留**；
    读不开的容器改由 `containers[].unreadable` → `CONTAINER_UNREADABLE` 表达（走 `emit_failure`，
    级别取 `diagnostics.codes`）。`tests/test_inventory.py::test_pkcs7_is_still_reported_as_unsupported` 钉住。

18. **策略文件 `policy_version` 仍是 `1.1.0`，但 `policy_sha256` 变了**：M5 把两条容器出处的
    `data/README.md 5.9`（那条其实是"排序"）改成 **`5.15`**（新增的"容器信号"口径）。
    `policy_numbers_used` 的 4 个数**没变**，所以**不需要**重跑 `bash fixtures/gen.sh`
    （已实测 `--check` 通过、`expected.json` 字节未变）。

19. **`level: off` / 失败路径 / 未知≠弱 / 边界含等号**等 M4 结论**全部未变**，见 `plan/HANDOFF-M5.md` §二。

20. **K7 的"临时码 3"已在 M5 退役**（它从未进过代码）：`tests/test_architecture.py::
    test_no_module_still_refuses_to_answer` 断全仓再无 `raise NotImplementedError`；
    `tests/test_cli.py::test_no_command_claims_an_unimplemented_capability` 逐子命令断不答"尚未落地"。
    `cli.main` 里的 `NotImplementedError` 分支**故意保留**：它是将来往参数面加阶段时的安全网，
    删掉它等于让一个未实现的分支有机会把 traceback 递给用户。

21. **`containers` 子命令现在也接受子命令后的 `--json`**（`plan/03` §⑤ 的文档形式）；
    全局位置的 `--json` 仍可用（`SUPPRESS` 归一在 `cli.main`）。

22. **`containers` 子命令没有 `--source` / `--roots` / `--files`**：它只吃位置参数 `PATH...`
    （外加 `--show-aliases` / `--password-env` / `--json` / `--policy`）。

---

## 三、下一棒待办（M6 发布）

按 `plan/05` §三 发布口径与 `plan/06` G3/G4/G7 执行，顺序建议：

1. **发布前最后一次本地全绿**（顺序不能倒）：
   `bash fixtures/gen.sh && bash fixtures/gen.sh --check && bash fixtures/gen.sh --determinism`，
   然后两条门 + `tools/selftest-gates.py` + `pytest -q`。
   **`--determinism` 会写 `fixtures/out/`（不入仓），跑完确认 `expected.json` 字节未变。**

2. **脱敏四步**（`plan/05` §三 / `plan/06` 五）：`tools/check-desensitized.py` 必须 0 命中；
   检查 `plan/`、`README.md`、`data/README.md` 里没有主机名 / 用户名 / 内网路径 / 代理。
   注意 `--no-redact` 跑出来的报告**含绝对路径**，**不要留到仓库里**（M5 已经踩过一次：
   `.tmpm5/r5.json` 让脱敏门报 1 它命中——门是对的）。

3. **干净环境验证**：中立目录 + 新 venv + **逐条敲 README 的 Usage 命令**
   （含 `certledger containers <path> --show-aliases`、`report --json/--markdown`、
   `report --baseline`，以及 `certledger --version` / `--help`）。
   容器有口令的用例要设 `CERTLEDGER_CONTAINER_PASSWORD`；空口令用例不需要。

4. **打包**：`python -m build --sdist --wheel --outdir <空目录>`；
   解包树里跑一次 `bash fixtures/gen.sh --check`（`MANIFEST.in` 已含 `fixtures/ *.sh *.py *.md`
   ——确认 M5 新增的 `src/certledger/render/markdown_out.py` / `redact.py`、`tests/test_*.py`
   都在包里；**sdist 走 `MANIFEST.in` 白名单，新增文件要顺手核对**）。

5. **建公开仓库 `yuluo554/10-21-certledger`**，首推，**回填真实 CI run id**（G3 的关闭条件）。

6. **tag `v0.1.0`** + **GitHub Release**（A 方案：附手工源码包）+ sha256 登记在 **Release 正文**；
   写 `plan/RELEASE-M6.md`（两栏 + "覆盖对账"小节 + ≥3 条三态行：实现 / 不适用+理由 / 待首推）。
   **tag 树内不留字面值**：tag/OID/包哈希一律写"见 `git rev-parse v0.1.0`"。

7. **关闭 G3 / G4 / G7**；G4（macOS）若无设备就保持 `SOURCE_UNAVAILABLE` 并写进 README 已知限制。
   **G3 / G4 / G7 的状态在 M6 之前不要动。**

8. **回写四个状态副本**（`plan/00` 里程碑表 + `plan/05` 状态表 + `README.md` 状态表 + `plan/00` 台账），
   翻 M6 为 ✅。`plan/00` 台账的"开源空白（软论据）"等 ⬜ 行若仍无证据，**不要**改成 ✅。

9. **本棒收尾不写 HANDOFF-M7**（没有下一棒）：改为写 `plan/RELEASE-M6.md` 的"tag 后追加"栏。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| 编号 | 约定 | 断言位置 |
|---|---|---|
| K1 | 指纹只对 DER 原始字节做 SHA-256 | `parsing/fingerprint.py::der_sha256`（唯一入口）；`test_only_parsing_computes_hashes`（`policy/loader.py` 是白名单例外）；`containers.entry_fingerprint` / `entry_spki` 也走同一入口 |
| K2 | `--as-of` 必填，不许回退到 `now()` | `test_architecture.py::test_single_clock_source`、`tests/test_timebase.py`、`test_hygiene.py::test_as_of_is_mandatory`、`tests/test_exit_codes.py::test_missing_as_of_is_exit_two` |
| K3 | 阈值/级别只从策略文件读；缺失/非法 → 退出 2 | `tests/test_policy.py`；`tests/test_exit_codes.py::test_unreadable_policy_is_exit_two`；`render._threshold` 读 `report.default_fail_on`（无代码字面量） |
| K4 | 配对键 = `spki_sha256`，不用文件名 / subject / SKI | `test_certificate_and_key_pair_on_spki` / `test_same_cn_with_different_keys_is_not_paired` / `test_orphan_case_pairs_neither_side`；`inventory._pair_certs`；**容器私钥与容器的条目证书也按 SPKI 接上**（`test_a_container_private_key_pairs_with_its_certificate`） |
| K5 | 报告无时间戳/耗时/主机名/用户名；键序=声明序 | `tests/test_model.py`；`test_inventory.py::test_key_order_is_declared_not_alphabetical`；`test_determinism.py::test_key_order_is_declared_in_the_report` + `test_neither_format_carries_a_timestamp_host_or_user` |
| K6 | 后端不可用 → `SOURCE_UNAVAILABLE`，退出码不变 | `test_unavailable_backend_keeps_exit_code_zero`、`test_macos_backend_is_always_unavailable_and_flagged`、`test_exit_codes.py::test_an_unavailable_backend_does_not_change_the_exit_code`；**容器无 JDK 同理**（`test_containers.py::test_no_jdk_degrades_to_unreadable_and_still_exits_zero`） |
| K7 | 不设"未实现"退出码；**已在 M5 退役** | `test_cli.py::test_no_command_claims_an_unimplemented_capability` + `test_architecture.py::test_no_module_still_refuses_to_answer`；`plan/06` G1 已关闭 |

数值口径的唯一权威是 `data/README.md` §五（现为 1–**15** 条）。
`src/certledger/data/default-policy.json` 是它的机器副本。
**`fixtures/expected.json::policy_numbers_used` 是第三份副本**——改那 4 个数必须同轮重跑
`bash fixtures/gen.sh`。

---

## 五、本机环境坑（只写实测过的）

- **Windows + Git Bash**：`py -3.12`（3.12.10）与 `py -3.8`（3.8.8）。项目下界 3.10，3.8 通道跑不了。
- **`py -X utf8` 是本机习惯**：不加它时中文控制台是 cp936。CI 里已设 `PYTHONUTF8=1`。
- **Git Bash 的 `/tmp` 与 Windows Python 路径不通，而且 MSYS 会改写 `argv` 里的 `/tmp/x`**：
  传给 `--json` 的 `/tmp/x.json` 会被 MSYS 换成会话临时目录下的绝对路径，而 Python 源码里写的
  字符串 `/tmp/x.json` 又落在当前盘根下——**同一个字符串，两个文件**（实测：`--json` 报出
  "wrote" 的那条路，与事后 `open()` 读的不是同一处）。做手工验证时用 **仓库内相对目录**
  （例如 `.tmpm5/`）+ 用完删掉。
- **`--no-redact` 的报告含绝对路径**：留在仓库里会被脱敏门抓住（本机实测：`.tmpm5/r5.json` 报 1 命中）。
- **`fixtures/out/` 不入仓**：改 `gen.py` 后要跑 `bash fixtures/gen.sh` 才有产物；
  测试在无产物时整体 skip（**不是 fail**）——注意别把 skip 当绿。
  **M5 新增的 `test_determinism.py` / `test_exit_codes.py` / `test_baseline.py` /
  `test_containers.py` 刻意不依赖 `fixtures/out`**（现场造证书/容器），所以 CI（不生成样本）
  也能跑到它们——判据在 CI 里 skip 等于判据不在。
- **`keytool` 不在 `PATH` 上**（实测 `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`）；
  `find_keytool()` 负责找，`CERTLEDGER_KEYTOOL` 可显式指定。**指向不存在的文件 → 返回 None**（不抛）。
- **`keytool` 输出是 JVM 语言，`LC_ALL=C` 不管用**：按标签名解析（英/中双认）。
  JCEKS/JKS 在 JDK 26 上会往 **stderr** 打"算法已过时"的迁移建议——**退出码 0，不是错误**。
- **`keytool -storepass:env <VAR>` / `-keypass:env <VAR>` 在 JDK 26 上可用**（建库与读库都实测过）。
  口令因此不进 `argv`。老 JDK 若不支持，退化为 `CONTAINER_UNREADABLE`（不静默）。
- **`cryptography` 50.0.2**：
  - `load_pkcs12(raw, b"")` 对 **OpenSSL 写的空口令包**有效，对 **`cryptography` 的
    `NoEncryption` 包**要传 `None`——两种写法都要试（`containers._password_candidates`）。
  - 非正序列号证书发 `CryptographyDeprecationWarning`（文件的属性，手工脚本用 `-W ignore`）。
  - `public_key()` 对 md5WithRSA 证书抛 `ValueError`（实测 `CN=Root Agency`）；
    `inventory._public_key()` 已容忍。
  - `ObjectIdentifier` 没有公开 `.name`（只有 `_name`）；升级时要复测
    `inventory._extended_key_usage()` 与 `hygiene._signature_name()`。
- **`os.chmod` 在 Windows 只切只读位**：`posix_mode` 在 Windows 上必须记 `null`
  （否则每个私钥都被判"权限过宽"）；`test_collectors.py` 那条 chmod 测试因此 skip。
- **`certutil -split -store <name>` 把文件写到当前工作目录**：要 `cwd=<临时目录>` 再 glob。
  `certutil` 输出编码是 **mbcs（cp936）**，所以不解析控制台文本。
- **OpenSSL 3.5.6（本机）**：`req -x509` 支持 `-not_before` / `-not_after` / `-set_serial`。
- **本机没有 `python` 别名**，用 `py -3.12`。

---

## 六、DoD 逐项 checklist（M5，已验）

- [x] 报告双格式（JSON + Markdown），排序稳定，两次运行字节级一致
      → `test_determinism.py::test_two_runs_are_byte_identical_in_both_formats`（两格式各比 sha256）
      + `test_two_separate_processes_produce_the_same_bytes`（两次独立进程，跨进程哈希种子不同）
      **变异（实测）**：① Markdown 头加一行运行耗时 → 前者变红；
      ② `findings` 按 `set` 迭代序重排 → **只有后者**变红（同进程两次仍相同）
- [x] 退出码 0/1/2 三条用例 + `--fail-on none` 恒 0
      → `test_exit_codes.py`（0/1/2 + none + 降门槛翻转 + 不可写输出转 2 + 后端不可用不改码）
- [x] `--baseline` 三类 diff 各一用例 + 换密钥不算轮换
      → `test_baseline.py`（added / removed / rotated / new-key-is-not-a-rotation / 空 diff /
        确定性 / 真读盘上的上一份报告 / 坏基线转 2）
- [x] `--top` 只影响展示：`findings` 全集与退出码不变（断言）
      → `test_determinism.py::test_top_trims_the_expiry_table_only`
      **变异**：把 `--top` 施加到 `findings` 上 → 该用例变红（实测）
- [x] 容器 alias 表（P12 真跑；JKS/JCEKS 走 keytool 真跑；无 JDK → `CONTAINER_UNREADABLE` 且退出 0）
      → `test_containers.py`（15 例；JKS/JCEKS 两例带 `needs_keytool` 的 skip 门）
- [x] 报告不含主机名/用户名/时间戳；绝对路径默认打码（`--no-redact` 关掉）
      → `test_neither_format_carries_a_timestamp_host_or_user` /
      `test_absolute_paths_are_masked_in_both_formats`（保留 basename）
      **变异**：Markdown 头加运行耗时 → `test_two_runs_are_byte_identical_in_both_formats` 变红（实测）
- [x] `render/` 零判定（AST 守门）；Markdown 零外链
      → `test_architecture.py::test_render_layer_does_not_judge` /
      `test_markdown_carries_no_external_link` + `render_markdown` 的 `ValueError` 兜底
- [x] 三个容器用例端到端对上真值；`perm` 的差集被一条测试钉成**恰好那一条**
      → `test_hygiene.py::test_case_matches_the_truth_file[16 例]` /
      `test_the_only_unreconciled_case_is_the_posix_only_one`
- [x] 容器内容归并进台账：`sources[].kind="container"` 带 format/alias/entry_type；
      容器内条目按指纹合并（多别名 = 一条记录两条来源）
      → `test_inventory.py::test_container_contents_are_opened_and_folded_in` /
      `test_a_container_private_key_pairs_with_its_certificate` /
      `test_an_unreadable_container_keeps_its_reason` /
      `test_pkcs7_is_still_reported_as_unsupported`
- [x] 口令不进 `argv` / 不落盘 / 不进报告
      → `test_containers.py::test_the_password_never_reaches_a_child_process_argv`（抓真实 argv）
      + `test_the_password_is_not_in_the_document`
      **变异**：把口令改成进 `argv` → 前一条变红（实测）
- [x] 空壳退役：全仓再无 `raise NotImplementedError`；K7 断言换成正向
      → `test_architecture.py::test_no_module_still_refuses_to_answer` +
      `test_every_stage_answers_instead_of_raising`；`test_cli.py::test_no_command_claims_an_unimplemented_capability`
- [x] `tests/test_determinism.py`（**10 例**）+ `test_exit_codes.py`（10 例）+ `test_baseline.py`（10 例）
      + `test_containers.py`（15 例）落盘
- [x] 四个状态副本同轮翻 M5 为 ✅；两道门全绿；`tools/selftest-gates.py` 仍全红（10 + 4）
- [x] `plan/06` G1 关闭；`plan/05` §五 的"三个容器用例"关闭、"`perm`"改写成平台前提
- [x] `plan/02` §五 的"零临时码"设计与 G1 的关闭口径一致（无幽灵语义）
- [x] 隐私：`git status --porcelain --untracked-files=all` 无证书类文件
- [x] `plan/HANDOFF-M6.md` 七节齐并已落盘

---

## 七、关键命令速查

```bash
# 门（任何新对话的第一件事）
py -3.12 -X utf8 tools/check-sprint-layout.py
py -3.12 -X utf8 tools/check-desensitized.py
py -3.12 -X utf8 tools/selftest-gates.py

# 测试（源码树，无需安装）
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q tests/test_determinism.py tests/test_exit_codes.py
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q tests/test_baseline.py tests/test_containers.py
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q -m system -v   # 碰宿主存储的用例

# 样本
bash fixtures/gen.sh --list
bash fixtures/gen.sh            # 全量重生成（会重写 expected.json；内容必须字节不变）
bash fixtures/gen.sh --check    # 只读比对：17 用例 / 字节 31 / alias 表 3 / 容器字节跳过 3
bash fixtures/gen.sh --determinism

# 报告与容器冒烟（容器要用公开夹具口令）
export CERTLEDGER_CONTAINER_PASSWORD=changeit
PYTHONPATH=src py -3.12 -X utf8 -m certledger report --roots fixtures/out --as-of 1900000000 \
  --source none --json /dev/stdout | head -20
PYTHONPATH=src py -3.12 -X utf8 -m certledger report --roots fixtures/out --as-of 1900000000 \
  --source none --json report.json --markdown report.md --fail-on none
PYTHONPATH=src py -3.12 -X utf8 -m certledger containers \
  fixtures/out/truststore-with-key/mixed.p12 fixtures/out/multi-alias/multi-alias.p12 \
  --show-aliases --json -
PYTHONPATH=src py -3.12 -X utf8 -m certledger containers fixtures/out/empty-pass/empty-pass.p12
  # 空口令用例：不需要设环境变量

# report 的其余开关
#   --top N            只裁 expiries 展示表（findings 与退出码不变）
#   --no-redact        不打码绝对路径（生成的报告不要入库）
#   --baseline prev.json  三类 diff；prev.json 的 kind 必须是 "report"
#   --fail-on none|INFO|WARN|ERROR

# Linux 后端（本机无 /etc/ssl/certs/ca-certificates.crt，只能注入路径验证）
PYTHONPATH=src py -3.12 -X utf8 -m certledger inventory --source windows   # 真读 Windows 存储

# 安装 + CLI 冒烟
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/certledger.exe --version
./.venv/Scripts/certledger.exe report --roots fixtures/out --as-of 1900000000 --fail-on none

# 打包（M6）
./.venv/Scripts/python.exe -m build --sdist --wheel --outdir <空目录>
```

> 手工验证**不要**把中间产物留在仓库里：用仓库内相对目录（`.tmpm5/` 之类）并**用完删掉**。
> `--no-redact` 的输出一定含绝对路径，脱敏门会（正确地）抓住它。