# HANDOFF-M3 · 归一化台账（合并 + 双指纹 + SPKI 配对）

> 用法：以 `plan/HANDOFF-M3.md` 为入口续接本棒。**第一动作 = 跑两条门**（见 §7）。
> 本文件写于 2026-10-21（M2 收尾）。库内一律相对路径。

---

## 一、当前进度 + 证据

M0、M1、M2 已完成并本地验证。M3 **未开始**。

| 已落地 | 证据（可复跑） |
|---|---|
| 方法论装订三件 | `AGENTS.md`、`tools/check-sprint-layout.py`、`tools/check-desensitized.py`、`plan/00` 顶部装订行 |
| 两道门全绿 | `py -3.12 -X utf8 tools/check-sprint-layout.py` → 10 项 PASS；`py -3.12 -X utf8 tools/check-desensitized.py` → 0 命中（63 文件） |
| 门自身可跑红 | `py -3.12 -X utf8 tools/selftest-gates.py` → 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 |
| 计划套件 | `plan/00`–`06`、`data/README.md` |
| 样本与真值 | `fixtures/gen.sh`（+`gen.py`）+ `fixtures/expected.json`（17 用例） |
| **嗅探器** | `src/certledger/parsing/{pem,asn1,sniff,fingerprint}.py`：八类格式按**内容**命名，多块 PEM 逐块展开并带 `offset` |
| **遍历器** | `src/certledger/collectors/walker.py`：NFC + casefold 排序键；六个跳过原因码；环检测用**祖先链**而非全局集合 |
| **三平台后端** | `src/certledger/collectors/backends.py`：linux 读 PEM bundle；windows 走 `certutil -split -store`；macOS 恒 `SOURCE_UNAVAILABLE` + `unverified_backend` |
| **采集入口** | `src/certledger/collectors/__init__.py::collect` 返回 `{schema_version, kind, candidates, diagnostics, backends, summary}` |
| 测试 | `PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q` → **192 passed / 1 skipped**；`tests/test_collectors.py` 51 例、`tests/test_parsing.py` 32 例 |
| 性能（R10/G6） | 10,000 个文件 **4.06s**（2,465 文件/s）；1 GB 未识别文本树 **0.30s**（前缀窗口生效，不整文件读） |
| 打包 | `python -m build --sdist --wheel` 成功；解包树含 `parsing/{pem,asn1,sniff,fingerprint}.py` 与 `collectors/{__init__,walker,backends}.py` |
| 隐私红线 | `git status --porcelain` 无任何 `*.pem/*.key/*.p12/*.jks/*.der` |

**未发生的事**：CI 从未实跑（无远端）。M0/M1/M2 的 CI 项一律记为"本地等价校验，未接远端，CI 待首推验证"。
**本机从未跑过 Linux 真实路径与 macOS 后端**（见 §五 与 §二 第 3 条）。

---

## 二、当前事实·状态不变量（下一棒动手前必须知道）

1. **版本号只有一处**：`src/certledger/__init__.py::__version__`。`pyproject.toml` 用
   `dynamic = ["version"]`，**不要**加 `version = "…"`（`test_version_has_one_source` 会红）。
2. **状态副本有四个**：`plan/00` 里程碑表、`plan/05` 状态表、`README.md` 的「状态」表、
   `plan/00` 承诺-证据台账。**翻一个必须翻四个**。
3. **后端"真跑"到什么程度（务必照实引用，不要拔高）**：
   - **windows**：真跑。`certutil -split -store` 汇总 Root=18、AuthRoot=58、CA=5、My=0，共 81 张。
   - **linux**：**读取与 PEM 拆分路径**用真实 multi-block bundle 实测（注入路径）；
     **`/etc/ssl/certs/ca-certificates.crt` 这个真实位置在本机不存在，从未被读过**。
     在 Linux 机器上复测前，台账里它只能是 🟡。
   - **macOS**：从未执行。代码恒返回 `SOURCE_UNAVAILABLE` + `unverified_backend: true`（D4）。
4. **`certutil -store Root` 只看到 18 张，合并视图是 76 张**。差额是 `AuthRoot` 自动更新配置单元
   （58 张，与 Root 有 4 张重叠）。只读 Root 会静默漏报 58 张根证书——**这是特性，不是 bug**，
   是 D5 要防的那类"看起来成功的错误答案"。后端因此读 `Root`/`AuthRoot`/`CA` 并**分别报告计数**。
   `test_windows_root_view_includes_authroot` 钉住。
5. **JCEKS 魔数是 `CECECECE`，JKS 是 `FEEDFEED`**（JDK 26 `keytool` 建库实测）。
   `plan/03` 原文的"同魔数"是错的，已在文档里划掉并注明。`CONTAINER_FORMAT_AMBIGUOUS` 因此不产出。
6. **`0x30` 也是 ASCII 的 `'0'`**。校验和文件、git reflog、带时间戳的日志都以它开头。
   嗅探器**先判文本、再进 ASN.1**；否则普通文本会被报成 `PARSE_FAILED`，
   甚至因 ASN.1 偶然走得通而被误标成容器。`test_text_starting_with_ascii_zero_is_not_der` 钉住。
7. **`collectors.collect` 已不是空壳**。`test_shells_raise_instead_of_returning_empty` 已把它摘出去；
   正向断言在 `test_collector_returns_counts_instead_of_raising`。剩下四个空壳
   （`inventory` / `hygiene` / `containers` / `render`）**仍必须抛 `NotImplementedError`**。
8. **`--json` 两个位置都接受**：全局（`certledger --json x collect …`）与子命令后
   （`certledger collect … --json x`）。子命令侧用 `default=argparse.SUPPRESS`——
   若改成 `None`，子解析器的默认值会**覆盖**顶层已解析的值（argparse 经典陷阱）。
   `main()` 里补了 `if not hasattr(args, "json"): args.json = None` 做归一。
9. **`summary` 的五个计数是不同单位**，不可相加：
   `visited` / `scanned` / `skipped`（从未打开）/ `skip_records`（`SKIP_*` 诊断条数）/
   `deduplicated`（同目录经另一路径二次到达）。
   **恒等式只有一条：`visited == scanned + skipped`**，有测试断言。
10. **环检测用祖先链，不用全局集合**。全局集合分不清"环"和"同一目录经另一条路径到达"
    （Windows 目录联接、绑定挂载、重叠 `--roots` 都是后者）；用全局集合会丢掉真实文件并报警。
    二次到达计入 `deduplicated`，不产出诊断。
11. **`_is_link_like()` 是必需的**：Python 把 Windows 目录**联接（junction）**报成普通目录
    （`is_symlink()` 为 False，`lstat` 给 `S_IFDIR`）。只有 `st_reparse_tag` 能看出来。
    少了它，`--follow-symlinks` 关闭时联接会被跟随，走出用户指定的树。
12. **`fixtures/expected.json` 的形状**（M3 直接拿它当输入）：
    `{schema_version, kind, as_of, as_of_utc, generator, policy_numbers_used,
      cases:[{case, group, index?, platform?, purpose, as_of, as_of_utc,
              inputs:[相对路径], artifacts:[{path,kind,format,reproducible,sha256,...}],
              expect:{findings:[{code,severity,count}], absent:[code], container?}}]}`
    `artifacts[].kind ∈ {cert, key, container, broken, noise}`；
    `reproducible ∈ {bytes, alias_table}`（`alias_table` 的 `sha256` 每次不同，不可用于比对）。
13. **多块 PEM 的 `offset` 已写进真值**：`bundle` 用例 3 条 artifact，`path` 相同、`offset` 0/1/2。
    M2 的采集器已能产出这三条，且 `der_sha256` 与真值 `fingerprint_sha256` 逐条相等
    （`test_every_cert_artifact_fingerprint_is_recomputed`，17 个用例全覆盖）。
14. **`MANIFEST.in` 已含 `fixtures *.sh *.py *.md *.json`**（M1 已补 `*.py`，无需再动）。
15. **`CONTAINER_TRUSTSTORE_WITH_KEY` 的判据是 PKCS#12 bag 结构**，不是 keytool 的 `Entry type`：
    `cryptography.load_pkcs12()` 给出"cert bag 带 friendlyName 且公钥与私钥条目不同"。
    keytool 读同一文件只报 1 个 `PrivateKeyEntry`——**这是特性，不是 bug**，代码注释里要写清楚。
16. **生成器刻意不造 ECDSA 与 JKS 样本**。容器/JKS 样本归 M5；M3 若需要 ECDSA 输入，
    用 `tmp_path` 现造，不要往真值里加。

---

## 三、下一棒待办（M3）

按 `plan/03` §② 执行，顺序建议：

1. **`inventory.build()`**：把采集候选流变成台账 `{schema_version, certs[], keys[], diagnostics[]}`。
   - 证书记录字段见 `plan/03` §② 记录模型；`subject` / `issuer` 用 `display` + `der_sha256`。
   - `der_sha256` 一律走 `parsing/fingerprint.der_sha256`（**唯一入口**，K1）。
   - `spki_sha256` = `cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)`
     再 `der_sha256`。**不要**用 `cryptography` 的 `fingerprint()` 便捷方法（它自带重编码假设）。
2. **合并**：同一 `fingerprint_sha256` → 一条记录，多来源进 `sources[]`；同一 `spki_sha256` 的私钥同理。
   `sources[]` 按 `(kind, path, alias)` 稳定排序（`model.Source.sort_key` 已就绪）。
3. **配对**：证书 `spki_sha256` == 私钥 `spki_sha256` → `paired_cert_fingerprint` 回填。
   **禁止**按文件名 / CN / SKI 配对（K4）。
4. **`tests/test_inventory.py`**：
   - 同一张证书放 3 个目录 → `certs` 长度 1、`sources` 长度 3（`plan/00` 台账点名）；
   - 同 CN 不同密钥对 → 2 条记录、均不配对（`same-cn` 用例已是现成输入）；
   - 证书 + 对应私钥 → `paired_cert_fingerprint` 指向正确指纹（`pair` / `healthy` 用例）；
   - `orphan` 用例 → 双侧都不配对；
   - JSON 两次运行**字节级相同**（同 `--as-of`）；
   - `broken-der` → `PARSE_FAILED` 带 `path` + `stage`（从采集诊断透传，不得吞掉）。
5. **改 `test_architecture.py::test_shells_raise_instead_of_returning_empty`**：
   把 `inventory.build` 摘出去，换成正向断言（照 M2 对 `collect` 的做法）。
6. **CLI 接线**：`_run_inventory` 已存在，`collect` 的 `policy` 传入方式可作模板。
   注意 `inventory` 目前**没有** `--max-size`（那是 `collect` 独有）；不要顺手加。
7. 回写四个状态副本（`plan/00` 里程碑表 + 台账、`plan/05` 状态表 + DoD、`README.md` 状态表）；
   同步 `plan/06` 缺口表（当前 G1/G3/G4/G5/G7 仍开着，**不要**动它们的状态）。
8. 写 `plan/HANDOFF-M4.md`（七节）。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| 编号 | 约定 | 断言位置 |
|---|---|---|
| K1 | 指纹只对 DER 原始字节做 SHA-256 | `parsing/fingerprint.py::der_sha256`（唯一入口，M2 已落地）；`test_only_parsing_computes_hashes`（`policy/loader.py` 是白名单例外：它哈希**策略文档**，不是密钥材料）；`test_der_sha256_hashes_the_bytes_it_was_given` |
| K2 | `--as-of` 必填，不许回退到 `now()` | `test_architecture.py::test_single_clock_source`、`tests/test_timebase.py` |
| K3 | 阈值只从策略文件读；缺失/非法 → 退出 2 | `tests/test_policy.py`；`test_collect_requires_a_policy`；`test_sniff_window_comes_from_policy`；`test_max_size_comes_from_policy_when_not_given` |
| K4 | 配对键 = `spki_sha256`，不用文件名 / subject / SKI | `plan/03` §②；**M3 落地测试**；`same-cn` 用例已把"同 CN 不误配"钉住 |
| K5 | 报告无时间戳 / 主机名 / 用户名；键序固定 | `tests/test_model.py`；`test_collect_output_is_json_serialisable_and_key_ordered` |
| K6 | 后端不可用 → `SOURCE_UNAVAILABLE`，退出码不变 | `test_unavailable_backend_keeps_exit_code_zero`、`test_macos_backend_is_always_unavailable_and_flagged` |
| K7 | 不设"未实现"退出码；未落地能力 → 可见记录或退出 2 | `test_cli.py::test_unimplemented_module_exits_two_without_claiming_success`（现已改指 `inventory`） |

数值口径的唯一权威是 `data/README.md` §五。`src/certledger/data/default-policy.json` 是它的机器副本。
**`fixtures/expected.json::policy_numbers_used` 是第三份副本**——改策略必须同轮重跑
`bash fixtures/gen.sh` 重新生成真值，否则 `test_every_expectation_recomputes_from_recorded_inputs` 会红。

---

## 五、本机环境坑（只写实测过的）

- **Windows + Git Bash**：`py -3.12`（3.12.10）与 `py -3.8`（3.8.8）。项目下界 3.10，
  3.8 通道**跑不了本项目**，别用它做"兼容性验证"。
- **`py -X utf8` 是本机习惯**：不加它时中文控制台是 cp936。CI 里已设 `PYTHONUTF8=1`。
- **Git Bash 的 `/tmp` 与 Windows Python 路径不通**：`/tmp/x` 传给 `py` 会找不到。
  用 `cygpath -w /tmp/x` 转换，或直接用工作区相对路径。
- **`cd /tmp` 再跑 `py` 会被 `/tmp/*.py` 遮蔽 stdlib**。干净环境验证必须在专用空目录里跑。
- **`certutil` 的输出编码是 `mbcs`（本机 cp936）**，不是 UTF-8。按 UTF-8 解码会抛异常，
  把一条可读的错误变成 traceback。`backends._decode_console` 里的回退链就是为了这个。
  **M2 因此不解析 certutil 的控制台文本**，改用 `-split` 让它落 DER 文件——
  既避开本地化排版，也直接拿到原始 DER（K1 需要）。
- **`certutil -split -store <name>` 把文件写到当前工作目录**。给目标目录参数会
  `NTE_NOT_FOUND` 失败。正确用法：`subprocess.run(..., cwd=<临时目录>)`，
  然后 glob `*.crt`（文件名是 SHA-1 指纹，小写）。
- **Windows 上 `Path.symlink_to` 需要管理员权限**（`WinError 1314`）。
  但 **`mklink /J` 建目录联接不需要**——测试用联接走同一条代码路径，不 skip。
- **Python 把 Windows 目录联接报成普通目录**：`is_symlink()` False、`lstat` 给 `S_IFDIR`。
  判据只能靠 `st_reparse_tag`（联接 = `0xA0000003`）或 `st_file_attributes & 0x400`。
- **`cryptography` 对非正序列号证书发 `CryptographyDeprecationWarning`**。那是**文件的属性**，
  不是本工具的缺陷；`sniff._load_certificate()` 已局部静音，否则 stderr 会被噪声污染、
  破坏"报告是可稳定文档"的承诺。
- **OpenSSL 3.5.6（本机）**：`req -x509` 支持 `-not_before` / `-not_after` / `-set_serial`。
  3.0 以下没有这两个日期开关，`gen.sh` 已在首行拦截。
- **JDK 26 的 `keytool`** 在 `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`，**不在 PATH 上**。
  `keytool -J-Duser.language=en` 可强制英文输出（本机实测），比 `LC_ALL=C` 可靠。
- **本机没有 `python` 别名**，用 `py -3.12`。AGENTS.md 已写明。

---

## 六、DoD 逐项 checklist（M2，已验）

- [x] 八类格式嗅探各一例通过（PEM/DER/PKCS#7/PKCS#12/JKS/JCEKS/PKCS#8/OpenSSH 公钥）
      → `test_eight_format_classes_are_each_recognised`（按名字断言，不是数个数）
- [x] 多块 PEM 展开：`bundle` 用例 3 条记录、`offset` 0/1/2
      → `test_bundle_expands_every_block_with_offsets` + `test_pem_block_offset_matches_truth_for_every_artifact`
- [x] 遍历顺序稳定：同一树两次运行候选流**列表相等**
      → `test_two_runs_produce_an_equal_list`（不是集合相等）
- [x] 五种 `SKIP_*` 各一条用例；不可读文件不静默
      → 实为**六种**：`test_noise_is_skipped_as_binary_not_failed` /
      `test_too_large_is_skipped` / `test_unknown_text_format_is_skipped_not_dropped` /
      `test_permission_denied_is_always_a_diagnostic`（注入式，跨平台）/
      `test_symlink_is_skipped_by_default_and_followed_on_request`（Windows 用联接）/
      `test_missing_file_is_reported_not_ignored`
- [x] 三平台后端：linux 读取路径用真实 bundle 实测；windows 真跑（`certutil`）；
      macOS → `SOURCE_UNAVAILABLE` + `unverified_backend`
      → `test_linux_backend_reads_a_real_pem_bundle` / `test_windows_backend_reads_real_stores`（`@system`）/
      `test_macos_backend_is_always_unavailable_and_flagged`
      **注**：linux 的真实文件位置本机不存在，未复测（见 §二 第 3 条）
- [x] 后端缺失退出码 0（D11） → `test_unavailable_backend_keeps_exit_code_zero`
- [x] 坏 DER → `PARSE_FAILED` 带 `path` + `stage`，退出码 0 → `test_broken_der_is_parse_failed_with_stage`
- [x] **零网络**：`collectors/` 不 import 网络模块 → `test_collectors_import_no_network_modules`（模块级）
- [x] `MANIFEST.in` 含 `fixtures *.py`（M1 已落，复核通过；解包树实测含 `gen.py`）
- [x] `test_shells_raise_instead_of_returning_empty` 已按新的真实情况更新
- [x] 四个状态副本同轮翻 M2 为 ✅；`tools/check-sprint-layout.py` 全绿
- [x] `tools/selftest-gates.py` 仍全红（10 + 4）
- [x] `plan/HANDOFF-M3.md` 七节齐并已落盘

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

# 只看采集器
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest tests/test_collectors.py tests/test_parsing.py -q

# 样本（M1 产出；M2/M3 拿它当输入）
bash fixtures/gen.sh --list
bash fixtures/gen.sh
bash fixtures/gen.sh --check
bash fixtures/gen.sh --determinism
bash fixtures/gen.sh --only healthy --out <dir>

# 采集冒烟
PYTHONPATH=src py -3.12 -X utf8 -m certledger.cli collect --roots fixtures/out --source none
PYTHONPATH=src py -3.12 -X utf8 -m certledger.cli collect --roots fixtures/out            # 真读 Windows 存储
PYTHONPATH=src py -3.12 -X utf8 -m certledger.cli collect --roots . --source none --json out.json

# 安装 + CLI 冒烟
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/certledger.exe collect --roots fixtures/out --source none

# 打包
./.venv/Scripts/python.exe -m build --sdist --wheel --outdir <空目录>
```

> Windows 上 `git status --porcelain` 里出现 `__pycache__` 时，先 `PYTHONDONTWRITEBYTECODE=1` 重跑；
> CI 的 `no-residue` job 会在干净树上断言行数不变。
