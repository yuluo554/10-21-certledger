# HANDOFF-M2 · 采集器（遍历 + 嗅探 + 三平台后端 + 降级）

> 用法：以 `plan/HANDOFF-M2.md` 为入口续接本棒。**第一动作 = 跑两条门**（见 §7）。
> 本文件写于 2026-10-21（M1 收尾）。库内一律相对路径。

---

## 一、当前进度 + 证据

M0、M1 已完成并本地验证。M2 **未开始**。

| 已落地 | 证据（可复跑） |
|---|---|
| 方法论装订三件 | `AGENTS.md`、`tools/check-sprint-layout.py`、`tools/check-desensitized.py`、`plan/00` 顶部装订行 |
| 两道门全绿 | `py -3.12 -X utf8 tools/check-sprint-layout.py` → 10 项 PASS；`py -3.12 -X utf8 tools/check-desensitized.py` → 0 命中 |
| 门自身可跑红 | `py -3.12 -X utf8 tools/selftest-gates.py` → 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 |
| 计划套件 | `plan/00`–`06`、`data/README.md` |
| 可运行骨架 | `pyproject.toml`（版本 `dynamic`）、`src/certledger/`（CLI 五子命令 + 策略加载 + 时间基准 + 记录模型） |
| **样本生成器** | `fixtures/gen.sh`（探测 openssl ≥ 3.0 + 找 Python ≥ 3.10；缺失退出 2）+ `fixtures/gen.py`（生成引擎） |
| **八类必需样本** | `bash fixtures/gen.sh` → `fixtures/out/{healthy,expiring,expired,weak-key,weak-sig,multi-alias,truststore-with-key,orphan}/` |
| **九类边界补充样本** | `pair` / `same-cn` / `cliff-none` / `cliff-hit` / `empty-pass` / `perm` / `bundle` / `broken-der` / `noise` |
| **真值** | `fixtures/expected.json`（17 用例、入仓、无 `observed_*`、无 PEM 材料） |
| **确定性自检** | `bash fixtures/gen.sh --determinism` → 29 个文件两次生成字节全等 + 3 个容器按 alias 表比对通过 |
| **比对通路** | `bash fixtures/gen.sh --check` → 17 用例 / 字节级 31 项 / alias 表 3 项 / 容器字节跳过 3 项 |
| 测试 | `PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q` → **105 passed**（干净树里会多 1 个 skip：非 git 检出）；`tests/test_fixtures_truth.py` 单文件 39 例 |
| 隐私红线 | `git status --porcelain` 里没有任何 `*.pem/*.key/*.p12/*.jks/*.der`；`fixtures/out/` 被 `.gitignore` 挡 |

**未发生的事**：CI 从未实跑（无远端）。M0/M1 的 CI 项一律只能记为"本地等价校验，未接远端，CI 待首推验证"。

---

## 二、当前事实·状态不变量（下一棒动手前必须知道）

1. **版本号只有一处**：`src/certledger/__init__.py::__version__`。`pyproject.toml` 用
   `dynamic = ["version"]`，**不要**加 `version = "…"`——`tests/test_architecture.py::test_version_has_one_source` 会红。
2. **状态副本有四个**：`plan/00` 里程碑表、`plan/05` 状态表、`README.md` 的「状态」表、
   `plan/00` 承诺-证据台账。**翻一个必须翻四个**，否则 `LAYOUT.STATUS` / `LAYOUT.LEDGER` 红。
3. **布局门只扫表头含「状态」的表**。`plan/05` 的"外部依赖"表首格也是 `M1`/`M2`，别把状态写进那张表。
   `plan/06` 的缺口表只认"首条非表格行即止"，别在表后追加行。
4. **缺口表匹配前会剥掉行内代码与 `.md` 文件名**。G2 已按"划掉 + 写已关闭"关闭并通过。
5. **`plan/03` 的空壳纪律仍在生效**：`collectors` / `inventory` / `hygiene` / `containers` / `render`
   五个入口**必须**抛 `NotImplementedError`，直到 M2 真正实现 `collect`。
   `tests/test_architecture.py::test_shells_raise_instead_of_returning_empty` 逐个断言——
   **M2 落地 `collect` 时同步改这条测试**（把 `collectors.collect` 从该断言里摘出来，
   换成"返回结构而不是抛错"的正向断言）。
6. **五条 K 口径**见 `AGENTS.md`。M2 直接相关的两条：
   - **K1**：指纹一律对 DER 原始字节做 SHA-256。`fixtures/expected.json` 里的
     `fingerprint_sha256` 就是这么算的，**不要**用 `cryptography` 重新编码后再哈希；
   - **K6**：后端不可用 → 一条 `SOURCE_UNAVAILABLE`，**退出码不变**。
7. **`.gitignore` 挡掉了 `fixtures/out/` 和全部证书后缀。** `fixtures/expected.json` 与
   `fixtures/gen.sh|.py` 在 `fixtures/` 根，**不要**把它们挪进 `out/`。
8. **`MANIFEST.in` 已把 `fixtures/` 列进 sdist 白名单**（`recursive-include fixtures *.sh *.md`）。
   **M2 新增的 `fixtures/gen.py` 目前不在白名单里**——见 §三 第 7 条，要在 M2 一并补上
   （脚本是交付面的可审计部分，缺了它解包树里跑不了生成器）。
9. **`license = "MIT"` + `license-files`**，且**不能**再保留 MIT 分类器——setuptools ≥ 77 直接拒绝构建。

### M1 留给下一棒的具体接口事实

10. **`fixtures/expected.json` 的形状**（M2 的测试应当直接用它当输入）：
    ```
    {schema_version, kind:"fixture-truth", as_of, as_of_utc,
     generator:{...}, policy_numbers_used:{warn_days,cliff_window_days,cliff_min_count,weak_key_rsa_min_bits},
     cases:[{case, group, index?, platform?, purpose, as_of, as_of_utc,
             inputs:[相对路径], artifacts:[{path,kind,format,reproducible,sha256,...}],
             expect:{findings:[{code,severity,count}], absent:[code], container?}}]}
    ```
    `artifacts[].kind ∈ {cert, key, container, broken, noise}`；
    `reproducible ∈ {bytes, alias_table}`（`alias_table` 的 `sha256` 每次不同，**不可用于比对**）。
11. **多块 PEM 的 `offset` 已写进真值**：`bundle` 用例有 3 条 artifact，`path` 相同、`offset` 分别 0/1/2。
    M2 的嗅探器展开多块 PEM 时，**这一条就是断言基准**。
12. **容器样本的口令**：`changeit`（`empty-pass` 用例除外，它空口令）。真值里写在
    `expect.container.password ∈ {set, empty}`。
13. **`truststore-with-key` 的判据是 PKCS#12 bag 结构**，不是 keytool 的 `Entry type` 字符串：
    `cryptography.load_pkcs12()` 会给出"cert bag 带 friendlyName 且公钥与私钥条目不同"。
    用 `keytool` 读同一个文件只会报 1 个 `PrivateKeyEntry`——**这是特性，不是 bug**，
    代码注释里要写清楚，否则下一个人会去"修"它。
14. **生成器刻意不造 ECDSA 与 JKS 样本**（理由见 `plan/04` §1.4 与 `fixtures/gen.py` 模块注释）。
    容器/JKS 样本归 M5；如果 M2 的嗅探器需要 ECDSA 输入，用 `tmp_path` 现造，不要往真值里加。

---

## 三、下一棒待办（M2）

按 `plan/03` §① 执行，顺序建议：

1. **`parsing/` 第一批**：PEM 拆块（RFC 7468，多块逐块展开，`offset` 从 0）、DER 判定、
   PKCS#7 `ContentInfo` OID 识别、PKCS#8 / OpenSSH 公钥识别。全部**只读前缀窗口**
   `collect.sniff_bytes`（策略值 4096），不整文件读。
2. **`collectors/collect`**：递归遍历（按规范化路径排序：大小写归一 + NFC）、
   `--follow-symlinks` 默认关、五种 `SKIP_*` 各一条记录、`--max-size` 生效。
   **不得返回空**：即使目录真的空，`summary.scanned` 等计数也要齐。
3. **三平台后端**：linux 走 `/etc/ssl/certs/ca-certificates.crt`；windows 走
   `certutil -store <Root|CA|My>`（**不用** `storeutl winstore`，D5）；macOS **一律**
   `SOURCE_UNAVAILABLE` + `unverified_backend:true`（D4，未实测不得假装支持）。
   后端缺失 → 一条记录、退出码 0（K6/D11）。
4. **`tests/test_collectors.py`**：八类格式各一例；不可读文件；后端缺失；遍历顺序稳定
   （**列表相等**，不是集合相等）；坏 DER → `PARSE_FAILED` 带 `stage`。
   直接用 `fixtures/expected.json` 的 `cases[].inputs` 当输入，用 `expect.findings` 当断言。
5. **AST 守门补一条**：`collectors/` 不 import 网络模块（`test_architecture.py` 已有全局版，
   建议再补一条模块级断言，把范围钉在采集器上）。
6. **改 `test_shells_raise_instead_of_returning_empty`**：把 `collectors.collect` 摘出去，
   换成"空目录也返回带计数的结构"。
7. **补 `MANIFEST.in`**：`recursive-include fixtures *.sh *.py *.md`（当前缺 `*.py`，
   解包树里 `gen.sh` 会因为找不到 `gen.py` 而失败）。
8. 回写四个状态副本 + 写 `plan/HANDOFF-M3.md`。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| 编号 | 约定 | 断言位置 |
|---|---|---|
| K1 | 指纹只对 DER 原始字节做 SHA-256 | `parsing/fingerprint.py`（唯一入口，M3 落地）；**M1 已按此口径写进真值** |
| K2 | `--as-of` 必填，不许回退到 `now()` | `tests/test_architecture.py::test_single_clock_source`、`tests/test_timebase.py` |
| K3 | 阈值只从策略文件读；缺失/非法 → 退出 2 | `tests/test_policy.py`、**`tests/test_fixtures_truth.py::test_every_expectation_recomputes_from_recorded_inputs`（读策略、不硬编码）** |
| K4 | 配对键 = `spki_sha256`，不用文件名 / subject / SKI | `plan/03` §②；M3 测试；**M1 的 `same-cn` 用例已把"同 CN 不误配"钉住** |
| K5 | 报告无时间戳 / 主机名 / 用户名；键序固定 | `tests/test_model.py` |
| K6 | 后端不可用 → `SOURCE_UNAVAILABLE`，退出码不变 | `plan/03` §①；**M2 测试（待落）** |
| K7 | 不设"未实现"退出码；未落地能力 → 可见记录或退出 2 | `tests/test_cli.py::test_unimplemented_module_exits_two_without_claiming_success` |

数值口径的唯一权威是 `data/README.md` §五。`src/certledger/data/default-policy.json` 是它的机器副本。
**`fixtures/expected.json::policy_numbers_used` 是第三份副本**——改策略必须同轮重跑
`bash fixtures/gen.sh` 重新生成真值，否则 `test_every_expectation_recomputes_from_recorded_inputs` 会红
（这是有意的：它正是"策略一变，样本就过期"的报警器）。

---

## 五、本机环境坑（只写实测过的）

- **Windows + Git Bash**：`py -3.12`（3.12.10）与 `py -3.8`（3.8.8）。项目下界 3.10，
  3.8 通道**跑不了本项目**，别用它做"兼容性验证"。
- **`py -X utf8` 是本机习惯**：不加它时中文控制台是 cp936。CI 里已设 `PYTHONUTF8=1`。
- **Git Bash 的 `/tmp` 与 Windows Python 路径不通**：`/tmp/x` 传给 `py` 会找不到。
  用 `cygpath -w /tmp/x` 转换，或直接用工作区相对路径。
  **M1 实测**：`bash fixtures/gen.sh --out /tmp/x` 能用，因为 bash 侧先解析成 `C:\...\Temp\x`
  再交给 Python；但**在 Python 里写死 `/tmp` 会失败**。
- **`cd /tmp` 再跑 `py` 会被 `/tmp/*.py` 遮蔽 stdlib**。干净环境验证必须在专用空目录里跑。
- **OpenSSL 3.5.6（本机）**：`req -x509` 同时支持 `-not_before` / `-not_after` / `-set_serial`，
  且 `-CA` / `-CAkey` 可在同一条命令里签 CA-signed 叶子。**3.0 以下没有这两个日期开关**，
  `gen.sh` 已在首行拦截。
- **`cryptography` 50.0.2（本机）拒绝用 SHA-1 签名**（`UnsupportedAlgorithm`），
  所以弱签名样本走 OpenSSL `-sha1`，不走 `CertificateBuilder.sign`。**M2/M3 解析侧不受影响**。
- **`cryptography` 拒绝写出空口令 PKCS#12**，但 OpenSSL `-passout pass:` 可以；
  `gen.py::p12_empty_password` 因此走子进程。
- **Windows 上 `os.chmod` 只改只读位**：`perm` 用例的 0644 在 Windows 上读回来仍是 0644
  （`stat` 能读到），但**不构成访问控制**——这正是 `plan/04` §五 说的 POSIX-only。
- **JDK 26 的 keytool 在 `C:\Program Files\Java\latest\jdk-26\bin\keytool.exe`**，
  **不在 PATH 上**（`java` 只有 `javapath` 里的 shim，`keytool` 没有）。M5 走 keytool 时
  要么显式找路径，要么把缺失当 `CONTAINER_UNREADABLE`（D2 的降级路径本来就要写）。
  **`keytool -J-Duser.language=en` 可强制英文输出**（本机实测），比 `LC_ALL=C` 可靠——
  后者在本机仍是中文，`plan/03` §⑤ 写的按 `Alias name:` 键取值会取不到。

---

## 六、DoD 逐项 checklist（M2）

- [ ] 八类格式嗅探各一例通过（PEM/DER/PKCS#7/PKCS#12/JKS/JCEKS/PKCS#8/OpenSSH 公钥）
- [ ] 多块 PEM 展开：`bundle` 用例 3 条记录、`offset` 0/1/2（与 `fixtures/expected.json` 一致）
- [ ] 遍历顺序稳定：同一树两次运行候选流**列表相等**
- [ ] 五种 `SKIP_*` 各一条用例；不可读文件不静默
- [ ] 三平台后端：linux 真跑；windows 真跑（`certutil`）；macOS → `SOURCE_UNAVAILABLE` + `unverified_backend`
- [ ] 后端缺失退出码 0（D11）
- [ ] 坏 DER → `PARSE_FAILED` 带 `path` + `stage`，退出码 0
- [ ] **零网络**：`collectors/` 不 import 网络模块（AST 守门）
- [ ] `MANIFEST.in` 补 `fixtures *.py`
- [ ] `test_shells_raise_instead_of_returning_empty` 已按新的真实情况更新
- [ ] 四个状态副本同轮翻 M2 为 ✅；`tools/check-sprint-layout.py` 全绿
- [ ] `tools/selftest-gates.py` 仍全红（10 + 4）
- [ ] `plan/HANDOFF-M3.md` 七节齐并已落盘

---

## 七、关键命令速查

```bash
# 门（任何新对话的第一件事）
py -3.12 -X utf8 tools/check-sprint-layout.py
py -3.12 -X utf8 tools/check-desensitized.py
py -3.12 -X utf8 tools/selftest-gates.py

# 测试（源码树，无需安装）
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q

# 样本（M1 产出；M2 拿它当输入）
bash fixtures/gen.sh --list                    # 17 个用例与用途
bash fixtures/gen.sh                           # 生成到 fixtures/out，并重写 expected.json
bash fixtures/gen.sh --check                   # 重生成到临时目录 + 比对真值（含跳过计数）
bash fixtures/gen.sh --determinism             # 两次生成逐文件比 sha256
bash fixtures/gen.sh --only healthy --out <dir>  # 部分生成（不改写 expected.json）

# 安装 + CLI 冒烟
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/certledger.exe --version
./.venv/Scripts/certledger.exe report --roots . --as-of 1900000000   # 期望 rc=2 + 明确的未落地提示

# 打包
./.venv/Scripts/python.exe -m build --sdist --wheel --outdir <空目录>
```
