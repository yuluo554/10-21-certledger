# HANDOFF-M1 · 数据先行（`fixtures/gen.sh` + 八类样本 + 真值）

> 用法：以 `plan/HANDOFF-M1.md` 为入口续接本棒。**第一动作 = 跑两条门**（见 §7）。
> 本文件写于 2026-10-20（M0 收尾）。库内一律相对路径。

---

## 一、当前进度 + 证据

M0 已完成并本地验证。M1 **未开始**。

| 已落地 | 证据（可复跑） |
|---|---|
| 方法论装订三件 | `AGENTS.md`、`tools/check-sprint-layout.py`、`tools/check-desensitized.py`、`plan/00` 顶部装订行 |
| 两道门全绿 | `py -3.12 tools/check-sprint-layout.py` → 10 项 PASS；`py -3.12 tools/check-desensitized.py` → 0 命中 |
| 门自身可跑红 | `py -3.12 tools/selftest-gates.py` → 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 |
| 计划套件 | `plan/00`–`06`、`data/README.md` |
| 可运行骨架 | `pyproject.toml`（版本 `dynamic`）、`src/certledger/`（CLI 五子命令 + 策略加载 + 时间基准 + 记录模型） |
| 测试 | `py -3.12 -m pytest -q` → 66 passed（本机 3.12.10；装成 editable 后 `test_installed_metadata_matches_module` 不再 skip） |
| 打包 | `python -m build` 产 sdist + wheel；解包树里两条门仍分别返回 0；干净 venv 从 wheel 安装后 `certledger --version` 正常 |
| CI | `.github/workflows/ci.yml` 本地 `yaml.safe_load` 通过，jobs = layout / test（2×3 矩阵）/ no-residue |

**未发生的事**：CI 从未实跑（无远端）。M0 DoD 里的 CI 项一律只能记为"本地等价校验，未接远端，CI 待首推验证"。

---

## 二、当前事实·状态不变量（下一棒动手前必须知道）

1. **版本号只有一处**：`src/certledger/__init__.py::__version__`。`pyproject.toml` 用
   `dynamic = ["version"]` + `[tool.setuptools.dynamic]`，**不要**在 `pyproject.toml` 里加 `version = "…"`
   ——`tests/test_architecture.py::test_version_has_one_source` 会红。
2. **状态副本有四个**：`plan/00` 里程碑表、`plan/05` 状态表、`README.md` 的「状态」表、
   `plan/00` 承诺-证据台账。**翻一个必须翻四个**，否则 `LAYOUT.STATUS` / `LAYOUT.LEDGER` 红。
3. **布局门只扫表头含「状态」的表**。`plan/05` 的"外部依赖"表首格也是 `M1`/`M2`，别把状态写进那张表。
   同理 `plan/06` 的缺口表只认"首条非表格行即止"，别在表后追加行。
4. **缺口表匹配前会剥掉行内代码与 `.md` 文件名**。在缺口格里写"见 `plan/RELEASE-M6.md`"是合法的；
   写"仍待 M6"会红。
5. **`plan/03` 的空壳纪律**：分析模块必须是 `NotImplementedError`，不能返回空 list/dict。
   `tests/test_architecture.py::test_shells_raise_instead_of_returning_empty` 逐个断言了五个入口。
6. **五条 K 口径**见 `AGENTS.md`（DER 原始字节哈希 / `--as-of` 必填 / 阈值只在策略文件 /
   SPKI 配对 / 报告无时间戳主机名）。M1 的生成器**不得**引入第二套时间口径：样本日期用
   `-not_before/-not_after` 钉死，`as_of` 固定为 `1900000000`。
7. **`.gitignore` 挡掉了 `fixtures/out/` 和全部证书后缀**。M1 的真值文件 `fixtures/expected.json`
   必须放在 `fixtures/` 根（不是 `out/`），否则会被一起挡掉。
8. **`MANIFEST.in` 已把 `tests/ plan/ data/ tools/ fixtures/ .github/` 列进 sdist**。新增顶层目录时
   同步加一行，否则发布包里缺件（M0 实测：没有 `conftest.py` 时 `pytest` 在解包树里跑不起来）。
9. **`license = "MIT"` + `license-files`**，且**不能**再保留
   `"License :: OSI Approved :: MIT License"` 分类器——setuptools ≥ 77 会直接拒绝构建（M0 实测报错）。

---

## 三、下一棒待办（M1）

按 `plan/04` §一 §二执行，顺序建议：

1. `fixtures/gen.sh`：`--out <dir>`（默认 `fixtures/out`）、`--only <case>`、`--check` 三个开关。
   开头探测 `openssl version` ≥ 3.0 与可选 `keytool`；缺失时**退出 2 并说明需要什么**（不要在脚本里静默降级）。
2. 八类样本 + 补充样本（`plan/04` §1.1 / §1.2）。日期与序列号钉死；生成后打印每个文件的 sha256。
3. `fixtures/expected.json`：每用例 `{case, as_of, inputs[], expect: {findings: [...]}}`。
   **禁止** `observed_*` 字段。
4. `--check` 通路：重生成到 `mktemp -d` → 比对指纹与 alias 表；容器字节跳过并打印跳过了几项。
   注意：`--only` **不得**改写 `expected.json` 的全集清单。
5. `tests/test_fixtures_truth.py`：字段白名单 + "期望值可由输入独立复算"（不 import `hygiene`）。
6. 回写四个状态副本 + 写 `plan/HANDOFF-M2.md`。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| 编号 | 约定 | 断言位置 |
|---|---|---|
| K1 | 指纹只对 DER 原始字节做 SHA-256 | `parsing/fingerprint.py`（唯一入口，M3 落地） |
| K2 | `--as-of` 必填，不许回退到 `now()` | `tests/test_architecture.py::test_single_clock_source`、`tests/test_timebase.py` |
| K3 | 阈值只从策略文件读；缺失/非法 → 退出 2 | `tests/test_policy.py` |
| K4 | 配对键 = `spki_sha256`，不用文件名 / subject / SKI | `plan/03` §②；M3 测试 |
| K5 | 报告无时间戳 / 主机名 / 用户名；键序固定 | `tests/test_model.py` |
| K6 | 后端不可用 → `SOURCE_UNAVAILABLE`，退出码不变 | `plan/03` §①；M2 测试 |
| K7 | 不设"未实现"退出码；未落地能力 → 可见记录或退出 2 | `tests/test_cli.py::test_unimplemented_module_exits_two_without_claiming_success` |

数值口径的唯一权威是 `data/README.md` §五。`src/certledger/data/default-policy.json` 是它的机器副本，
两边不一致时以 `data/README.md` 为准；改一处必须改另一处并跑 `tests/test_policy.py`。

---

## 五、本机环境坑（只写实测过的）

- **Windows + Git Bash**：`py -3.12`（3.12.10）与 `py -3.8`（3.8.8）。项目下界 3.10，
  3.8 通道**跑不了本项目**，别用它做"兼容性验证"。
- **`py -X utf8` 是本机习惯**：不加它时中文控制台是 cp936。CI 里已设 `PYTHONUTF8=1`。
- **Git Bash 的 `/tmp` 与 Windows Python 路径不通**：`/tmp/x` 传给 `py` 会找不到。
  用 `cygpath -w /tmp/x` 转换，或直接用工作区相对路径。
- **`cd /tmp` 再跑 `py` 会被 `/tmp/*.py` 遮蔽 stdlib**（M0 实测：`/tmp/inspect.py` 让
  `dataclass(slots=True)` 报 `AttributeError: module 'inspect' has no attribute 'get_annotations'`）。
  **干净环境验证必须在专用空目录里跑**（建 `mkdir -p <tmp>/neutral-run` 再进）。
- **`python -m build` 需要 venv 里有 `setuptools`**：本机 `py -3.12` 全局有，但新建 venv 里
  `--no-build-isolation` 可能报 `BackendUnavailable: Cannot import 'setuptools.build_meta'`。
  先 `pip install build setuptools wheel`，或不带 `--no-build-isolation`。
- **`pyproject.toml` 的 license 分类器会拦构建**：setuptools 84 拒绝同时存在
  `license = "MIT"` 与 `License :: OSI Approved :: MIT License`。
- **JDK 26 的 keytool 可用**（2026-10-20 复测）。openjdk 相关路径未入 K 清单，M1 只在脚本里探测。

---

## 六、DoD 逐项 checklist（M1）

- [ ] `fixtures/gen.sh --out <dir>` 在干净 clone 里一键生成八类 + 补充样本
- [ ] 同参数两次生成 → 所有 `.pem/.key/.crt` 的 sha256 相同（脚本自检并打印）
- [ ] `fixtures/expected.json` 就位，无 `observed_*`，每条期望可由输入独立复算
- [ ] `--check` 通路跑通，容器字节跳过数被打印
- [ ] `--only` 不改写 `expected.json` 的全集清单
- [ ] **真实证书与私钥零入库**：`git status --porcelain` 里没有 `*.pem/*.key/*.p12/*.jks`
- [ ] `tests/test_fixtures_truth.py` 全绿
- [ ] 四个状态副本同轮翻 M1 为 ✅；`tools/check-sprint-layout.py` 全绿
- [ ] `tools/selftest-gates.py` 仍全红（10 + 4）
- [ ] `plan/HANDOFF-M2.md` 七节齐并已落盘

---

## 七、关键命令速查

```bash
# 门（任何新对话的第一件事）
py -3.12 -X utf8 tools/check-sprint-layout.py
py -3.12 -X utf8 tools/check-desensitized.py
py -3.12 -X utf8 tools/selftest-gates.py

# 测试（源码树，无需安装）
PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q

# 安装 + CLI 冒烟
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/certledger.exe --version
./.venv/Scripts/certledger.exe report --roots . --as-of 1900000000   # 期望 rc=2 + 明确的未落地提示

# 打包
./.venv/Scripts/python.exe -m build --sdist --wheel --outdir <空目录>
```
