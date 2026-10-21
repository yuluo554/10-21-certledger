# plan/RELEASE-M6 · 发布留档

> 口径：`plan/05` §三。写出顺序 = 先本地全绿 → 打包 → 建仓首推 → tag → Release。
> **本文件的 tag 树版本不含任何字面值**：tag 对象 / commit OID / 包哈希 / CI run id
> 一律写「见 `git rev-parse v0.1.0`」或「见 §二」；字面值只在 **tag 之后的追加提交**里补（§二）。
> 这样 tag 树不会因为「打一次 tag 就过期」而说谎。

---

## 一、tag 前事实

| 事实 | 证据 | 复跑命令 |
|---|---|---|
| 版本单一来源 = `0.1.0` | `src/certledger/__init__.py::__version__`；`pyproject.toml` 走 `dynamic`，无第二处字面量 | `py -3.12 -c "import sys;sys.path.insert(0,'src');import certledger;print(certledger.__version__)"` |
| 布局门全绿 | 16 份必备件 / 7 份文档 / 4 处状态副本一致 / 8 行缺口 / 31 行台账 | `py -3.12 -X utf8 tools/check-sprint-layout.py` |
| 脱敏门 0 命中 | 扫 79 个文本文件 | `py -3.12 -X utf8 tools/check-desensitized.py` |
| 门自身可跑红 | 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 | `py -3.12 -X utf8 tools/selftest-gates.py` |
| 测试全绿 | 360 passed / 1 skipped（359 收集 → 修正后 +1 回归例；唯一 skip 是 Windows chmod 不构成访问控制） | `PYTHONDONTWRITEBYTECODE=1 py -3.12 -X utf8 -m pytest -q` |
| 样本可复现 | `--check` → 17 用例 / 字节级 31 项 / alias 表 3 项 / 容器字节跳过 3 项；全量重生成前后 `fixtures/expected.json` **字节未变**（sha256 见 `git rev-parse v0.1.0:fixtures/expected.json`） | `bash fixtures/gen.sh && bash fixtures/gen.sh --check && bash fixtures/gen.sh --determinism` |
| 干净环境可安装可跑 | 中立目录 + 全新 venv + `pip install -e ".[dev]"` → `certledger 0.1.0`；README 的 Usage 命令逐条跑通（`report --json/--markdown`、`report --baseline`、`containers --show-aliases`、空口令容器） | 见下「干净环境验证」 |
| 打包产物 | sdist + wheel 由本树构建；解包后的 sdist 树里 `bash fixtures/gen.sh --check` 通过，且**不含** `fixtures/out/` 与任何证书/私钥字节 | `python -m build --sdist --wheel`；sha256 见 §二 |
| 隐私 | `git status --porcelain --untracked-files=all` 无 `*.pem/*.key/*.p12/*.pfx/*.jks/*.jceks/*.der/*.crt` | 见「本机环境」 |
| 发布形态 | A 方案：GitHub Release **附手工源码包**（`certledger-0.1.0.tar.gz`），sha256 只登记在 Release 正文 | `gh release view v0.1.0` |

### 干净环境验证（M6 第 3 步）

在**中立目录**（非工作树）用**全新 venv** 逐条敲 README 的 Usage：

```bash
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e "<repo>[dev]"
./.venv/Scripts/certledger.exe --version            # → certledger 0.1.0
export CERTLEDGER_CONTAINER_PASSWORD=changeit
./.venv/Scripts/certledger.exe collect   --roots ./pki --source auto --json -          # rc=0
./.venv/Scripts/certledger.exe inventory --roots ./pki --json ledger.json               # rc=0
./.venv/Scripts/certledger.exe hygiene   --inventory ledger.json --as-of 1900000000      # rc=0
./.venv/Scripts/certledger.exe report    --inventory ledger.json \
    --as-of 2030-03-17T17:46:40Z --json report.json --markdown report.md                 # rc=1（命中门禁，报告已出）
./.venv/Scripts/certledger.exe report    --inventory ledger.json --as-of 1900000000 \
    --baseline report.json --json after.json                                             # rc=1
./.venv/Scripts/certledger.exe containers ./pki/truststore-with-key/mixed.p12 --show-aliases  # rc=0
unset CERTLEDGER_CONTAINER_PASSWORD
./.venv/Scripts/certledger.exe containers ./pki/empty-pass/empty-pass.p12                # rc=0
```

### 本步实录的发布阻塞缺陷（已在本 tag 内修正）

**现象**：`report --json … --markdown …` 在**读过系统库的机器上必报错退出**。
`inventory` / `report` 的 `--source` 缺省是 `auto`，会把系统信任库并进台账；
真实根证书的 **subject 里自带 URL**（本机实测 `CN=http://www.usertrust.com`），
而 `render_markdown` 的「零外链」守门用**全文字符串包含**判定，
把这条**数据**当成了渲染层引入的外链，抛 `ValueError` 并整条命令失败。

**根因**：渲染三律 2「正文不得出现 `http(s)://`」把「渲染层引入的链接」与
「证书名里作为数据的 URL」混为一谈；后者不可能靠不渲染来消除。

**修正**（`src/certledger/render/markdown_out.py`）：在数据单元格里把
`http(s)://` 的冒号转义成 `http\://`——人读仍是 `http://`，但既不成链接、
也不触发本律；`render_markdown` 的守门保留为**渲染层自引进链接**的兜底。
同时把该口径写回 `plan/03` §④ 渲染三律 2，并加回归例
`tests/test_determinism.py::test_a_url_inside_a_certificate_name_is_defused_not_a_link`。

**验收**：修正后同一命令 `report --json report.json --markdown report.md` 正常出稿（rc=1 为门禁命中，
非错误）；Markdown 正文 `grep -c 'http://'` = 0，且 `usertrust` 仍以 `http\://www.usertrust.com` 可读地留在表里。

### 未发生的事（照实记）

- **CI 从未实跑**（首推前一概如此）；本机等价物 = 双解释器不可得，故只 3.12 + 两道门 + `selftest-gates` + CLI 冒烟。
- **本机从未跑过 Linux 真实路径**（无 `/etc/ssl/certs/ca-certificates.crt`）**与 macOS 后端**。
- **BKS / UBER 等非 JDK 容器格式从未验证**（落 `CONTAINER_UNREADABLE`，不静默）。

---

## 二、tag 后追加

> 本节在 **tag `v0.1.0` 之后的追加提交**里填写字面值；tag 树版本为占位。

| 事实 | 字面值 |
|---|---|
| tag 对象 OID | 见 `git rev-parse v0.1.0` |
| tag 指向的 commit | 见 `git rev-parse v0.1.0^{commit}` |
| CI 首推 run id | 见本仓库 Actions 页 `v0.1.0` 之前最近一次 push 的 run（G3 关闭证据） |
| `certledger-0.1.0.tar.gz` sha256 | 见 Release 正文 |
| `certledger-0.1.0-py3-none-any.whl` sha256 | 见 Release 正文 |
| Release 地址 | `https://github.com/yuluo554/10-21-certledger/releases/tag/v0.1.0` |

---

## 覆盖对账（阶段 7 · 三态）

> 三态：**实现**（有可复跑证据）/ **不适用**（附理由，属已决定不做或平台前提不满足）/
> **待首推**（本机不可实跑，首推后由 §二 回填）。逐项对齐 `plan/05` §二 DoD、§五 已知未验证项
> 与 `plan/06` §三 缺口表。

| # | 覆盖项 | 三态 | 依据 / 理由 |
|---|---|---|---|
| 1 | 五子命令全链路（collect / inventory / hygiene / report / containers） | 实现 | `tests/test_cli.py`；干净环境逐条跑通 |
| 2 | 双格式确定性报告（JSON + Markdown，字节级） | 实现 | `tests/test_determinism.py`（11 例，含跨进程确定性） |
| 3 | 退出码 0/1/2 与 `--fail-on none` 恒 0 | 实现 | `tests/test_exit_codes.py`（10 例） |
| 4 | `--baseline` 三类 diff（added / removed / rotated） | 实现 | `tests/test_baseline.py`（10 例） |
| 5 | 容器 P12 / JKS / JCEKS 别名表 | 实现 | `tests/test_containers.py`（15 例）；本机 JDK 26 `keytool` 真建真读 |
| 6 | Windows 后端 / P12 / JKS 真实读取 | 实现 | 本机实测（`plan/HANDOFF-M6` §二.4–5） |
| 7 | 容器 BKS / UBER 等非 JDK 格式 | 不适用 | 无规范、无样本；落 `CONTAINER_UNREADABLE`，不静默（`plan/05` §五） |
| 8 | macOS 后端真机验证 | 不适用 | 无设备；恒 `SOURCE_UNAVAILABLE` + `unverified_backend`（D4），降级语义已实现并测试（G4 保持） |
| 9 | `perm` 用例端到端对账 | 不适用 | POSIX-only；Windows 上 `posix_mode` 记 `null`，规则按设计静默（`plan/05` §五） |
| 10 | Windows ACL「权限过宽」判定 | 不适用 | 已定稿不做（`data/README` §六，G5） |
| 11 | `PUBLIC_VALIDITY_HINT` 展示层提示 | 不适用 | 已定稿不进 `findings`（`plan/06` G8） |
| 12 | Linux `/etc/ssl/certs/ca-certificates.crt` 真实路径 | 不适用 | 本机无该文件；读取与 PEM 拆分路径已用真实 bundle 注入实测 |
| 13 | CI 矩阵（ubuntu / windows × 3.10–3.13） | 待首推 | 本机只有 3.8 / 3.12；首推后回填 run id（G3） |
| 14 | Release 附手工源码包 + sha256 登记 | 待首推 | tag 后录入 §二；包哈希不复算不写进 tag 树（A 方案） |
| 15 | 开源空白（`total_count` 软论据） | 不适用 | 软论据，检索式与窗口记入 `data/README` §1.3，可复算；不作为硬承诺 |
