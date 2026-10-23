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
| CI 首推 | 全绿：run `39540591781`，8 个 job（layout / no-residue / tests × 6）；headSha = tag 指向的 commit | `gh run view 39540591781` |

### 首推 CI 抓到的缺陷（本 tag 内已修，先红后绿）

本机（Windows + OpenSSL 3.5.6）全绿，**首推后 CI 全红**。这不是"CI 配错了"——是六类只在
另一平台上才暴露的真实缺陷，逐条修完才绿：

| # | 缺陷 | 为什么本机看不见 | 修法 |
|---|---|---|---|
| 1 | 生成器用 `openssl req -x509 -not_before/-not_after` | 本机 OpenSSL 3.5.6 支持；CI 的 3.0 报 `req: Use -help for summary` | 先改 `ca -startdate/-enddate`，最终改 `cryptography` 自建 TBS |
| 2 | `openssl ca` 的输出在 3.0 与 3.5 上字节不同 | 本机只有一个版本 | 同上：去掉 OpenSSL 签名路径 |
| 3 | Windows 上 `bash` 是 WSL 启动器（无发行版）；`text=True` 按 locale 解码 | 本机 bash 是 Git Bash | 显式探 Git Bash；输出固定 UTF-8 解码；找不到就 skip 并给理由 |
| 4 | 符号链接测试在无 `fixtures/out` 时写占位文本 | 本机有 `fixtures/out` | 现场造一张真证书 |
| 5 | 测试夹具写私钥用默认 umask（POSIX 0644）→ 多出 `PERMISSION_TOO_OPEN` | Windows 上 `posix_mode` 记 `null` | 夹具显式 `chmod 0600` |
| 6 | CI 的 layout job 缺 `pyyaml` | 本机 `.venv` 装了 | workflow 里装依赖 |

另有一处**发布阻塞缺陷**在干净环境验证时抓到（不依赖 CI）：`report --markdown` 在读过系统库的
机器上必失败——真实根证书的 subject 自带 URL（`CN=http://www.usertrust.com`），被「零外链」
守门当成链接。修法与验收见下节。

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

- **本机从未跑过 Linux 真实路径**（无 `/etc/ssl/certs/ca-certificates.crt`）**与 macOS 后端**。
  区分清楚：CI 跑通了 Linux 上的**测试**，但测试用的是注入的 bundle，不是那个真实路径。
- **BKS / UBER 等非 JDK 容器格式从未验证**（落 `CONTAINER_UNREADABLE`，不静默）。

> **"CI 绿"是先红后绿拿到的**：tag 之前 CI 实跑了四轮——`39527273833`、
> `39534488059`、`39536509191` 三红，`39540591781` 全绿，且这一轮的 `headSha`
> 正是 tag 指向的 commit。run id 与每轮失败原因见 §二与上表。

---

## 二、tag 后追加

> 本节在 **tag `v0.1.0` 之后的追加提交**里填写字面值；tag 树版本为占位。
> **以下字面值都在 tag 之后写入**，不在 tag 树内——tag 树里那一栏只有占位符。

| 事实 | 字面值 |
|---|---|
| tag 对象 OID | `77a61038153728a85826280f7b82ec3585b8a89a` |
| tag 指向的 commit | `37f80a6e2c14df45c9f05c79540efbd320c52b93`（`证书生成改由 cryptography 自建 TBS…`） |
| CI 首推 run id | **`39540591781`**（G3 关闭证据）。该 run 的 `headSha` 正是 tag 指向的 `37f80a6`；8 个 job 全绿：`Methodology gates` / `no-residue` / `Tests (py3.10,3.12,3.13) × (ubuntu, windows)` |
| 首推前失败的 run（留档） | `39527273833`（6 类跨平台缺陷）、`39534488059`（Windows 全绿、Linux 真值漂移）、`39536509191`（`ca` 的扩展集已钉住仍漂移）——三次失败的原因与修正见 §一「本步实录」与 git log |
| `certledger-0.1.0.tar.gz` sha256 | `137b89ed58e1458eec95dc31c70c956dbc40a62439c6db340944ddd068a1c29a`（300,685 bytes；已用 `gh release download` 取回复算，与本地构建一致） |
| wheel | **未附**。A 方案只要"手工源码包"；wheel 是平台无关的同一份代码，附上会多一个需要复算的哈希而没有新增可审计面 |
| Release 地址 | `https://github.com/yuluo554/10-21-certledger/releases/tag/v0.1.0`（`isDraft=false`、`isPrerelease=false`，附件 `certledger-0.1.0.tar.gz`） |

### tag 之后需要知道的一件事

`openssl` 已不在证书签名路径上。首推暴露的第三个问题（`ca` 的输出在 OpenSSL 3.0 与 3.5
上字节不同）意味着**真值文件的指纹曾经取决于跑生成器的机器**；改成 `cryptography` 自建
TBS 之后，`expected.json` 才真正与平台无关。这条修正落在 tag 树内（`37f80a6`），
CI 的 Linux job 是它的验收——**先红后绿**，不是本机推断。

---

## 覆盖对账（阶段 7 · 三态）

> 三态：**实现**（有可复跑证据）/ **不适用**（附理由，属已决定不做或平台前提不满足）/
> **待首推**（本机不可实跑，首推后由 §二 回填）。逐项对齐 `plan/05` §二 DoD、§五 已知未验证项
> 与 `plan/06` §三 缺口表。**首推已完成**：原为「待首推」的两项（#13 CI 矩阵、#14 Release 产物）
> 已按实际 run id 与包哈希回填为「实现」；其余「不适用」项的理由不因发布而改变。

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
| 13 | CI 矩阵（ubuntu / windows × 3.10 / 3.12 / 3.13） | 实现 | run `39540591781`（8 job 全绿）。**先红后绿**：前三次 run 暴露 6 类跨平台缺陷 + 真值随 OpenSSL 版本漂移，逐条修完后才绿（G3 关闭） |
| 14 | Release 附手工源码包 + sha256 登记 | 实现 | `certledger-0.1.0.tar.gz` 已附，sha256 写在 Release 正文；取回复算一致（§二）。tag 树内仍是占位符（A 方案） |
| 15 | 开源空白（`total_count` 软论据） | 不适用 | 软论据，检索式与窗口记入 `data/README` §1.3，可复算；不作为硬承诺 |

---

# v0.1.1 二次迭代（2026-10-21）

> 口径同本文件开头：**tag 树版本不含任何字面值**。`v0.1.1` 的 tag 对象 / commit OID / 包哈希 /
> CI run id 在 tag 树里一律写「见 `git rev-parse v0.1.1`」或「见下 §二」；
> 真值只在 **tag 之后的追加提交**里补（本节 §二）。`v0.1.0` 的 tag 与 Release **原样保留**。

## 一、tag 前事实（v0.1.1）

| 事实 | 证据 | 复跑命令 |
|---|---|---|
| 版本单一来源 = `0.1.1` | `src/certledger/__init__.py::__version__`；`pyproject.toml` 走 `dynamic`，无第二处字面量 | `py -3.12 -c "import sys;sys.path.insert(0,'src');import certledger;print(certledger.__version__)"` |
| **D1 关闭**（`cryptography` 警告作用域） | `inventory.build()` 在整条记录构建外只静音 `CryptographyDeprecationWarning`；本机 81 张系统证书含 2 张触发（`Go Daddy Class 2` / `Starfield Class 2`，其 `AuthorityKeyIdentifier` 内嵌 serial=0，警告在访问 `.extensions` 时才惰性发出） | ① `py -3.12 -X utf8 -m certledger inventory --roots fixtures/out --source auto --json <out> 2> <err>` → stderr **0 字节**；② `py -3.12 -W error -X utf8 -m certledger inventory --roots fixtures/out --source auto --json <out>` → exit 0 |
| **D1 有回归防线** | `tests/test_inventory.py` 新增 2 例：记录仍成形 / 升格为 error 也不抛。**负控实测**：撤掉静音，两例全红 | `./.venv/Scripts/python.exe -m pytest -q -k "cryptography_warns_about or promoted_to_an_error"` |
| **D2 关闭**（入口文档点名 `selftest-gates.py`） | `README.md` §Development 与 `AGENTS.md`「任何新对话的第一件事」各加一行；`LAYOUT.DOC_TOOLS` 未受影响，M8 变异 `hit=True` 仍成立 | `grep -c "selftest-gates" README.md AGENTS.md` → 各 ≥ 1；`py -3.12 -X utf8 tools/selftest-gates.py` → 14 组全红 exit 0 |
| **D3 关闭**（floor 3.10→3.12，决策 D15） | `pyproject.toml` `requires-python = ">=3.12"`、classifiers 删 3.10/3.11；`ci.yml` 矩阵 `["3.12","3.13"]`（6→4 job）；`README.md:37` `≥ 3.12`；`plan/00`/`plan/05`/`AGENTS.md` 同步 | `grep -n requires-python pyproject.toml`；`grep -C2 "python:" .github/workflows/ci.yml`；`grep -n "≥ 3.12" README.md` |
| 布局门全绿 | 16 份必备件 / 7 份文档 / 4 处状态副本一致 / 8 行缺口 / 31 行台账 | `py -3.12 -X utf8 tools/check-sprint-layout.py` |
| 脱敏门 0 命中 | 扫 80 个文本文件（`update/` 已加入 `SKIP_DIRS` 并 `gitignore`） | `py -3.12 -X utf8 tools/check-desensitized.py` |
| 门自身可跑红 | 基线全绿 + 10 组布局变异 + 4 组脱敏变异全部按预期变红 | `py -3.12 -X utf8 tools/selftest-gates.py` |
| 测试全绿 | 362 passed / 1 skipped（360 → +2 D1 回归例；唯一 skip 是 Windows chmod 不构成访问控制） | `./.venv/Scripts/python.exe -m pytest -q` |
| `fixtures/expected.json` 字节未变 | M1 承诺：二次迭代未触碰生成器与真值 | `git diff v0.1.0..v0.1.1 -- fixtures/expected.json`（应无输出） |
| sdist 仍自足 | 新 tag 的 sdist 解包 → 全新 venv 只装 pytest + 包 → pytest exit 0；再跑 `bash fixtures/gen.sh` → pytest exit 0 | 见下「sdist 自足复验」 |
| 发布形态 | GitHub Release 附 `certledger-0.1.1.tar.gz`（sdist），sha256 登记在 Release 正文 | `gh release view v0.1.1` |

### sdist 自足复验（本仓强项，二次迭代后仍须成立）

```bash
TMP=$(mktemp -d); cd "$TMP"; tar xzf <下载的 certledger-0.1.1.tar.gz>; cd certledger-0.1.1
py -3.12 -m venv v && v/Scripts/python.exe -m pip -q install pytest && v/Scripts/python.exe -m pip -q install .
v/Scripts/python.exe -m pytest -q                      # 第一轮：无 samples，含 D1 回归例
bash fixtures/gen.sh >/dev/null 2>&1
v/Scripts/python.exe -m pytest -q                      # 第二轮：生成样本后
```

> **数字口径**：与仓库内 `362 passed / 1 skipped` 的差值 = sdist 无 `.git`（`test_fixtures_truth.py` 的
> "not a git checkout" 合理 skip）+ 无 `fixtures/out` 时的样本用例 skip。**逐次实测值见 §二**。

## 二、tag 后追加（v0.1.1）

> 本节在 **tag `v0.1.1` 之后的追加提交**里填写字面值；tag 树版本为占位。
> **以下字面值都不在 tag 树内**——tag 树里那一栏只有占位符。

| 事实 | 字面值 |
|---|---|
| tag 对象 OID | 见 `git rev-parse v0.1.1` |
| tag 指向的 commit | 见 `git rev-parse v0.1.1^{commit}` |
| tag 事件 CI run id | 见本仓库 Actions 页 `v0.1.1` 那次 run |
| `certledger-0.1.1.tar.gz` sha256 | 见 Release 正文 |
| Release 地址 | `https://github.com/yuluo554/10-21-certledger/releases/tag/v0.1.1`（`isDraft=false`、`isPrerelease=false`） |
| sdist 两轮实测 | 见下方「复验记录」 |

### 覆盖对账（v0.1.1 · 三态，增量项）

> 只列二次迭代**新增或状态变化**的覆盖项；其余 15 项沿用上文「覆盖对账（阶段 7）」，理由不因二次迭代改变。

| # | 覆盖项 | 三态 | 依据 / 理由 |
|---|---|---|---|
| 16 | 真实系统库证书的库警告不污染 stderr（D1） | 实现 | `inventory.build()` 静音作用域覆盖整条记录构建；本机 `--source auto` stderr 0 字节（实测） |
| 17 | D1 回归防线（`-W error` 下不抛） | 实现 | `tests/test_inventory.py` 2 例 + 负控实测（撤掉静音两例全红） |
| 18 | 入口文档点名 `selftest-gates.py`（D2） | 实现 | `README.md` §Development、`AGENTS.md` 各一行；`grep -c` 各 ≥ 1 |
| 19 | Python floor 3.12 / CI 矩阵 4 job（D3 / D15） | 实现 | `pyproject.toml` + `ci.yml` + 三处文档同步；`plan/00` D15 supersede D13 的 floor 一项 |
| 20 | v0.1.0 的 tag 与 Release 原样保留 | 实现 | `git rev-parse v0.1.0` 不变；Release `v0.1.0` 未编辑 |
