# AGENTS.md

本仓库遵循 **`ai-tool-project-sprint`** 方法论（装订日期：2026-10-20）。

## 任何新对话的第一件事

```bash
python tools/check-sprint-layout.py      # 布局门；必须绿，红了先修布局再干活
python tools/check-desensitized.py       # 脱敏门；发布前必须 0 命中
```

> 本机（Windows）没有 `python` 别名时用 `py -3.12`；两条命令等价。

- 续接对话：读 `plan/HANDOFF-M<k>.md`（第 k 棒的收尾交接单），**先跑上面两条门**。
- 接手对话（无 HANDOFF）：先读 `plan/00`、`plan/05`、`plan/06` 与各 HANDOFF，
  重建"当前状态 + 既定口径（K 编号）清单"再动手。
- **门不存在 = 本项目没装订** → 先补第零步三件（本文件 + 两条门 + `plan/00` 顶部一行），再做别的。

## 强制布局（布局门逐条断言，改动前先看这里）

| 项 | 位置 | 判据 |
| --- | --- | --- |
| 计划套件 | `plan/00`–`06` + `data/README.md` | 存在，且各含必需小节（**锚定标题行**匹配） |
| 必备件 | `README.md` / `LICENSE` / `pyproject.toml` / `.github/workflows/ci.yml` / `src/certledger/{__init__,cli}.py` / 随包默认策略 | 逐个存在 |
| 交接单 | `plan/HANDOFF-M<k>.md` | 每个 ✅ 里程碑一份（M0 已声明豁免），**七节**齐（含"当前事实·状态不变量"） |
| 里程碑状态副本 | `plan/00` 里程碑表 + `plan/05` 状态表 + `README.md` 状态表 + `plan/00` 承诺-证据台账 | **逐处一致**；真值不取自任何单一副本；**只扫表头含「状态」的表**（否则 `plan/05` 的"外部依赖"表会被误读成状态行） |
| 缺口表 | `plan/06` 的「缺口」表 | 不得残留已 ✅ 里程碑的未关闭项；匹配前剥掉行内代码与 `.md` 文件名（文件引用不是状态引用） |
| 发布留档 | `plan/RELEASE-M6.md` | 两栏（`一、tag 前事实` / `二、tag 后追加`）+ "覆盖对账"小节 + ≥3 条三态行 |
| 文档点名的工具 | `tools/*.py` | 计划文档里出现的每个 `tools/…` 路径都必须在仓库里有实物 |
| CI 接线 | `.github/workflows/ci.yml` | 两条门命令各有一步 |

> 强制布局只放**结构性质**的项（存在性、节齐、N 处一致）。
> **不放**会随实现漂移的数字（测试数 / 用例数 / 行数 / run 数）——写进 tag 树那一刻就过期。

## 既定口径（K 清单，动了会打挂测试）

| 编号 | 约定 | 落点 |
| --- | --- | --- |
| K1 | 指纹一律对 **DER 原始字节**做 SHA-256，不重新编码后再哈希 | `plan/00` D6；`src/certledger/parsing/fingerprint.py` 是唯一入口 |
| K2 | `--as-of` **必填**，代码里不存在"回退到 `now()`"的分支 | `plan/00` D7；`cli.py` 与 `domain/timebase.py` |
| K3 | 阈值只从策略文件读，**代码零默认字面量**；策略缺失/非法 → 退出码 2 | `plan/00` D10；`src/certledger/policy/loader.py` |
| K4 | 配对键一律 `spki_sha256`，不用文件名 / subject / SKI | `plan/00` D8；`data/README.md` §五.6 |
| K5 | 报告不含时间戳、耗时、主机名、用户名；JSON 键序 = schema 声明序 | `plan/00` D9；`src/certledger/render/` |
| K6 | 后端不可用 → 一条 `SOURCE_UNAVAILABLE`，**退出码不变** | `plan/00` D11 |
| K7 | 退出码 `0/1/2` 语义见 `data/README.md` §五.8；骨架期临时码 `3`（未实现）**必须在 M5 退役**，退役时四处同步 | `plan/06` 缺口表 G1 |

## 本机环境事实与禁忌

- 本机：Windows + Git Bash；`py -3.12`（3.12.10）/ `py -3.8`（3.8.8）两条通道；
  Node 24.15.0；OpenSSL 3.5.6；JDK 26（`keytool` 可用）；`gh` 已登录（账号见 `gh auth status`）。
  以上实测日期 2026-10-20，**引用前先复测**。
- 跑 Python 一律 `py -3.12 -X utf8`（中文控制台编码）；项目下界 3.10，**不要写 3.8 不支持的语法**。
- 禁止：把"未执行"写成已完成；在 tag 之后改交付面（代码/策略/样例）。
- 隐私红线：真实证书与私钥永不入库；`fixtures/out/` 不入仓；报告不写主机名/用户名/绝对路径。
- 品牌隔离：文档中不出现本系列其他项目的领域描述。
