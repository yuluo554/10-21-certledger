> 方法论：`ai-tool-project-sprint`（装订 2026-10-20）｜布局门：`py tools/check-sprint-layout.py`｜续接对话第一件事 = 跑它

# 10-21-certledger · README 总览（本地密码学资产台账）

> **一句话定位**：ChainWarden 回答"这张证书有没有问题"，我们回答"**这台机器上有哪些证书和私钥，谁配谁**"。
> 过期表只是其中一列；**这是台账，不是过期提醒器**。

| 项 | 内容 |
|---|---|
| 项目 | CertLedger（本地密码学资产台账） |
| 性质 | 不参赛项目题 · 发布 GitHub **公开仓库** · 署名 `yuluo554` |
| 交付形态 | **纯本地 Python CLI**（唯一形态；零网络、零远程握手、零守护进程） |
| 技术栈 | Python ≥ 3.10 · `cryptography` ≥ 42（解析底座）· `pytest`（dev）· 可选 JDK `keytool` |
| 许可证 | MIT |
| 版本 | v1 计划 · 2026-10-20 定稿；代码版本 `0.1.0.dev0`（`src/certledger/__init__.py` 单一来源） |
| 检索/查证窗口 | **2026-10-19T18:35Z – 19:05Z**（星数、push 日期均为该窗口快照） |
| 当前状态 | **M0 完成**：方法论装订 + plan/00–06 + 可运行骨架（五子命令参数面 / 策略加载 / 时间基准 / 记录模型）+ 两道门 |

---

## 一、文档索引

| 文档 | 内容 | 状态 |
|---|---|---|
| `AGENTS.md` | 方法论锚点：门命令、强制布局、K 清单、本机环境事实 | ✅ 已落盘 |
| `plan/00-README总览.md` | 本文档：索引、决策记录、弃选项、招牌动词表、承诺-证据台账、里程碑 | ✅ 已落盘 |
| `plan/01-题目文档.md` | 十段式题目定稿（**定稿后只增勘误，不改写**） | ✅ 已落盘 |
| `plan/02-架构与技术选型.md` | 分层、目录结构、依赖策略（含 JKS 路线）、构建 | ✅ 已落盘 |
| `plan/03-模块详设.md` | 五模块的输入/输出/失败路径/断言基准 | ✅ 已落盘 |
| `plan/04-数据计划.md` | 八类样本矩阵、真值纪律、可复现性、数值口径引用 | ✅ 已落盘 |
| `plan/05-里程碑与发布.md` | 逐里程碑 DoD、发布口径、已知未验证项 | ✅ 已落盘 |
| `plan/06-交付对标与决策.md` | 评分对标、风险登记、缺口表、待定决策 | ✅ 已落盘 |
| `data/README.md` | 依据查证（三态）、规范台账、数据源、合成数据纪律、数值口径单点定义 | ✅ 已落盘 |
| `tools/check-sprint-layout.py` | 布局门（10 条判据 + 非空跑自证） | ✅ 已落盘 |
| `tools/check-desensitized.py` | 脱敏门（4 条规则 + 自豁免） | ✅ 已落盘 |
| `tools/selftest-gates.py` | 两道门的变异自检（10 + 4 组） | ✅ 已落盘 |
| `.github/workflows/ci.yml` | 布局门 / 脱敏门 / 变异自检 / pytest 矩阵 / 零残留 | ✅ 已落盘 |
| `pyproject.toml` | 构建配置（版本 `dynamic`，`[project.scripts] certledger`） | ✅ 已落盘 |
| `MANIFEST.in` | 源码包白名单（tests/plan/data/tools/fixtures/CI 进 sdist） | ✅ 已落盘 |
| `.gitattributes` | 源码 EOL 归一；证书类文件 `-text` | ✅ 已落盘 |
| `src/certledger/` | CLI + 策略 + 时间基准 + 模型；五个分析模块为空壳（显式未实现） | ✅ 骨架 / ⬜ 分析层 |
| `tests/` | CLI 面 / 策略 / 时间基准 / 模型 / 架构守门 / README 承诺 | ✅ 已落盘 |
| `fixtures/gen.sh` + `fixtures/gen.py` | 可复现样本生成脚本（shell 探测工具链 + Python 生成引擎；日期与序列号钉死） | ✅ 已落盘 |
| `plan/HANDOFF-M<k>.md` | 逐棒交接单（七节）；`plan/HANDOFF-M1.md` 已落盘 | ✅ M1 交接单已落盘 |
| `plan/RELEASE-M6.md` | 发布留档（tag 前入库；tag 后事实分栏追加） | ⬜ 待 M6 |

---

## 二、决策记录

> **D1–D5 是本题的定位生死线，任何里程碑都不得削弱。**

| 编号 | 日期 | 决策 | 理由 / 依据 |
|---|---|---|---|
| **D1** | 2026-10-20 | **最大风险不是"没人做"，而是 `ChainWarden` 77★ 已占"离线 PEM 审计"**——README **首屏必须用一句话说清差异**，且这句必须同时出现"一个 PEM 文件 vs 一台机器"与"容器别名/系统库/孤儿私钥" | ChainWarden（77★，2025-10 建仓，2026-09-03 push）用 stdlib 做了 expiry/weak/chain，且 `--as-of` 确定性已具备。它的 README 明说不验签、不查吊销、只量 RSA、不处理 P12/JKS/私钥/系统库。**差异只能建在这四条边界上**；若首屏写成"更好的证书检查工具"，读者会直接归类为 ChainWarden 的重复品。**机器断言**：`tests/test_readme.py::test_first_screen_names_the_scope_difference` |
| **D2** | 2026-10-20 | **JKS 解析是最大工程风险**（pyjks 136★，**2024-02-19 停更**）→ **MVP 走 `keytool -list -v` 输出解析**，允许 Java 依赖；`keytool` 缺失时降级为一条 `CONTAINER_UNREADABLE` 记录，**不整体失败、不静默返回空容器** | 三选一里 pyjks 停更（格式漂移无人修）、自研 JKS 解析器（私有格式 + 时间黑洞）、keytool（JDK 自带、行为稳定、输出可解析）。选 keytool，并把 Java 变成**可选依赖**：没有 JDK 的机器上，容器视图降级而不是项目不可用。**JKS/JCEKS 无 IETF 规范**，任何实现都是逆向，必须在文档里明说。 |
| **D3** | 2026-10-20 | **"RSA 2048 已不推荐"不得写成结论；必须写成带出处的可配置政策**：NIST SP 800-57 Pt1r5 表 2（2048 = 112-bit）+ SP 800-131A Rev.2 记载 "transition to a security strength of 128 bits in **2030**" + 表 4 "through 2030 acceptable / **2031 and beyond disallowed**" + CA/B TLS BR v2.3.1 §6.1.5（modulus ≥ 2048）。**默认 `WARN`，可按策略升 `ERROR`，可关闭** | 把政策写成"现在已弱"是**事实错误**（当前仍被 NIST 接受用于施加保护，只是 2031 起不允许）。错误的口径会让报告在真实环境里制造假警报，直接毁掉台账的可信度。阈值必须**带出处**，出自 `data/README.md` §数值口径单点定义。**机器断言**：策略加载器拒收空出处与非法出处形态 |
| **D4** | 2026-10-20 | **macOS 后端未实测（⬜）**——实现时**要么在真机验证后标 ✅，要么降级为 `SOURCE_UNAVAILABLE`**；不得靠"应该能用"写进 README 的能力清单 | macOS 取证书要走 `security find-certificate`（以及 `security dump-keychain` 对私钥），二进制与 keychain 分区行为在 Win/Linux 上无法验证。**未验证的能力不得对外承诺**——这既是诚实性要求，也避免 CI 上出现无法复现的差异。 |
| **D5** | 2026-10-20 | **`openssl storeutl 'org.openssl.winstore:'` 在本机返回空 → 不得当 Windows 后端**；Windows 后端走 `certutil -store <name>` 解析或 PowerShell `Cert:`（实测 Root=76、CA=5、My=0） | 实测已推翻"openssl 一站式读 Windows 存储"的设想。若沿用会在 Windows 上产出**空台账**——这比报错更危险，因为它看起来像"这台机器没有证书"。降级路径必须区分"后端不可用"与"存储真的为空"。 |

补充决策（非生死线，但影响实现一致性）：

| 编号 | 决策 | 理由 |
|---|---|---|
| D6 | 指纹**只对 DER 原始字节**做 SHA-256，**不重新编码后再哈希** | 重编码会引入解析器/版本差异，导致同一张证书在不同机器上指纹不同——台账一旦不可复算，diff 与基线全部失效。 |
| D7 | `--as-of` **必填**，不允许默认取 `now()` | wall clock 会让报告不可复现；`openssl verify -attime` 实测已证明"钉死时间"的判定可复现。 |
| D8 | 去重与孤儿判定**一律走 `spki_sha256`**，不按文件名、不按 subject 猜 | 文件名是人为产物（`server.crt` 满地都是）；subject 相同的不同密钥对是常见事故源头（同 CN 重签）。SPKI 哈希是私钥↔证书唯一的确定性连接键。 |
| D9 | 报告**不嵌入时间戳、耗时、主机名、用户名**；绝对路径默认打码 | 报告要能进 git / 进工单 / 做 baseline diff；嵌入易变字段会毁掉字节级确定性，主机名与用户名会把内网信息带出。 |
| D10 | 强度与有效期阈值**只从策略文件读**，代码零默认字面量 | 与 D3 配套：政策可变，代码不可散落魔数；策略缺失即报错，不静默取默认。 |
| D11 | 后端不可用 → 一条 `SOURCE_UNAVAILABLE`，**退出码不变** | "没看到"和"没有"必须可区分，但也不该把"这台机器没装 JDK"判成采集失败。 |
| D12 | 品牌隔离：本项目文档**不提及本系列任何其他项目**；命名避开"扫描/监控/告警"词系，用"台账/盘点"词系 | 交叉引用会污染定位与检索，也会把项目误归入监控红海。 |
| **D13** | 2026-10-20 | **解析底座 = `cryptography` ≥ 42（用户拍板）**；Python 下界 **3.10**；许可证 **MIT** | 三条是骨架级决策：解析底座决定依赖面与全部测试形态（`cryptography` 能直接拿 DER 原始字节做哈希，满足 K1，且无需自研 ASN.1）；3.10 在受众面与语法可用性之间取中；MIT 便于公司内部直接采用。被否方案与理由见 `plan/02` §三。 |
| **D14** | 2026-10-20 | **不设"未实现"退出码**：骨架期未落地能力产可见记录（`SOURCE_UNAVAILABLE` / `PARSE_UNSUPPORTED`）或由 CLI 转退出码 2，**不引入临时码** | 临时退出码退役时要四处同步（常量/分派/文档/测试），漏一处就是"文档说 4、实际不是 4"的漂移。既然骨架期就能用"可见记录 + 退出码 2"表达同一语义，就不制造需要退役的幽灵语义（`plan/06` G1）。 |

---

## 三、弃选项（做过比较后放弃，理由留档）

| 弃选项 | 为什么不做 | 处置 |
|---|---|---|
| **证书链本地验证**独立成模块 | `openssl verify -CAfile/-untrusted/-CRLfile/-crl_check_all/-attime` 已完整覆盖；**certigo 1036★ 已把 verify + lint + JSON 做完了**。首期正面撞上去，输出面还很窄（一个 pass/fail），性价比低 | **降为 `verify` 子命令（v2）**，复用 openssl 作 oracle，不自研路径验证 |
| **私钥卫生**独立成题 | 与 gitleaks 30126★ / trufflehog 28592★ 边界极易被误读成 secret scanning；且单看"权限位对不对"只是几十行脚本，撑不起一题 | **并入 `hygiene` 模块**（`PRIVATE_KEY_UNENCRYPTED` / `PERMISSION_TOO_OPEN`），价值来自"与证书配对后才知道该不该在乎" |
| **JKS/P12 别名一致性**独立成题 | 判据窄（同指纹多别名），**Keystore Explorer 2072★ 已覆盖人工查看**；JKS 无 RFC，与"规范驱动"的题面基调冲突 | **并入 `containers` 模块**，作为台账的一种来源类型 |
| **根证书库基线 diff** 独立成题 | 太薄：一次 dump + 一次 diff，撑不起四栏评分 | 作为 `report --baseline` 的一个用例场景，不单独承诺 |
| **CBOM 输出** | **cbomkit-theia 46★ 已占该形态**，且 CBOM 属 SBOM 家族，是本题明确划出的禁区（议题会被带到依赖图与供应链） | 不做。只出 JSON + Markdown 台账 |
| 远程 TLS 扫描（借道 testssl.sh） | 9241★ 已占，且与"零网络"承诺直接冲突 | 不做 |
| 常驻守护进程 / 告警推送 / Web 面板 | 会把项目推进监控红海（与 cert-manager 14120★、ssl_exporter 597★ 正面撞），也破坏"盘点一次、留一份可 diff 快照"的定位 | 不做。定位写进 `plan/01` §六 |
| 用 pyjks 作 JKS 主解析器 | 136★，**2024-02-19 停更**；私有格式的漂移无人修 | 见 D2：MVP 走 keytool；pyjks 最多作 v2 的交叉校验 oracle |
| 用 `openssl storeutl org.openssl.winstore:` 读 Windows 存储 | **本机实测返回空** | 见 D5：走 certutil / PowerShell |
| 纯 stdlib 自研 ASN.1 解析 | 解析器 bug 会直接污染指纹（K1 的失败模式是"看起来对但不可复算"），M2 要额外做逐字段对账；工期翻倍 | 见 D13：用 `cryptography` |
| `openssl` 子进程作解析层 | 每文件 fork 一次，大目录扫描慢一个量级；输出随版本漂移 | 见 D13 |
| `--format text` 终端表格 | 引入第三套渲染路径与第三套确定性测试，收益低于成本 | 待定决策 Q1（`plan/06` §四） |

---

## 四、招牌动词表（能力名词 → 交付态命令 → 断言基准）

> 写作纪律：首段/标题/定位宣言里出现的每个能力名词，两列都必须填得出；填不出的当场删词或降级 roadmap。

| 能力名词 | 哪条交付态命令产出它 | 哪条基准/测试断言它 |
|---|---|---|
| 证书台账（跨目录/容器/系统库合并） | `certledger inventory --roots <path> --json` 的 `certs[]` | `tests/test_inventory.py`：同一 DER 出现在 3 处 → 1 条记录、`sources` 长度 3 |
| 私钥↔证书配对 | `certledger inventory` 的 `keys[].paired_cert_fingerprint` | `tests/test_pairing.py`：正确配对的 SPKI 相等；同 CN 不同密钥对不误配 |
| 孤儿（有证书无私钥 / 有私钥无证书） | `certledger hygiene` 的 `ORPHAN_CERT` / `ORPHAN_KEY` | `tests/test_hygiene.py`：孤儿样本命中、非孤儿不命中 |
| 重复（同指纹多副本） | `certledger hygiene` 的 `DUPLICATE_CERT` / `DUPLICATE_KEY` | `tests/test_hygiene.py`：多副本样本 `sources` 长度 > 1 且 severity 正确 |
| 过期 / 将过期（`--as-of` 驱动） | `certledger report --as-of <ts>` 的 `EXPIRED` / `EXPIRING` | `tests/test_asof.py`：同一 fixture 在 as-of=1900000000 与 as-of=1700000000 下结论不同；缺 `--as-of` 退出码 2（**M0 已落**：`tests/test_cli.py::test_missing_as_of_is_usage_error`） |
| 到期扎堆（EXPIRY_CLIFF） | `certledger hygiene` 的 `EXPIRY_CLIFF` | `tests/test_hygiene.py`：窗口内 3 张 vs 窗口内 1 张，结论不同 |
| 密钥强度（带出处、可配置） | `certledger hygiene` 的 `WEAK_KEY` / `WEAK_SIG` + `rule_source` 字段 | `tests/test_strength.py`：策略改阈值后 severity 翻转；`rule_source` 必含 CA/B 或 NIST 节号。**M0 已落**：`tests/test_policy.py::test_uncited_threshold_is_rejected` |
| 私钥卫生（加密态 / 权限） | `certledger hygiene` 的 `PRIVATE_KEY_UNENCRYPTED` / `PERMISSION_TOO_OPEN` | `tests/test_hygiene.py`：644 私钥命中，600 不命中 |
| 容器 alias 表（P12/JKS/JCEKS） | `certledger containers --show-aliases` | `tests/test_containers.py`：多别名样本列出全部 alias；无 JDK 环境降级为 `CONTAINER_UNREADABLE` |
| 确定性报告（字节级可复现） | `certledger report --as-of <ts> --json/--markdown` | `tests/test_determinism.py`：同输入调用两次，输出 sha256 相等。**M0 已落**：`tests/test_model.py::test_dump_json_is_byte_identical_across_calls` |
| 快照 diff（新增/消失/轮换） | `certledger report --baseline prev.json` | `tests/test_baseline.py`：三类 diff 各一用例 |
| 采集残差可见（不静默） | `certledger collect` 的 `SKIP_*` / `SOURCE_UNAVAILABLE` / `PARSE_FAILED` 记录 | `tests/test_collectors.py`：路径不可读、后端缺失、坏 DER 三种输入各产一条记录且退出码 0 |
| **离线（零网络）** | 全命令 | `tests/test_architecture.py::test_no_network_imports_anywhere`（AST 守门，**M0 已落**） |
| **单一时间源** | 全命令 | `tests/test_architecture.py::test_single_clock_source`（AST 守门，**M0 已落**） |
| **方法论装订可跑红** | `tools/check-sprint-layout.py` / `tools/check-desensitized.py` | `tools/selftest-gates.py`（10 + 4 组变异，**M0 已落**） |

---

## 五、提交材料实物表（一物一证）

| 承诺项 | 应存在的文件路径 | 由哪个里程碑产出 | 核对命令 |
|---|---|---|---|
| CLI 入口 | `pyproject.toml`（`[project.scripts] certledger`）+ `src/certledger/cli.py` | M0 | `pip install -e . && certledger --help` |
| 可复现样本生成 | `fixtures/gen.sh` | M1 | `bash fixtures/gen.sh --out fixtures/out && sha256sum fixtures/out/*` |
| 依据与口径 | `data/README.md` | M0（骨架已有） | `git ls-files data/README.md` |
| 确定性基准 | `tests/test_determinism.py` | M5 | `pytest -q tests/test_determinism.py` |
| 计划文档套件 | `plan/00..06` | M0 | `py tools/check-sprint-layout.py` |
| 方法论装订 | `AGENTS.md` + `tools/check-sprint-layout.py` + `tools/check-desensitized.py` | M0 | `py tools/selftest-gates.py` |
| 发布三件套 | tag `v0.1.0` + Release 附产物 + `plan/RELEASE-M6.md` | M6 | `git tag -l` / `git cat-file -e v0.1.0:plan/RELEASE-M6.md` |
| 隐私声明 | `README.md` 首屏 | M0 | `tests/test_readme.py::test_privacy_statement_is_on_the_first_screen` |

---

## 六、承诺-证据台账（全项目唯一一份；其他文档只可引用）

| 承诺项 | 素材来源 | 当前证据 | 状态 |
|---|---|---|---|
| 方法论装订（锚点 + 两道门 + plan/00 一行） | `ai-tool-project-sprint` 硬约束③ | `AGENTS.md`、两道门、`tools/selftest-gates.py` 10+4 组变异 | ✅ 已实测 |
| 五子命令参数面完整、退出码 2 语义正确 | `plan/02` §五 | `tests/test_cli.py`（17 例） | ✅ 已实测（M0） |
| 阈值零代码字面量 + 出处强制 | CA/B TLS BR v2.3.1 §6.1.5；NIST SP 800-131A Rev.2 | `src/certledger/data/default-policy.json` + `tests/test_policy.py` | ✅ 已实测（M0） |
| `--as-of` 必填且唯一时间源 | RFC 5280 §4.1.2.5；本机 OpenSSL 实测 | `tests/test_timebase.py` + `tests/test_architecture.py::test_single_clock_source` | ✅ 已实测（M0） |
| 零网络 | — | `tests/test_architecture.py::test_no_network_imports_anywhere` | ✅ 已实测（M0） |
| 八类样本可一键重生成 + 真值可独立复算 | `plan/04` §1.1 / §二；OpenSSL 3.5.6 实测 `-not_before`/`-not_after`/`-set_serial` | `fixtures/gen.sh` + `fixtures/gen.py` + `fixtures/expected.json`；`tests/test_fixtures_truth.py`（39 例）；`gen.sh --determinism` 29 个文件字节全等 | ✅ 已实测（M1） |
| 证书/私钥/容器/系统库同表交叉引用 | 自建实现（无同类先例，见 `plan/01` §1.4） | 设计定稿于 `plan/03` §②；`model.py` 记录结构已落 | ⬜ 待 M3 验证 |
| 私钥↔证书按 SPKI 配对 | RFC 5280 §4.2.1.2 SKI / SPKI 结构 | 决策 D8 已定口径；`model.py::KeyRecord.paired_cert_fingerprint` 字段已定 | ⬜ 待 M3 验证 |
| 过期判定确定性（`--as-of`） | OpenSSL 3.5.6 实测 `verify -attime` 正确报 error 10 | `tests/test_timebase.py`（解析与边界）已落；判定本身待 M4 | ⬜ 待 M4 验证（解析已 ✅） |
| P12 可造可读 | OpenSSL 3.5.6 `pkcs12 -export/-info`（MAC=sha256、PBES2/AES-256-CBC） | 本机实测 | ✅ 已实测 |
| JKS 构建与解析可行 | JDK 26 `keytool` 可建 JKS；`cacerts` 实测为 PKCS12、150 条 trustedCertEntry | 本机实测（2026-10-20 复测 JDK 26） | ✅ 已实测 |
| JKS 解析无停更依赖风险 | pyjks 136★，2024-02-19 停更 | 决策 D2：MVP 走 keytool | ⬜ 待 M5 验证 |
| Windows 后端可读 | `Get-ChildItem Cert:\LocalMachine\Root` = 76 张；CA=5；My=0；`certutil -store Root` 可列 | 本机实测 | ✅ 已实测 |
| Windows 后端不使用 storeutl | `openssl storeutl 'org.openssl.winstore:'` 返回空 | 本机实测（否定结论） | ✅ 已实测 |
| Linux 后端可读 | `/etc/ssl/certs/ca-certificates.crt` + p11-kit `trust list` | 本机实测（WSL） | ✅ 已实测 |
| macOS 后端 | `security find-certificate` | **未实测** | ⬜ 待真机验证或降级 |
| 零依赖解析底座可选 | Node 24 `crypto.X509Certificate` 可取 validFrom/validTo/fingerprint256/modulusLength | 本机实测（取到 rsa 1024）；仅作交叉校验 | ✅ 已实测 |
| 开源空白（台账位置空着） | 十条检索式 total_count ≤ 3 或 0 | gh api 检索，窗口 2026-10-19T18:35Z–19:05Z | ⬜ 软论据 |
| ChainWarden 边界（不验签/不查吊销/只量 RSA/不处理 P12·JKS·私钥·系统库） | ChainWarden 77★ README | ✅ 逐句核对；README 首屏已按 D1 写 | ✅ 已核对 |

---

## 七、里程碑

| 里程碑 | 内容 | DoD | 状态 |
|---|---|---|---|
| **M0 骨架** | 方法论装订（`AGENTS.md` + 两道门 + `plan/00` 一行）+ `plan/00–06` + 可运行骨架（五子命令参数面 / 策略加载 / 时间基准 / 记录模型）+ CI workflow | 两道门全绿且 14 组变异全红；`pytest` 全绿；`--help` / `--version` 退出 0；非法参数退出 2；未落地能力不伪造空结果 | ✅ 已完成 |
| **M1 数据先行** | `fixtures/gen.sh` 造八类样本：健康 / 将过期 / 已过期 / 弱密钥 / 弱签名 / 多别名 / truststore 混私钥 / 孤儿私钥；样本真值 | 样本可由脚本一键重生成；日期与序列号钉死（`-not_before` / `-not_after` / `-set_serial`）；`expected.json` 只存输入与期望；**真实证书与私钥零入库** | ✅ 已完成（2026-10-21） |
| **M2 采集器** | `collectors`：递归遍历 + 内容嗅探（PEM/DER/PKCS#7/PKCS#12/JKS/JCEKS/PKCS#8/OpenSSH 公钥）+ 三平台后端可插拔 + 降级记录 | 八类格式均能识别；后端缺失产 `SOURCE_UNAVAILABLE` 且退出码 0；遍历顺序稳定；跳过的文件带原因码 | ⬜ 未开始 |
| **M3 台账** | `inventory`：统一记录模型 + 双指纹 + `sources[]` 合并 + SPKI 配对 | 同证书三处来源合并为一条；同 CN 不同密钥对不被误配；JSON 键序稳定 | ⬜ 未开始 |
| **M4 卫生规则** | `hygiene`：九类 finding + 策略文件（阈值带出处）+ `--as-of` 必填 | 每条规则有出处的 `rule_source`；无出处阈值不得生效；策略缺失报错退出 2 | ⬜ 未开始 |
| **M5 报告与容器** | `report`（JSON+Markdown、退出码、`--fail-on`、`--baseline`）+ `containers`（keytool 路线 + 降级） | 两次运行字节级相同；三类 diff 可复现；无 JDK 时容器降级不失败 | ⬜ 未开始 |
| **M6 发布** | 公开仓库发布 | **DoD 三件套**：**git tag** + **GitHub Release（附产物）** + **发布留档 `plan/RELEASE-M6.md`**；README 首屏差异句在位；`plan/00` 台账状态逐项翻转 | ⬜ 未开始 |

> **发布口径（A 方案，写死）**：M6 的 "Release 附产物" = 至少一个手工上传附件（源码包或 sdist），
> **本地留副本 + sha256 留档**，不用"源码 zipball 即产物"（B 方案）替代。
