# data/README.md — 依据查证、规范台账与数据纪律

- 状态：v1 2026-10-20（出题阶段落盘）
- **检索/查证窗口**：**2026-10-19T18:35Z – 19:05Z**。本文件所有星数、push 日期、`total_count` 均为该窗口内的检索快照；窗口外的变化不复算。
- 三态口径：✅ = 已核对原文/已实测；⬜ = 未核对/未实测/软论据。**⬜ 不得以确定语气对外表述。**

---

## 一、依据查证记录（竞品与需求原话）

### 1.1 竞品边界（✅ 星数与活跃度均为窗口内 `gh api` 实测）

| 项目 | 星数 | 活跃度 | 边界（✅ 已读 README） | 与本题关系 |
|---|---|---|---|---|
| **ChainWarden** | **77★** | 2025-10 建仓；2026-09-03 push | stdlib 离线 PEM 审计；`--as-of` 确定性；expiry / weak / chain 三项均有；**不验签、不查吊销、只量 RSA、不处理 P12/JKS/私钥/系统库** | **最大风险：已占"离线 PEM 审计"这个词。差异只能建在四条边界上**（plan/00 D1） |
| testssl.sh | **9241★** | 2026-10-18 | 远程 TLS 扫描 | 方向已占；与"零网络"冲突 |
| sslyze | 3792★ | — | 远程 TLS 扫描（Python） | 同上 |
| cfssl | 9487★ | — | 证书签发工具链 | 签发侧，不涉本地存量 |
| smallstep/certificates | 8970★ | — | 在线 CA / ACME | 同上 |
| smallstep/cli | 4353★ | — | 证书签发与操作 CLI | 同上 |
| cert-manager | **14120★** | — | K8s 证书签发/续期 | 同上 |
| openssl | 30987★ | — | 密码学底座 | `verify`/`x509`/`pkcs12`/`storeutl` 是**底座不是产品** |
| Keystore Explorer | **2072★** | — | JKS/P12 **GUI** | 要人动手点、不可 CI、无跨目录台账 |
| xca | 2022★ | — | 同类 GUI（证书/密钥管理） | 同上 |
| **square/certigo** | **1036★** | 2026-10-14 | PEM/DER/JCEKS/PKCS7/PKCS12 + lint + JSON | **最接近**；但**单文件、无目录遍历、无私钥、无去重/孤儿** |
| enix/x509-certificate-exporter | **959★** | — | 磁盘 glob + P12/JKS/JCEKS + CRL 新鲜度 | **K8s 优先、只出 Prometheus 指标**，无台账 |
| zlint | 447★ | — | Web PKI BR 合规 lint | 单证书 lint，非资产 |
| pkimetal | 131★ | — | 同上（多 linter 聚合） | 同上 |
| RaymiiOrg/certificate-expiry-monitor | 433★ | **2020-01-22 停更** | 过期监控脚本 | 停更 6 年；非台账 |
| check_ssl_cert | 418★ | — | 远程检查 + Nagios 插件 | 远程形态 |
| **cert-manage** | 32★ | 2026-09-03 | 系统信任库 list/whitelist；**自述 WIP** | 无过期、无密钥 |
| **cbomkit-theia** | 46★ | 2026-10-05 | 容器/目录内证书 + 密钥 + secret 发现，输出 **CBOM** | **形态已占（SBOM 家族），本题明确不做 CBOM** |
| cdxgen | 1090★ | — | SBOM/CBOM 生成 | 同上 |
| **pyjks** | 136★ | **2024-02-19 停更** | JKS/JCEKS/P12 解析库 | **依赖风险点**：MVP 不用它作主解析器（plan/00 D2） |
| gitleaks | 30126★ | — | 密钥泄露扫描 | 边界易误读：本题**不做** secret scanning |
| trufflehog | 28592★ | — | 同上 | 同上 |
| android-keystore-audit | 476★ | — | **Android 应用签名审计** | **是不同问题**，检索同名但对象不同 |

### 1.2 需求原话（✅ 逐条读原帖）

| 编号 | 日期 | 原话（摘） | 链接 |
|---|---|---|---|
| HN 44722816 | 2025-07-29 | "large or long-running environments rarely have clean cert inventories… **Certs embedded in keystores, containers, or staging systems that nobody owns anymore**; 'Temporary' certs that live on for years…" | <https://news.ycombinator.com/item?id=44722816> |
| HN 16544984 | 2018-03-08 | "More than one cert has expired because the guy who was maintaining them moved on and **nobody else knew how to keep them up to date**." | <https://news.ycombinator.com/item?id=16544984> |
| HN 46756301 | 2026-01-25 | "…years of dealing with SSL certificate surprises – **expired certs on subdomains nobody knew existed**, shadow IT spinning up certs, the usual 3am outages." | <https://news.ycombinator.com/item?id=46756301> |
| HN 43714094 | 2025-04-17 | "I think probably already a **double digit fraction of our infrastructure outages are due to expired certificates**." | <https://news.ycombinator.com/item?id=43714094> |
| HN 39281412 | 2024-02-06 | "The Root CA certificate, etcd certificate, and API server certificate expired… we had to **rebuild the entire cluster from scratch**." | <https://news.ycombinator.com/item?id=39281412> |
| HN 46281401 | 2025-12-15 | "Certificate rotation/renewal has been the biggest headache of my IT career. **It's always after the fact.**" | <https://news.ycombinator.com/item?id=46281401> |
| HN 29811982 | 2022-01-05 | "Venafi… tries to auto-inventory certs… **discovery was hard to tune properly to get good results**. But once you have a working inventory, lifecycle management gets easier." | <https://news.ycombinator.com/item?id=29811982> |
| ServerFault 837352 | — | "What I need is a management tool that could keep track of my cards and help to manage certificates in them, expiration date…"（2 赞，1 答；提问者自述除商业产品 Versasec 外找不到） | <https://serverfault.com/q/837352> |

### 1.3 开源空白检索式（⬜ 软论据；`gh api search/repositories`，窗口内 total_count）

| 检索式 | total_count | 该式最高星（窗口内） |
|---|---|---|
| `certificate inventory` | 231 | certmate **1470★**；KPN-CISO 16★ / 14★ |
| `cert inventory` | 90 | — |
| `certificate expiry scanner` | 15 | 最高 29★ |
| `certificate expiration monitoring` | 181 | https-ssl-cert-check-zabbix 315★；domain-monitor 263★ |
| `certificate expiry` | 761 | ssl_exporter 597★；RaymiiOrg 433★ |
| `x509 expiry` | 31 | **ChainWarden 77★**；cert_tree 32★ |
| `certificate expiry report html` | 3 | — |
| **`pem der p12 jks scan`** | **0** | — |
| **`local pki inventory`** | **0** | — |
| **`scan certs on disk`** | **0** | — |
| **`certificate hygiene cli`** | **0** | — |
| **`certificate sprawl`** | **0** | — |
| **`cert inventory filesystem`** | **0** | — |
| **`tls cert discovery filesystem`** | **0** | — |
| **`certificate deduplication fingerprint`** | **0** | — |
| **`jks truststore scanner`** | **0** | — |
| `private key permission audit` | 5 | perms-check 0★ |
| `truststore audit` | 1 | 0★ |
| `keystore audit` | 14 | android-keystore-audit 476★（**不同问题**：Android 应用签名） |
| `certificate inventory offline` | 3 | 0★ |

**判定（⬜ 软论据）**：不是"没人做过 expire check"，而是**没有一个工具把"证书 + 私钥 + 容器 + 系统库"放在同一张表里用同一套指纹交叉引用**。**台账这个位置现在空着**——文中不使用"首创/唯一/第一"。

---

## 二、规范台账（✅ 节号与原文已逐条核对）

### 2.1 X.509 / RFC 5280

| 主题 | 节号 | 本题用法 |
|---|---|---|
| Validity | §4.1.2.5 | 过期判定的唯一时间字段来源 |
| UTCTime 编码 | §4.1.2.5.1 | 解析年份映射（两位年 → 1950–2049） |
| GeneralizedTime 编码 | §4.1.2.5.2 | 2050 年后的到期必须能解析 |
| Key Usage | §4.2.1.3 | 台账列 + `KEY_USAGE_*` 提示 |
| Basic Constraints | §4.2.1.9 | 判定"是不是 CA 证书"（孤儿/根库语境） |
| Name Constraints | §4.2.1.10 | 仅台账列，首期不判 |
| SAN | §4.2.1.6 | 台账列（DNS-ID 归类） |
| EKU | §4.2.1.12 | 台账列 + 用途提示 |
| CRL Distribution Points | §4.2.1.13 | 仅记录地址（v2 离线 CRL 用） |
| Certificate Policies | §4.2.1.4 | 台账列 |
| Subject Key Identifier | §4.2.1.2 | 台账列；**配对判定仍以 SPKI SHA-256 为准**（SKI 可缺、可重复） |
| 路径验证 | §6（核心子集 §6.1.3 / §6.1.4 / §6.3.3） | **首期不做**，v2 交给 `openssl verify` |

### 2.2 密钥强度（只引两家，不自创阈值）

**CA/B Forum TLS BR v2.3.1 §6.1.5 Key sizes**（原文）：

- "Ensure that the modulus size, when encoded, is at least **2048 bits**"
- "Ensure that the key represents a valid point on the **NIST P-256, NIST P-384 or NIST P-521** elliptic curve"
- "**No other algorithms or key sizes are permitted.**"

**NIST SP 800-131A Rev.2**：

- RSA："length of the modulus n shall be **2048 bits or more** to meet the minimum security-strength requirement of **112 bits**"
- ECDSA：`len(n) ≥ 224`
- SHA-1："**disallowed** for digital signature generation"；verification 属 **legacy use**

**NIST SP 800-57 Part 1 Rev.5**：

- 表 2：RSA 2048 = **112-bit** 安全强度；
- §1.1 与 SP 800-131A Rev.2 记载：SP 800-57 Part 1 "includes a **transition to a security strength of 128 bits in 2030**"；
- 表 4（Applying protection）：112-bit 为 "**through 2030 acceptable** / **2031 and beyond disallowed**"。

> **必须精确表述的口径**：RSA 2048 在 NIST 口径下 **2031 年起不再允许用于"施加保护"**；**不是"现在已弱"**。
> 因此工具把它做成**带出处可配置策略**，默认 `WARN`（plan/00 D3）。

### 2.3 公网有效期政策（提示层，不参与本地合规判定）

CA/B Forum BR 时间表（BR.md 日期表 + §6.3.2 原文核对）：

| 生效日 | 最长有效期 |
|---|---|
| 2026-03-15 | 200 天 |
| 2027-03-15 | 100 天 |
| 2029-03-15 | 47 天 |

用途：`PUBLIC_VALIDITY_HINT` 信息级 finding。**不改变任何本地合规判定**，也不改变退出码。

### 2.4 主机名匹配

- **现行依据**：RFC 9525 §6 / §6.3（DNS-ID 匹配）。
- **废弃关系**：RFC 9525 §1 明写 "This document **obsoletes RFC 6125**"；正文指出 CN RDN **MUST NOT** 用于识别服务。
- **纪律**：本项目文档、代码注释、finding 文案**一律不得**引用 RFC 6125 §6.4.4 作现行依据。

### 2.5 编码与容器格式

| 格式 | 规范 | 备注 |
|---|---|---|
| PEM | **RFC 7468** | 多块文件逐块展开；label 不唯一可靠（`CERTIFICATE` / `PRIVATE KEY` / `RSA PRIVATE KEY` / `EC PRIVATE KEY` / `CERTIFICATE REQUEST` 等） |
| PKCS#12 | **RFC 7292** | 本机实测 `-export` 产物 MAC=sha256、PBES2/AES-256-CBC |
| EC 私钥 | **RFC 5915** | `EC PRIVATE KEY` 块 |
| 通用私钥 | **RFC 5958**（OneAsymmetricKey） | `PRIVATE KEY` 块；PKCS#8 的 IETF 化 |
| **JKS / JCEKS** | **无 IETF 规范** | **Sun 私有格式，必须明说无 RFC 依据**，只能按实现逆向（keytool 行为为准） |

### 2.6 吊销（首期不做，只记口径）

- CRL 仅从**本地** `.crl` / PEM 读（v2 用 `openssl verify -CRLfile` / `-crl_check_all`）；
- OCSP 仅接受**本地保存的 DER**（v2 用 `openssl ocsp -respin`）；
- 任何联网拉取必须显式 `--online`，**默认关闭**。

---

## 三、数据源可获取性记录

| 数据源 / 能力 | 状态 | 实测/阻断说明 | 处置 |
|---|---|---|---|
| OpenSSL **3.5.6**（造样本 + 确定性过期判定） | **✅ 已实测** | 可造自签根 + RSA1024/SHA-1 叶子；`openssl verify -attime 1900000000` 正确报 `error 10 certificate has expired`；`pkcs12 -export/-info` 可造可读 | 作 fixtures 生成器与判定 oracle |
| Node **24**（`crypto.X509Certificate`） | **✅ 已实测** | 可取 validFrom / validTo / fingerprint256 / modulusLength（实测取到 `rsa 1024`） | 仅作**交叉校验**（零依赖对照），不作主解析器 |
| JDK **24**（`keytool`） | **✅ 已实测** | 可建 JKS（自警告 "The JKS keystore uses a proprietary format"）；系统 `cacerts` 实测为 **PKCS12、150 条 trustedCertEntry** | JKS/JCEKS 的 MVP 解析路线（plan/00 D2） |
| Windows 证书存储（`certutil` / PowerShell `Cert:`） | **✅ 已实测** | `Get-ChildItem Cert:\LocalMachine\Root` = **76 张根**；CA store = 5；My = 0；`certutil -store Root` 可列 | Windows 后端 |
| `openssl storeutl 'org.openssl.winstore:'` | **✅ 已实测（否定结论）** | **本机返回空** | **不得当 Windows 后端**（plan/00 D5） |
| Linux 系统信任库 | **✅ 已实测** | `/etc/ssl/certs/ca-certificates.crt` + p11-kit `trust list` 可用 | Linux 后端 |
| **macOS**（`security find-certificate`） | **⬜ 未实测** | 本机无 mac 环境 | **实现时必须真机验证后再标 ✅，否则降级为 `SOURCE_UNAVAILABLE`**（plan/00 D4） |
| pyjks（JKS 解析库） | **✅ 已查证其停更状态** | 136★，2024-02-19 停更 | 不作主解析器；最多作 v2 交叉校验 |
| ServerFault 837352 原帖 | **✅ 已读** | 2 赞、1 答；提问者自述除 Versasec 外无适用工具 | 需求证据 |
| 八条 HN 原帖 | **✅ 已读** | 链接与摘录见 §1.2 | 需求证据 |
| ChainWarden README 边界四条 | **✅ 已逐句核对** | 不验签 / 不查吊销 / 只量 RSA / 不处理 P12·JKS·私钥·系统库 | 差异立论基础 |
| CA/B BR v2.3.1 §6.1.5 原文 | **✅ 已核对** | 见 §2.2 | 强度策略出处 |
| NIST SP 800-131A Rev.2 / SP 800-57 Pt1r5 表 2·表 4 | **✅ 已核对** | 见 §2.2 | 强度策略出处 |
| RFC 5280 §4.1.2.5 等节号 | **✅ 已核对** | 见 §2.1 | 台账字段与判定依据 |
| RFC 9525 / RFC 6125 废弃关系 | **✅ 已核对** | 见 §2.4 | 主机名匹配口径 |
| RFC 7468 / 7292 / 5915 / 5958 | **✅ 已核对** | 见 §2.5 | 编码层归类 |
| JKS/JCEKS 是否存在 RFC | **✅ 已核（结论为"无"）** | IETF 无对应规范；Sun 私有格式 | 文档必须明说，不得暗示"按标准实现" |

---

## 四、合成数据纪律

### 4.1 生成器与可复现性

- 唯一生成入口：`fixtures/gen.sh`（OpenSSL ≥ 3.0 + JDK `keytool`，可选）。
- **日期钉死**：所有证书用 `openssl ca -startdate` / `-enddate` 指定（固定基准日 + 固定偏移），**不使用相对当前时刻的默认值**。
  用 `ca` 而不是 `req -x509` 的理由：`req` 的 `-not_before/-not_after` 要到 **OpenSSL 3.5** 才有，
  而 CI 的发行版镜像多为 3.0——那条路会让样本只能在装了 3.5 的机器上生成（M6 首推实测）。
  `ca` 同时能签 SHA-1 证书，而 `cryptography` 50 拒绝用 SHA-1 签名，`weak-sig` 样本因此只能走 `ca`。
- **序列号钉死**：`openssl ca` 的序列号来自其数据库（写死初值），保证同参数多次运行产出**同指纹**证书。
- 生成参数写入 `fixtures/out/manifest.json`（每项：文件名 / 格式 / 期望结论 / 生成命令）。
- 允许的例外：PKCS#12 的 salt 与迭代随机化、JKS 容器的时间戳字段会导致**容器文件字节**不可复现——因此**基线比对的对象是台账 JSON，不是容器文件字节**（口径见 §4.4）。

### 4.2 八类样本（首期必需，缺一即 M1 未达成）

| 类别 | 期望结论 |
|---|---|
| 健康 | 无 finding（`EXPIRING` 窗口外） |
| 将过期 | `EXPIRING` |
| 已过期 | `EXPIRED`（按 `--as-of` 判定） |
| 弱密钥 | `WEAK_KEY`（RSA 1024） |
| 弱签名 | `WEAK_SIG`（SHA-1 签发） |
| 多别名 | 容器 alias 表多条；`DUPLICATE_CERT` |
| truststore 混私钥 | `CONTAINER_TRUSTSTORE_WITH_KEY` |
| 孤儿私钥 | `ORPHAN_KEY`（另造 `ORPHAN_CERT` 对侧） |

补充样本（用于规则边界，不占八类名额）：同 CN 不同密钥对（验证**不误配**）、窗口内单张到期（验证 `EXPIRY_CLIFF` 不触发）、空口令容器（`CONTAINER_EMPTY_PASSWORD`）。

### 4.3 真实资产红线

- **真实证书、真实私钥、真实 keystore/truststore 永不入库、永不入示例目录、永不入测试夹具**。
- `.gitignore` 拦截 `*.pem` / `*.key` / `*.p12` / `*.jks` / `*.jceks` / `*.pfx` / `*.der` / `*.crt` / `*.csr` 与 `fixtures/out/`。
- 若确需在仓库内保留"可读的格式样例"，只保留**公开测试向量**或**由 `gen.sh` 现场生成**的产物，不提交二进制。
- 报告不写主机名、用户名；绝对路径默认打码。

### 4.4 基线比对对象

- **比对对象 = 规范化台账 JSON + 报告 JSON/Markdown**；
- **不比对**容器文件字节（P12 salt / JKS 内部时间戳不可控）；
- 确定性断言的口径：同输入 + 同 `--as-of` → 两次运行输出 **sha256 相等**。

---

## 五、数值口径纪律（**一处定义**；plan/01、plan/00、代码注记一律引用本节）

> 以下 1–14 条只在本节定义，其他文档与代码不得手写第二口径。**代码零默认字面量**：策略缺失即报错退出（退出码 2）。

1. **`--as-of` 语义**：
   - 取值 = 一个显式时间点（UTC，接受 ISO-8601 与 Unix 秒）；
   - **必填**，无缺省值、**不允许回退到系统当前时间**；
   - 全部时效类判定（`EXPIRED` / `EXPIRING` / `EXPIRY_CLIFF`）以它为唯一"现在"；
   - 报告头部必须回显该值及其原始写法。
2. **过期判定**：
   - `EXPIRED` ⟺ `not_after < as_of`（严格小于；`not_after == as_of` 视为仍有效，边界归属一条写死）；
   - `EXPIRING` ⟺ `as_of ≤ not_after < as_of + warn_days`；`warn_days` 来自策略文件（**无代码默认值**）。
3. **`EXPIRY_CLIFF`（到期扎堆）**：
   - 定义：在 `[as_of, as_of + cliff_window_days)` 内，`EXPIRING + EXPIRED` 的**去重证书条数** ≥ `cliff_min_count`；
   - `cliff_window_days` 与 `cliff_min_count` 均来自策略文件；
   - 计数单位 = **唯一 `fingerprint_sha256`**（多副本不放大计数）。
4. **弱密钥 / 弱签名阈值**（**必须带出处**，且默认 `WARN`）：
   | 判定 | 阈值 | 出处 |
   |---|---|---|
   | `WEAK_KEY`（RSA） | `modulus_bits < 2048` | CA/B TLS BR v2.3.1 §6.1.5；NIST SP 800-131A Rev.2 |
   | `WEAK_KEY`（ECDSA） | 曲线 ∉ {P-256, P-384, P-521} | CA/B TLS BR v2.3.1 §6.1.5 |
   | `WEAK_SIG` | `signature_algorithm` 含 SHA-1 | NIST SP 800-131A Rev.2（generation disallowed；verification = legacy use） |
   | `POLICY_NIST_2031` | RSA 2048 且策略启用"2031 过渡"档 | SP 800-57 Pt1r5 表 2 / 表 4 + 800-131A Rev.2 §1.1 |
   - 每条 finding 的 `rule_source` 必须写出上表出处；
   - **禁止**把 `POLICY_NIST_2031` 表述为"当前已弱"（见 plan/01 §1.5）。
5. **私钥卫生**：
   - `PRIVATE_KEY_UNENCRYPTED` ⟺ 私钥可无口令解析成功；
   - `PERMISSION_TOO_OPEN` ⟺ POSIX mode 含 `o+r` 或 `g+r`（Windows：ACL 对 `Everyone` / `Users` 可读）——**判据写死在策略文件，代码不散落**。
6. **孤儿与配对**：
   - 配对键 = **`spki_sha256`**（私钥推导公钥 → SubjectPublicKeyInfo DER 的 SHA-256）；
   - `ORPHAN_CERT` ⟺ 存在证书，其 `spki_sha256` 无对应私钥；
   - `ORPHAN_KEY` ⟺ 存在私钥，其 `spki_sha256` 无对应证书；
   - **不按文件名、不按 subject/CN、不按 SKI 判定**（SKI 可缺、可重复；文件名是人为产物）。
7. **重复判定**：
   - `DUPLICATE_CERT` ⟺ 同一 `fingerprint_sha256` 的 `sources` 长度 > 1；
   - `DUPLICATE_KEY` ⟺ 同一 `spki_sha256` 的私钥 `sources` 长度 > 1。
8. **退出码**：
   | 码 | 含义 |
   |---|---|
   | `0` | 无 finding 达到 `--fail-on` 门槛（含"仅有 WARN/INFO"） |
   | `1` | 有 finding 达到 `--fail-on` 门槛（默认 `ERROR`） |
   | `2` | 输入/策略/参数错误（缺 `--as-of`、策略文件缺失或字段非法、根路径不可读、输出路径不可写） |
   - **后端不可用不改变退出码**（plan/00 D11）：`SOURCE_UNAVAILABLE` 是 INFO 级记录。
9. **排序**：`severity → code → subject → fingerprint`（均升序，字符串按码点比较）。报告 Markdown 与 JSON 共用同一排序。
10. **失败路径分级**：采集/容器阶段产生的每个诊断码都**必须**成为一条 finding，
   级别在策略文件 `hygiene.diagnostics.codes` 里逐条给出，未列出的码取
   同一块的 `default`。理由：只列"找到了什么"的报告，与"根本没读那台机器"的报告，
    在纸面上无法区分。`SOURCE_UNAVAILABLE` 恒 `INFO`（D11，不改变退出码）。
11. **`level: off` 的语义**：该规则**不产 finding**，但其本应产出的条数计入
    `summary.suppressed`（按码分组为 `suppressed_by_code`）。关掉一条规则必须留下痕迹，
    否则"规则被关了"与"机器上没问题"会渲染成同一份报告。
12. **severity 与阈值同源**：每条规则的 `level`（`ERROR` / `WARN` / `INFO` / `off`）
    与它的数值阈值写在策略文件的同一块里，代码不写任何默认级别。
13. **权限判据的单位**：`hygiene.permissions.max_posix_mode` 是八进制**字符串**
    （`"640"`），判定用位掩码 `actual & ~permitted & 0o777`。
    来源记录里的 `posix_mode` 由采集器在**读到文件的那一刻**取，之后不再重读——
    台账可能被另一台机器上的 `hygiene` 消费，在那里 `stat` 描述的是另一个文件系统。
    无 POSIX 模式的平台（Windows）记 `null`，该平台因此不产 `PERMISSION_TOO_OPEN`：
    **没有 mode 不等于 mode 过宽**。
14. **未知不等于弱**：`key_algo` 为空串表示"本构建解不出这个公钥算法"（本机实测 81 张
    真实存储证书里有 1 张），不是"密钥弱"；`sig_algo` 为无短名的 OID 时同样不产
    `WEAK_SIG`。规则只在**读到证据**时才断言。
15. **容器信号（口径 M5 定稿）**：容器三条 finding 只读台账 `containers[]`，判据写死在这里。
    - `CONTAINER_TRUSTSTORE_WITH_KEY` ⟺ **有私钥条目且**有非私钥条目（一个 truststore
      兼当 keystore 用；PKCS#12 侧由 bag 结构判定，JKS 侧由 `PrivateKeyEntry` 判定）；
    - `CONTAINER_EMPTY_PASSWORD` ⟺ 容器**用空口令就能打开**（`password == "empty"`）；
    - `CONTAINER_UNREADABLE` ⟺ 容器在字节上属于已知家族但打不开（无口令、口令不对、
      `keytool` 缺失/超时/非零退出），级别取 `hygiene.diagnostics.codes`。
    - **口令的读取口径**：只从**环境变量**读——变量名由 `--password-env <VAR>` 指定，
      缺省 `CERTLEDGER_CONTAINER_PASSWORD`。**不写进 argv、不落盘、不进报告**；
      报告里只有 `password ∈ {set, empty, unknown}`。
    - **除用户给的口令外只额外试空口令**（`b""` 与 `None` 两种写法，覆盖 keytool/OpenSSL
      与 `cryptography` 自造的无加密包）。**代码里没有产品默认口令、没有口令字典**：
      试"空"是判据，试"某个常见口令"是猜测，后者不进规则集。
    - **容器内的私钥记 `encrypted: true`**：它在容器里受容器口令保护，不是明文散落的文件；
      "这层保护够不够"由 `CONTAINER_EMPTY_PASSWORD` 回答，故容器来源的私钥不产
      `PRIVATE_KEY_UNENCRYPTED`。
    - **`containers[].entries[].chain_length`**：JKS/JCEKS 取 `keytool` 报的链长；
      **PKCS#12 恒为 0**——bag 结构不区分"链成员"与"外来可信证书"，把额外证书数当链长
      正是 `keytool` 在 `truststore-with-key` 上犯的错。

---

## 六、未决与待核对清单（⬜ 不得以确定语气对外）

| 项 | 状态 | 处置 |
|---|---|---|
| macOS 后端行为 | ⬜ 未实测 | 真机验证后升 ✅；否则降级 `SOURCE_UNAVAILABLE` |
| JKS 变体（BKS / UBER / JCEKS 私有扩展）覆盖度 | ⬜ 未逐一实测 | 首期只保证 keytool 能读的那些；未覆盖格式产 `CONTAINER_UNREADABLE` |
| OpenSSH 私钥（`OPENSSH PRIVATE KEY`）加密态判定细节 | ⬜ 未实测 | 首期只做格式识别与"是否加密"粗判，细节留 M2 定稿 |
| 开源空白判定 | ⬜ 软论据 | 检索式与 total_count 见 §1.3，可复算；不与硬锚点并列 |
| Windows ACL → "过宽"的映射规则 | ✅ 已定稿（2026-10-21）：**不做 ACL 判定** | 理由见下。Windows 侧不产 `PERMISSION_TOO_OPEN`，`posix_mode` 记 `null` |

### Windows ACL 为什么不做（G5 定稿）

三条理由，按分量排序：

1. **判定需要读 ACL，而 ACL 不是文件属性。** 有效权限 = 文件 DACL ∪ 父目录继承 ∪ 组成员
   展开 ∪ 拒绝项优先级，还要区分 `Everyone` / `Users` / `Authenticated Users` 的语义差别。
   在 Windows 上正确地做这件事要么走 `icacls` 输出解析（本地化排版、`(OI)(CI)` 标志、
   继承链），要么走 Win32 API（本项目零依赖底线不允许）。两条路都会把"权限过宽"变成
   一个**会误报**的判据，而误报会直接毁掉报告的可信度（这与 D3 的理由同源）。
2. **误报的代价不对称。** 一张 `C:\ProgramData` 下继承来的 `Users:R` 证书在真实环境里
   到处都是；把每一张都报成"权限过宽"会让报告淹没在一条不会有人修的 finding 里。
3. **POSIX 侧已经能给出一条可执行、可复算的判据**，而它覆盖了本项目实际跑得到的那一侧。

**因此**：`hygiene.permissions` 只在记录里存在 `posix_mode` 时判定；Windows 上前端
记 `null`，规则静默。这不是"未实现"，是**已决定不做的判据**——把它记成未验证项会让
下一棒去实现一个已经被否掉的东西。

> 若将来要做，判据必须先在 `data/README.md` 本节写下"哪些 ACL 组合算过宽"，
> 再进策略文件，再进代码——顺序不能倒（K3）。
