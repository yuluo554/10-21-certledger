#!/usr/bin/env bash
# ═══ 可复现样本生成器（唯一生成入口） ═══
#
# 用法：
#   bash fixtures/gen.sh                        # 生成到 fixtures/out
#   bash fixtures/gen.sh --out <dir>            # 指定输出目录
#   bash fixtures/gen.sh --only <case>[,...]    # 只生成部分用例（不改写 expected.json 全集）
#   bash fixtures/gen.sh --check                # 重生成到临时目录并与 fixtures/expected.json 比对
#   bash fixtures/gen.sh --determinism          # 连生成两次，逐文件比 sha256
#   bash fixtures/gen.sh --help
#
# 退出码：0 成功 / 2 环境缺失或参数错误。
#
# 这一层只做两件事：**探测工具链**（缺什么就退出 2 并说清楚要什么，绝不静默降级）
# 和**找到 Python 解释器**。真正的生成逻辑在 fixtures/gen.py —— JSON 与确定性密钥
# 在 shell 里写不干净，硬写会得到一个不可审计的脚本。
#
# 样本一律现场生成，**不入库**（.gitignore 挡 fixtures/out/ 与全部证书后缀）。
# 生成出来的密钥是**公开夹具**，只用 SHA-256 计数器播种，绝不用于任何真实用途。

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_PY="${SCRIPT_DIR}/gen.py"

die() { printf 'gen.sh: %s\n' "$1" >&2; exit 2; }

case "${1:-}" in
    -h|--help)
        sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
esac

# ── ① OpenSSL ≥ 3.0 ─────────────────────────────────────────────────────────
# 证书由 `openssl ca -startdate/-enddate` 签发（日期钉死在固定值上）。这些选项
# 早于 3.0 就有；而 `req -x509` 的 `-not_before/-not_after` 要到 3.5 才出现，
# CI 的发行版镜像多为 3.0——用那条路会让样本只能装在 3.5 的机器上生成。
command -v openssl >/dev/null 2>&1 \
    || die "找不到 openssl。样本的日期与序列号要靠它钉死；请安装 OpenSSL ≥ 3.0 后重试。"

OPENSSL_VERSION="$(openssl version 2>/dev/null | awk '{print $2}')"
[ -n "${OPENSSL_VERSION}" ] || die "openssl 存在但读不出版本号；请确认 openssl 可用。"

OPENSSL_MAJOR="${OPENSSL_VERSION%%.*}"
case "${OPENSSL_MAJOR}" in
    ''|*[!0-9]*) die "无法解析 openssl 版本号：${OPENSSL_VERSION}" ;;
esac
if [ "${OPENSSL_MAJOR}" -lt 3 ]; then
    die "OpenSSL ${OPENSSL_VERSION} 太旧。需要 ≥ 3.0（3.x 才有稳定的 ca -startdate/-enddate
        与 AES-256-CBC 的 PKCS#12 导出；旧版本会让样本不可复现）。"
fi

# ── ② keytool（可选；探到就报告，探不到就明说本次跳过什么） ─────────────────
# JKS 样本需要 keytool，而 keytool 是可选依赖（plan/00 D2）：没有 JDK 的机器上
# 容器视图降级，不是项目不可用。因此这里**只探测与告知**，不退出 2。
# 注意：JDK 的 bin 目录通常不在 PATH 上（本机实测只有 java 的 shim，没有 keytool）。
find_keytool() {
    if command -v keytool >/dev/null 2>&1; then
        printf 'keytool'; return 0
    fi
    for candidate in \
        "${JAVA_HOME:+${JAVA_HOME}/bin/keytool}" \
        "/c/Program Files/Java/latest/jdk-26/bin/keytool.exe" \
        /c/Program\ Files/Java/jdk*/bin/keytool.exe
    do
        [ -n "${candidate}" ] && [ -x "${candidate}" ] && { printf '%s' "${candidate}"; return 0; }
    done
    return 1
}

if KEYTOOL_PATH="$(find_keytool)"; then
    printf 'gen.sh: keytool 可用（%s）——本次样本不含 JKS，容器路线见后续里程碑\n' "${KEYTOOL_PATH}" >&2
else
    printf 'gen.sh: 未探测到 keytool——本次跳过 JKS/JCEKS 样本（可选依赖，不失败）\n' >&2
fi

# ── ③ Python ≥ 3.10（项目下界） ─────────────────────────────────────────────
find_python() {
    for candidate in python3 python py; do
        command -v "${candidate}" >/dev/null 2>&1 || continue
        if [ "${candidate}" = "py" ]; then
            if py -3.12 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
                printf 'py -3.12'; return 0
            fi
            continue
        fi
        if "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            printf '%s' "${candidate}"; return 0
        fi
    done
    return 1
}

PYTHON="$(find_python)" || die "找不到 Python ≥ 3.10。生成器用它写 JSON、算指纹、造确定性密钥对。"

# shellcheck disable=SC2086  # PYTHON 可能是 "py -3.12" 两个词
exec ${PYTHON} -X utf8 "${GEN_PY}" "$@"
