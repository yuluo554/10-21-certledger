#!/usr/bin/env python3
# ═══ 脱敏门（发布前必跑，进 CI 的 layout job） ═══
# 来源：ai-tool-project-sprint references/templates/check-desensitized.mjs（4 条规则 + 自豁免 + 占位符放行）。
#
# 为什么是门而不是发布前 grep 一次：HANDOFF 与环境坑章节每续接一轮就会被追加以本机事实，
# 本机盘符 / 用户名 / 回环代理会反复回流。门必须常驻、可跑红、按行点名。
#
# 退出码：0 零命中 / 1 有命中 / 2 用法错误。
# 变异验证见 tools/selftest-gates.py（V1–V4，每条规则一组）。

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = "tools/check-desensitized.py"

SKIP_DIRS = {
    ".git",
    ".tmp",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "dist-release",
    "node_modules",
    "fixtures/out",
}
SKIP_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".zip",
    ".gz",
    ".exe",
    ".dll",
    ".pdf",
    ".woff",
    ".woff2",
    ".pem",
    ".key",
    ".p12",
    ".jks",
}

# 规则 ①–④。占位符 `<user>` / `<repo>` / `<local-proxy>` 是脱敏后的正确写法，负向前瞻放行。
RULES = [
    (
        "absolute-session-path",
        r"\b[A-Za-z]:[\\/](?:ProgramData|Users|zcode|repos?|projects?)[\\/](?!<)",
    ),
    ("msys-user-path", r"/[a-z]/Users/(?!<)[A-Za-z0-9._-]+/"),
    ("host-username", r"\bASUS\b"),
    ("loopback-proxy", r"\b127\.0\.0\.1:\d{2,5}\b"),
]


def walk(base: Path):
    for entry in sorted(base.iterdir(), key=lambda p: p.name):
        if entry.name == ".git":
            continue
        if entry.is_dir():
            if entry.name in SKIP_DIRS:
                continue
            yield from walk(entry)
            continue
        if entry.is_file() and entry.suffix.lower() not in SKIP_EXTS:
            yield entry


def main() -> int:
    if len(sys.argv) > 1:
        sys.stderr.write("check-desensitized: 不接受参数\n")
        return 2

    hits: list[str] = []
    scanned = 0
    for path in walk(ROOT):
        rel = path.relative_to(ROOT).as_posix()
        if rel == SELF:
            continue  # 自豁免：规则本身必须写出被判据禁止的字面量
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "\u0000" in text:
            continue
        scanned += 1
        for number, line in enumerate(text.split("\n"), start=1):
            for rule_id, pattern in RULES:
                if re.search(pattern, line):
                    hits.append(f"{rel}:{number}: [{rule_id}] {line.strip()[:160]}")

    if hits:
        sys.stdout.write(f"脱敏门：{len(hits)} 处命中（扫了 {scanned} 个文本文件，豁免 {SELF}）\n")
        for hit in hits:
            sys.stdout.write(f"FAIL  {hit}\n")
        return 1
    sys.stdout.write(f"脱敏门：扫了 {scanned} 个文本文件，0 命中（豁免 {SELF}）\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
