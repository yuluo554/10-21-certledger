"""Container view: alias tables and container-level signals (not implemented yet).

PKCS#12 goes through ``cryptography``; JKS/JCEKS through ``keytool -list -v``
(D2). A missing JDK degrades to one ``CONTAINER_UNREADABLE`` record and never
fails the process.
"""

from __future__ import annotations

from typing import Sequence


def inspect(
    *,
    paths: Sequence[str],
    show_aliases: bool,
    password_env: str | None,
    policy,
    json_path: str | None,
) -> dict:
    raise NotImplementedError("containers.inspect 尚未实现")
