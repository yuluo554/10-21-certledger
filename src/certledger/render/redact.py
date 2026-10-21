"""Path masking for reports: absolute paths out, actionability in.

A report is written to be published — committed, pasted into a ticket, attached
to a review. The machine-specific prefix of an absolute path is therefore the
leak: ``/home/<someone>/…`` and ``C:\\Users\\<someone>\\…`` carry a user name and
a home-directory layout, and neither is a fact about the certificate.

What is masked is decided by the path's **shape**, never by a configured prefix
(``plan/02`` §六). A prefix list would have to be maintained, and a machine whose
layout is not on the list would silently publish its full paths — the failure
mode where a privacy control is present and does nothing.

The **basename is kept**. ``<redacted>/server.pem`` still tells a reader which
file to look at, which is the whole reason the path was in the finding; the
prefix is what identified the machine, and that is what goes. A report that
said ``<redacted>`` forty times would be publishable and useless.

Nothing here judges. Masking is presentation: the ledger, the findings and the
exit code are computed from the real paths and are unaffected.
"""

from __future__ import annotations

import re
from typing import Any

#: What an absolute path looks like, by shape:
#:
#: * a drive letter (``C:\`` or ``C:/``) — Windows;
#: * a UNC share (``\\host\share``) — Windows network;
#: * a leading slash — POSIX.
#:
#: ``store:Root`` deliberately does not match: a store *name* is not a location
#: on this machine, and masking it would remove the one piece of information
#: that makes a store finding actionable.
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_UNC = re.compile(r"^\\\\[^\\]")
_POSIX = re.compile(r"^/")

MASK = "<redacted>"


def looks_absolute(text: str) -> bool:
    """True when ``text`` has the shape of an absolute path."""
    if not text:
        return False
    return bool(_WINDOWS_DRIVE.match(text) or _UNC.match(text) or _POSIX.match(text))


def mask_path(text: str) -> str:
    """Replace the directory part of an absolute path, keep the final name.

    A path with nothing but a root (``/``, ``C:\\``, ``/etc``) has no directory
    to strip and no separate file name, so it collapses to the mask alone: the
    one component it has *is* the location.
    """
    if not looks_absolute(text):
        return text
    stripped = text.rstrip("\\/")
    if not stripped:
        return MASK
    # Split at the last separator of either kind: a Windows path is not
    # guaranteed to use backslashes, and a POSIX path never does.
    cut = max(stripped.rfind("/"), stripped.rfind("\\"))
    if cut <= 0:
        return MASK
    name = stripped[cut + 1 :]
    if not name:
        return MASK
    return f"{MASK}/{name}"


def redact_absolutes(node: Any) -> Any:
    """Walk a document and mask every string that looks like an absolute path.

    Applied to the finished document rather than to chosen fields: a new field
    that happens to carry a path is then masked by default. Enumerating the
    fields that need masking is how a report starts leaking the day someone adds
    one.
    """
    if isinstance(node, str):
        return mask_path(node)
    if isinstance(node, dict):
        return {key: redact_absolutes(value) for key, value in node.items()}
    if isinstance(node, (list, tuple)):
        return [redact_absolutes(item) for item in node]
    return node


__all__ = ["MASK", "looks_absolute", "mask_path", "redact_absolutes"]
