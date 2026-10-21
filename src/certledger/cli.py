"""Command line surface.

The full parameter surface is live (``--help``, ``--version``, validation, exit
codes 0/1/2) and every subcommand answers. ``main`` remains the single place
where a raised condition becomes a process exit code: ``CliError`` → 2, and 0/1
come back from the handler that computed them.

``NotImplementedError`` is still caught, but nothing raises it any more — it is
the net under a future stage that is added to the surface before it is
implemented, so that such a stage cannot reach the user as a traceback or, far
worse, as an empty document that reads like an answer.

User-facing text must never cite internal milestone numbers: a promise written
against an internal plan goes stale the moment the plan moves (plan/06 R7).
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from certledger import __version__
from certledger.errors import EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE, CliError
from certledger.policy.loader import load_policy
from certledger.timebase import parse_as_of

PROG = "certledger"

NOT_AVAILABLE = "该能力尚未在当前版本落地"


def _add_common_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--roots",
        action="append",
        metavar="PATH",
        default=None,
        help="recursively scan this directory (repeatable)",
    )
    parser.add_argument(
        "--files",
        action="append",
        metavar="PATH",
        default=None,
        help="scan this explicit file (repeatable)",
    )
    parser.add_argument(
        "--source",
        choices=("auto", "linux", "windows", "macos", "none"),
        default="auto",
        help="which system store backend to probe (default: auto)",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=None,
        help="follow symbolic links while walking (default: off, from policy)",
    )
    parser.add_argument(
        "--policy",
        metavar="PATH",
        default=None,
        help="policy file with thresholds and citations (default: bundled)",
    )
    _add_json_option(parser)


def _add_json_option(parser: argparse.ArgumentParser) -> None:
    """``--json``, accepted **after** the subcommand as well as before it.

    The documented forms put it after (``certledger report --as-of … --json …``,
    plan/03 §④), but the global position also has to keep working. Hence
    ``SUPPRESS``: without it, the subparser's own ``None`` default would
    overwrite a value already parsed at the top level — the classic argparse
    subparser-default trap.
    """
    parser.add_argument(
        "--json",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="write machine-readable output to PATH ('-' for stdout)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Local cryptographic asset ledger: which certificates and private keys live "
            "on this machine, which pairs with which, and which nobody uses."
        ),
        epilog=(
            "CertLedger is offline by design: no network access, no telemetry. "
            "Real certificates and private keys never enter this repository."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__}",
    )
    _add_json_option(parser)

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    collect = subparsers.add_parser(
        "collect",
        help="walk paths and system stores, report what was found and what was skipped",
    )
    _add_common_inputs(collect)
    collect.add_argument("--max-size", type=int, metavar="BYTES", default=None, dest="max_size")
    collect.set_defaults(handler=_run_collect)

    inventory = subparsers.add_parser(
        "inventory",
        help="build the normalized ledger: one record per fingerprint, sources merged",
    )
    _add_common_inputs(inventory)
    inventory.set_defaults(handler=_run_inventory)

    hygiene = subparsers.add_parser(
        "hygiene",
        help="apply the rule set to the ledger and emit findings",
    )
    _add_common_inputs(hygiene)
    hygiene.add_argument("--as-of", required=True, metavar="WHEN", dest="as_of",
                         help="the only notion of 'now' (Unix seconds or ISO-8601 with offset)")
    hygiene.add_argument("--inventory", metavar="PATH", default=None,
                         help="read a previously written ledger instead of scanning")
    hygiene.set_defaults(handler=_run_hygiene)

    report = subparsers.add_parser(
        "report",
        help="render JSON + Markdown and apply the exit-code threshold",
    )
    _add_common_inputs(report)
    report.add_argument("--as-of", required=True, metavar="WHEN", dest="as_of",
                        help="the only notion of 'now' (Unix seconds or ISO-8601 with offset)")
    report.add_argument("--inventory", metavar="PATH", default=None,
                        help="read a previously written ledger instead of scanning")
    report.add_argument("--markdown", metavar="PATH", default=None,
                        help="write the human-readable report to PATH ('-' for stdout)")
    report.add_argument("--baseline", metavar="PATH", default=None,
                        help="previous report to diff against (added / removed / rotated)")
    report.add_argument("--fail-on", choices=("ERROR", "WARN", "INFO", "none"), default=None,
                        dest="fail_on", help="severity threshold for exit code 1 (default: from policy)")
    report.add_argument("--top", type=int, metavar="N", default=None,
                        help="show only the N most urgent expiries (display only)")
    report.add_argument("--no-redact", action="store_true", default=False,
                        help="do not mask absolute paths in the report")
    report.set_defaults(handler=_run_report)

    containers = subparsers.add_parser(
        "containers",
        help="list aliases and container-level signals for PKCS#12 / JKS / JCEKS",
    )
    containers.add_argument("paths", nargs="+", metavar="PATH", help="container files to inspect")
    containers.add_argument("--show-aliases", action="store_true", default=False, dest="show_aliases",
                            help="include the per-alias table")
    containers.add_argument("--password-env", metavar="VAR", default=None, dest="password_env",
                            help="read the container password from this environment variable")
    containers.add_argument("--policy", metavar="PATH", default=None,
                            help="policy file with thresholds and citations (default: bundled)")
    # ``--json`` is accepted here as well as before the subcommand: ``plan/03`` §⑤
    # documents it *after* the positional paths, and the global position keeps
    # working (see ``_add_json_option``).
    _add_json_option(containers)
    containers.set_defaults(handler=_run_containers)

    return parser


# ── validation helpers ───────────────────────────────────────────────────────


def _require_input(args: argparse.Namespace) -> None:
    if not args.roots and not args.files:
        raise CliError(
            "缺少输入",
            "至少给出一个 --roots 或 --files",
        )


def _validate(args: argparse.Namespace) -> None:
    """Checks shared by every subcommand, before any work happens.

    Deliberately ordered so that a bad argument is reported before expensive
    work starts, and so that tests can distinguish "bad input" from
    "not implemented yet".

    The ``--roots``/``--files`` requirement is gated on the subcommand actually
    *having* those inputs. ``containers`` takes positional paths instead and
    carries ``--policy``; testing for ``policy`` alone made it fall into this
    branch and raise ``AttributeError`` on a missing ``roots`` attribute — a
    traceback with exit code 1, which the exit-code contract does not allow.
    """
    has_path_inputs = hasattr(args, "roots") or hasattr(args, "files")
    if has_path_inputs:
        if not getattr(args, "inventory", None):
            _require_input(args)
        if getattr(args, "max_size", None) is not None and args.max_size < 1:
            raise CliError("--max-size 非法", "必须是正整数")
        if getattr(args, "top", None) is not None and args.top < 1:
            raise CliError("--top 非法", "必须是正整数")

    if getattr(args, "as_of", None) is not None:
        args.as_of_parsed = parse_as_of(args.as_of)

    if hasattr(args, "policy"):
        args.policy_loaded = load_policy(args.policy)


# ── handlers ─────────────────────────────────────────────────────────────────


def _run_collect(args: argparse.Namespace) -> int:
    _validate(args)
    from certledger.collectors import collect  # local import keeps --help fast

    result = collect(
        roots=args.roots or (),
        files=args.files or (),
        source=args.source,
        follow_symlinks=args.follow_symlinks,
        max_size=args.max_size,
        policy=args.policy_loaded,
    )
    return _emit(result, args)


def _run_inventory(args: argparse.Namespace) -> int:
    _validate(args)
    from certledger.inventory import build

    result = build(
        roots=args.roots or (),
        files=args.files or (),
        source=args.source,
        follow_symlinks=args.follow_symlinks,
        policy=args.policy_loaded,
    )
    return _emit(result, args)


def _run_hygiene(args: argparse.Namespace) -> int:
    _validate(args)
    from certledger.hygiene import evaluate

    result = evaluate(
        roots=args.roots or (),
        files=args.files or (),
        inventory_path=args.inventory,
        as_of=args.as_of_parsed,
        policy=args.policy_loaded,
        source=args.source,
    )
    return _emit(result, args)


def _run_report(args: argparse.Namespace) -> int:
    _validate(args)
    from certledger.pipeline import report

    return report(
        roots=args.roots or (),
        files=args.files or (),
        inventory_path=args.inventory,
        as_of=args.as_of_parsed,
        policy=args.policy_loaded,
        json_path=args.json,
        markdown_path=args.markdown,
        baseline=args.baseline,
        fail_on=args.fail_on,
        top=args.top,
        redact=not args.no_redact,
        source=args.source,
    )


def _run_containers(args: argparse.Namespace) -> int:
    _validate(args)
    from certledger.containers import inspect

    result = inspect(
        paths=args.paths,
        show_aliases=args.show_aliases,
        password_env=args.password_env,
        policy=args.policy_loaded,
        json_path=args.json,
    )
    return _emit(result, args)


def _emit(payload, args: argparse.Namespace) -> int:
    """Write a dict result through the one serialization path."""
    from certledger.model import dump_json

    text = dump_json(payload)
    target = getattr(args, "json", None)
    if target in (None, "-"):
        sys.stdout.write(text)
    else:
        _write(target, text)
        sys.stdout.write(f"wrote {target}\n")
    return EXIT_OK


def _write(path: str, text: str) -> None:
    from pathlib import Path

    try:
        Path(path).write_text(text, encoding="utf-8", newline="\n")
    except OSError as error:
        raise CliError("输出不可写", f"{path}: {error.strerror}") from None


# ── entry point ──────────────────────────────────────────────────────────────


def main(argv: Sequence[str] | None = None) -> int:
    """The single entry point for both the console script and ``python -m``."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_request:  # --help / --version / argparse errors
        code = exit_request.code
        return code if isinstance(code, int) else EXIT_USAGE

    if getattr(args, "handler", None) is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    # ``--json`` uses SUPPRESS so a subparser's own default cannot clobber a
    # value parsed at the top level. That leaves the attribute absent when the
    # option was never given; normalise it here so handlers read one shape.
    if not hasattr(args, "json"):
        args.json = None

    try:
        return args.handler(args)
    except CliError as error:
        sys.stderr.write(f"{PROG}: {error}\n")
        return EXIT_USAGE
    except NotImplementedError as error:
        detail = str(error).strip()
        sys.stderr.write(f"{PROG}: {NOT_AVAILABLE}" + (f"（{detail}）" if detail else "") + "\n")
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        sys.stderr.write(f"{PROG}: interrupted\n")
        return EXIT_USAGE


__all__ = ["main", "build_parser", "EXIT_OK", "EXIT_THRESHOLD", "EXIT_USAGE"]
