"""Command-line interface for sigma-detection-lab.

Usage::

    python -m sigmalab.cli scan <events.jsonl> <rules_dir> [--json]

Exit status is 1 when at least one rule fires (so the command can be used
as a CI gate that fails a pipeline on detections) and 0 when nothing fires.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from . import __version__
from .engine import scan
from .rule import load_rules


def load_events(path: str | Path) -> List[Dict[str, Any]]:
    """Read events from a JSON Lines file, ignoring blank lines.

    Raises:
        FileNotFoundError: if *path* does not exist.
        ValueError: if a non-blank line is not valid JSON.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"events file not found: {file_path}")

    events: List[Dict[str, Any]] = []
    with file_path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{file_path}:{lineno}: invalid JSON: {exc}") from exc
    return events


def _summarise_event(event: Dict[str, Any]) -> str:
    """Produce a compact one-line description of an event for the table."""
    for key in ("CommandLine", "Image", "TargetUserName", "User", "EventID"):
        if key in event:
            return f"{key}={event[key]}"
    return json.dumps(event, separators=(",", ":"))


def _print_table(alerts: List[Dict[str, Any]]) -> None:
    """Render fired alerts as a plain-text table on stdout."""
    if not alerts:
        print("No rules fired.")
        return

    rows = [
        (
            alert["level"].upper(),
            alert["attack_id"] or "-",
            alert["rule_title"],
            _summarise_event(alert["event"]),
        )
        for alert in alerts
    ]
    headers = ("LEVEL", "ATT&CK", "RULE", "EVENT")
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(w, len(str(c))) for w, c in zip(widths, row)]

    def fmt(cols: Sequence[str]) -> str:
        return "  ".join(str(c).ljust(w) for c, w in zip(cols, widths))

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))
    print(f"\n{len(alerts)} alert(s) from {len({a['rule_title'] for a in alerts})} rule(s).")


def _cmd_scan(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules_dir)
    events = load_events(args.events)
    alerts = scan(events, rules)

    if args.json:
        print(json.dumps(alerts, indent=2))
    else:
        _print_table(alerts)

    return 1 if alerts else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmalab",
        description="Evaluate Sigma-style detection rules against log events.",
    )
    parser.add_argument("--version", action="version", version=f"sigmalab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan events against a directory of rules")
    scan_p.add_argument("events", help="path to a JSON Lines events file")
    scan_p.add_argument("rules_dir", help="directory containing *.yml rule files")
    scan_p.add_argument(
        "--json", action="store_true", help="emit alerts as JSON instead of a table"
    )
    scan_p.set_defaults(func=_cmd_scan)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
