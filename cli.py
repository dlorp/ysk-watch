"""Review and report on what ysk-watch has flagged.

Two jobs, both read-only over ``<HERMES_HOME>/logs/ysk-watch``:

* ``review`` walks every finding in the check logs, shows each with its stable id, and lets
  you mark it confirmed or benign. Confirmed cases can be exported as replayable fixtures so
  the tuning loop becomes a test rather than an opinion.
* ``summary --since 7d`` answers "what fired this week, on what rule, in what session, in
  what repository" without reading JSONL by hand.

Precision is measured, not described: a rule with enough reviewed findings and a low
confirmed ratio is demoted to a warning by the hook, and ``review`` prints which rules
crossed that line.

Usage (no install step required)::

    python3 /path/to/ysk-watch review --list
    python3 /path/to/ysk-watch review --id f-1a2b3c4 --mark confirmed
    python3 /path/to/ysk-watch review --export tests/fixtures/confirmed.json
    python3 /path/to/ysk-watch summary --since 7d
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from . import tripwires, ysk_config
except ImportError:  # run as a script from the repository root
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import tripwires  # type: ignore[no-redef]
    import ysk_config  # type: ignore[no-redef]

_COMMAND_TOOLS = {"terminal", "execute_code", "shell", "bash"}
_FINDING_KINDS = {
    "tripwire",
    "subagent_tripwire",
    "pre_verify_note",
    "pre_verify_block",
    "would_block",
    "diff_scan",
    "completion",
    "allowlisted",
    "justified",
}
_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)([smhdw])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}


def _finding_id(finding: Dict[str, Any], key_id: str) -> str:
    material = "|".join(
        [
            str(finding.get("category") or finding.get("rule") or ""),
            str(key_id or ""),
            str(finding.get("evidence") or ""),
        ]
    )
    return "f-" + hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()[:7]


def _short(session: str, width: int = 16) -> str:
    """Session ids are 64-hex hashes; the head is enough to find one in the log."""
    return session if len(session) <= width else session[: width - 1] + "~"


def _row(record: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    session = str(record.get("session_id") or record.get("task_id") or "")
    rule = str(finding.get("category") or finding.get("rule") or "unknown")
    return {
        "id": str(finding.get("id") or _finding_id(finding, session)),
        "rule": rule,
        "severity": str(finding.get("severity") or ""),
        "claim": str(finding.get("claim") or ""),
        "evidence": str(finding.get("evidence") or ""),
        "sample": str(finding.get("sample") or ""),
        "tool": str(finding.get("tool") or record.get("tool") or ""),
        "repo": str(record.get("repo") or ""),
        "session": session,
        "kind": str(record.get("kind") or ""),
        "report_only": bool(record.get("report_only")),
        "ts": float(record.get("ts") or 0.0),
    }


# When one finding is logged more than once (as a tripwire, then as the block it caused), the
# row keeps the most consequential outcome, so a summary counts what actually happened.
_KIND_RANK = {"pre_verify_block": 4, "would_block": 3, "completion": 2}


def iter_findings(since_seconds: Optional[float] = None) -> Iterable[Dict[str, Any]]:
    """Every logged finding, oldest first, one row per id with its strongest outcome."""
    rows: Dict[str, Dict[str, Any]] = {}
    for record in ysk_config.iter_checks(since_seconds):
        kind = str(record.get("kind") or "")
        if kind not in _FINDING_KINDS:
            continue
        findings = record.get("findings")
        if isinstance(findings, list):
            candidates = [finding for finding in findings if isinstance(finding, dict)]
        elif record.get("category"):
            candidates = [record]
        else:
            continue
        for finding in candidates:
            row = _row(record, finding)
            known = rows.get(row["id"])
            if known is None:
                rows[row["id"]] = row
                continue
            if _KIND_RANK.get(row["kind"], 0) > _KIND_RANK.get(known["kind"], 0):
                known["kind"] = row["kind"]
            for field in ("repo", "sample", "session"):
                if not known[field] and row[field]:
                    known[field] = row[field]
    return list(rows.values())


def _load_reviews() -> Dict[str, Dict[str, Any]]:
    return ysk_config.load_reviews()


def _save_reviews(reviews: Dict[str, Dict[str, Any]]) -> None:
    ysk_config.save_reviews(reviews)


def _print_precision(reviews: Dict[str, Dict[str, Any]]) -> None:
    rows = ysk_config.precision(reviews)
    if not rows:
        print("No reviewed findings yet. Mark some with --mark confirmed|benign.")
        return
    print(
        f"{'rule':32} {'confirmed':>9} {'benign':>7} {'precision':>10} {'95% interval':>13} "
        f"{'samples':>8} {'stale':>6}"
    )
    for rule in sorted(rows):
        row = rows[rule]
        value = row.get("precision")
        shown = "-" if value is None else f"{float(value):.2f}"
        interval = "-" if value is None else f"{row['lower']:.2f}-{row['upper']:.2f}"
        print(
            f"{rule:32} {row['confirmed']:>9} {row['benign']:>7} {shown:>10} {interval:>13} "
            f"{row['samples']:>8} {row['stale']:>6}"
        )
    low = ysk_config.rules_below_threshold()
    if low:
        print("\nFlagged for tuning (min_samples reached, 95% upper bound under threshold):")
        for rule in low:
            print(f"  {rule} - currently demoted to a warning")
    else:
        print("\nNo rule is below the precision threshold on current evidence.")


def _review(args: argparse.Namespace) -> int:
    reviews = _load_reviews()
    rows = list(iter_findings())
    if args.rule:
        rows = [row for row in rows if row["rule"] == args.rule]
    if args.since:
        cutoff = time.time() - _parse_since(args.since)
        rows = [row for row in rows if row["ts"] >= cutoff]

    if args.export:
        confirmed = [
            row
            for row in rows
            if (reviews.get(row["id"]) or {}).get("status") == "confirmed" and row.get("sample")
        ]
        payload = {
            "note": "Confirmed ysk-watch findings, replayable with `review --check`.",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "fixtures": [
                {
                    "rule": row["rule"],
                    "tool": row["tool"],
                    "sample": row["sample"],
                    "evidence": row["evidence"],
                    "repo": row["repo"],
                }
                for row in confirmed
            ],
        }
        path = Path(args.export).expanduser()
        if path.exists() and not args.force:
            print(f"{path} exists; pass --force to overwrite it.", file=sys.stderr)
            return 2
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        skipped = sum(
            1
            for row in rows
            if (reviews.get(row["id"]) or {}).get("status") == "confirmed" and not row.get("sample")
        )
        print(f"Wrote {len(confirmed)} fixture(s) to {path}.")
        if skipped:
            print(f"Skipped {skipped} confirmed finding(s) with no recorded input to replay.")
        return 0

    if args.check:
        return _check_fixtures(Path(args.check).expanduser())

    unmarked = [row for row in rows if row["id"] not in reviews]
    if args.mark:
        if not args.id:
            print("--mark needs one or more --id values.", file=sys.stderr)
            return 2
        by_id = {row["id"]: row for row in rows}
        for finding_id in args.id:
            row = by_id.get(finding_id)
            if row is None:
                print(f"No finding {finding_id} in the logs.", file=sys.stderr)
                return 2
            reviews[finding_id] = {
                "rule": row["rule"],
                "rule_rev": ysk_config.rule_revision(row["rule"]),
                "status": args.mark,
                "evidence": row["evidence"],
                "repo": row["repo"],
                "session": row["session"],
                "reviewed": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        _save_reviews(reviews)
        print(f"Marked {len(args.id)} finding(s) as {args.mark}.")
        _print_precision(reviews)
        return 0

    if args.list or not sys.stdin.isatty():
        if not unmarked:
            print(f"No unreviewed findings ({len(rows)} in view).")
        for row in unmarked:
            print(
                f"{row['id']}  {row['rule']:28} {row['severity']:5} "
                f"{row['repo'] or '-':16} {_short(row['session'] or '-'):16} "
                f"{row['evidence'][:80]}"
            )
        if args.list:
            _print_precision(reviews)
        return 0

    if not unmarked:
        print(f"No unreviewed findings ({len(rows)} in view).")
        _print_precision(reviews)
        return 0

    for row in unmarked:
        print("")
        print(f"{row['id']}  {row['rule']}  ({row['severity']})")
        print(f"  claim:    {row['claim']}")
        print(f"  evidence: {row['evidence'][:300]}")
        if row["repo"] or row["session"]:
            print(f"  repo:     {row['repo'] or '-'}   session: {row['session'] or '-'}")
        answer = input("  [c]onfirmed / [b]enign / [s]kip / [q]uit: ").strip().lower()
        if answer in ("q", "quit"):
            break
        if answer not in ("c", "b"):
            continue
        reviews[row["id"]] = {
            "rule": row["rule"],
            "rule_rev": ysk_config.rule_revision(row["rule"]),
            "status": "confirmed" if answer == "c" else "benign",
            "evidence": row["evidence"],
            "repo": row["repo"],
            "session": row["session"],
            "reviewed": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        _save_reviews(reviews)
    _print_precision(reviews)
    return 0


def _check_fixtures(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Cannot read {path}: {exc}", file=sys.stderr)
        return 2
    fixtures = data.get("fixtures") if isinstance(data, dict) else data
    if not isinstance(fixtures, list):
        print(f"{path} has no fixtures list.", file=sys.stderr)
        return 2
    failures = 0
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        rule = str(fixture.get("rule") or "")
        sample = str(fixture.get("sample") or "")
        if not rule or not sample:
            continue
        if str(fixture.get("tool") or "") in _COMMAND_TOOLS:
            produced = {f.get("category") for f in tripwires.scan_command(sample)}
        else:
            evidence = str(fixture.get("evidence") or "")
            produced = {f.get("category") for f in tripwires.scan_diff(sample, evidence)}
        if rule in produced:
            print(f"ok   {rule}")
        else:
            failures += 1
            print(f"FAIL {rule}: no longer fires on its recorded case")
    print(f"\n{len(fixtures) - failures}/{len(fixtures)} fixtures still fire.")
    return 1 if failures else 0


def _parse_since(value: str) -> float:
    match = _DURATION_RE.match((value or "").strip().lower())
    if not match:
        raise SystemExit(f"--since wants a duration like 7d, 24h, 30m (got {value!r})")
    return float(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def _summary(args: argparse.Namespace) -> int:
    since = _parse_since(args.since) if args.since else None
    rows = list(iter_findings(since))
    if not rows:
        print("No findings in that window.")
        return 0
    by_rule: Dict[str, int] = {}
    by_session: Dict[str, int] = {}
    by_repo: Dict[str, int] = {}
    # What each finding did. A report-only week is read off the ``would block`` line: it is
    # the number of turns enforcement would have held.
    outcomes = {"blocked": 0, "would block": 0, "posted to a task": 0, "recorded": 0}
    for row in rows:
        by_rule[row["rule"]] = by_rule.get(row["rule"], 0) + 1
        key = _short(row["session"] or "-")
        by_session[key] = by_session.get(key, 0) + 1
        repo = row["repo"] or "(not recorded)"
        by_repo[repo] = by_repo.get(repo, 0) + 1
        if row["kind"] == "pre_verify_block":
            outcomes["blocked"] += 1
        elif row["kind"] == "would_block":
            outcomes["would block"] += 1
        elif row["kind"] == "completion":
            outcomes["posted to a task"] += 1
        else:
            outcomes["recorded"] += 1
    window = f"last {args.since}" if args.since else "all time"
    print(f"ysk-watch summary - {window} - {len(rows)} finding(s)")
    top = max(1, int(args.top or 10))
    for title, counts in (
        ("by rule", by_rule),
        ("by session", by_session),
        ("by repo", by_repo),
    ):
        print(f"\n{title}:")
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        for name, count in ordered[:top]:
            print(f"  {count:>5}  {name}")
        if len(ordered) > top:
            rest = sum(count for _, count in ordered[top:])
            print(f"  {rest:>5}  ... {len(ordered) - top} more")
    print("\noutcome:")
    for name, count in outcomes.items():
        print(f"  {count:>5}  {name}")
    low = ysk_config.rules_below_threshold()
    if low:
        print("flagged for tuning: " + ", ".join(low))
    return 0


def _rules(_: argparse.Namespace) -> int:
    _print_precision(_load_reviews())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ysk-watch", description="Review and report on ysk-watch findings."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="review findings and measure rule precision")
    review.add_argument("--list", action="store_true", help="list unreviewed findings and exit")
    review.add_argument("--id", action="append", default=[], help="finding id to mark")
    review.add_argument("--mark", choices=["confirmed", "benign"], help="status to apply")
    review.add_argument("--since", help="only findings newer than this (e.g. 7d)")
    review.add_argument("--rule", help="only findings of this rule")
    review.add_argument("--export", help="write confirmed findings as replayable fixtures")
    review.add_argument("--check", help="replay a fixture file and verify each rule still fires")
    review.add_argument("--force", action="store_true", help="let --export overwrite a file")
    review.set_defaults(func=_review)

    summary = sub.add_parser("summary", help="findings by rule, session and repository")
    summary.add_argument("--since", default=None, help="window, e.g. 7d")
    summary.add_argument("--top", type=int, default=10, help="rows per section (default 10)")
    summary.set_defaults(func=_summary, since=None)

    rules = sub.add_parser("rules", help="print measured precision per rule")
    rules.set_defaults(func=_rules)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
