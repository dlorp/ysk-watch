"""Runtime configuration, per-repository allowlists and measured rule precision.

Three things live here because they are the same thing: what counts as expected.

* configuration — thresholds, protected branches, safe-delete paths and extra secret patterns
  come from ``$HERMES_HOME/config.yaml`` (``plugins.ysk_watch`` or a top-level ``ysk_watch``)
  or from the file named by ``YSK_WATCH_CONFIG``. Constants stay in the code as defaults;
  a team whose work is chattier, or whose main branch is called ``develop``, changes data.
* allowlists — an ``.ysk-watch.yaml`` at the root of the repository being edited names
  expected exceptions (a test that is skipped on one platform on purpose) with a reason.
* precision — confirmed/benign marks written by ``ysk-watch review``. A rule whose measured
  precision is under the threshold is demoted to a warning instead of being defended.

No YAML library is required: without one, the built-in defaults apply and nothing breaks.
"""

from __future__ import annotations

import fnmatch
import json
import math
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULTS: Dict[str, Any] = {
    "thresholds": {
        "repeat_command": 4,
        "help_fishing": 3,
        "approval_loop": 3,
        "missing_path_loop": 3,
        "max_aux_calls": 4,
    },
    "protected_branches": ["main", "master"],
    "safe_delete": {"names": [], "prefixes": []},
    "secret_patterns": [],
    "report_only": False,
    "justify": {"max_nudges": 3, "min_confidence": 0.7},
    "precision": {"min_samples": 5, "threshold": 0.5, "demote": True},
    "retention_days": 30,
    # What the kanban completion comment carries: "all" (high and warn), "high" (high plus how
    # the run ended), or "off".
    "completion_comment": "all",
    # Append findings still unresolved when an answer is delivered (turns that could not be held).
    "final_notice": True,
}

_CACHE: Dict[str, Any] = {
    "cfg": None,
    "stamp": None,
    "allow": {},
    "reviews": None,
    "reviews_stamp": None,
}
_ALLOW_CACHE_MAX = 32


def _home() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes"))


def log_dir() -> Path:
    return _home() / "logs" / "ysk-watch"


_MAX_YAML_BYTES = 256 * 1024


def _yaml_load(path: Path) -> Optional[Dict[str, Any]]:
    """Parse a YAML file with a safe loader, or ``None``."""
    try:
        if path.stat().st_size > _MAX_YAML_BYTES:
            return None
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return _yaml_text(text)


def _yaml_text(text: str) -> Optional[Dict[str, Any]]:
    """Parse YAML text with a safe loader, or ``None``.

    PyYAML first; Hermes itself depends on ``ruamel.yaml``, so that is the fallback a bare
    install is guaranteed to have. Both are used in safe mode only: no Python object tags.
    Callers type-check every value they use, so an alias-expanded structure never reaches
    ``str()``.
    """
    if len(text) > _MAX_YAML_BYTES:
        return None
    data: Any = None
    try:
        import yaml  # type: ignore[import-untyped]

        try:
            data = yaml.safe_load(text)
        except (yaml.YAMLError, RecursionError, ValueError):
            return None
    except ImportError:
        try:
            from ruamel.yaml import YAML  # type: ignore[import-not-found]
            from ruamel.yaml.error import YAMLError  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            data = YAML(typ="safe", pure=True).load(text)
        except (YAMLError, RecursionError, ValueError):
            return None
    return data if isinstance(data, dict) else None


def _config_path() -> Path:
    explicit = os.environ.get("YSK_WATCH_CONFIG")
    if explicit:
        return Path(os.path.expanduser(explicit))
    return _home() / "config.yaml"


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _section(data: Dict[str, Any]) -> Dict[str, Any]:
    plugins = data.get("plugins")
    if isinstance(plugins, dict) and isinstance(plugins.get("ysk_watch"), dict):
        return plugins["ysk_watch"]
    section = data.get("ysk_watch")
    return section if isinstance(section, dict) else {}


def _number(value: Any, default: Any, *, low: float, high: float, kind: type) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if not low <= value <= high:
        return default
    return kind(value)


def _strings(value: Any, default: List[str], *, limit: int = 64) -> List[str]:
    if not isinstance(value, list):
        return list(default)
    return [item for item in value if isinstance(item, str) and 0 < len(item) <= 200][:limit]


def _sanitize(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce every key to the type the hooks expect, falling back to the default per key.

    A typo in config must not raise inside a hook: a hook that raises fails open, so one bad
    value (``max_nudges: three``) would quietly turn enforcement off for every turn.
    """
    out: Dict[str, Any] = {}
    thresholds = cfg.get("thresholds") if isinstance(cfg.get("thresholds"), dict) else {}
    out["thresholds"] = {
        name: _number(thresholds.get(name), default, low=1, high=1000, kind=int)
        for name, default in DEFAULTS["thresholds"].items()
    }
    out["protected_branches"] = _strings(
        cfg.get("protected_branches"), DEFAULTS["protected_branches"]
    ) or list(DEFAULTS["protected_branches"])
    safe = cfg.get("safe_delete") if isinstance(cfg.get("safe_delete"), dict) else {}
    out["safe_delete"] = {
        "names": _strings(safe.get("names"), []),
        "prefixes": _strings(safe.get("prefixes"), []),
    }
    out["secret_patterns"] = _strings(cfg.get("secret_patterns"), [])
    out["report_only"] = cfg.get("report_only") is True
    justify = cfg.get("justify") if isinstance(cfg.get("justify"), dict) else {}
    out["justify"] = {
        "max_nudges": _number(
            justify.get("max_nudges"), DEFAULTS["justify"]["max_nudges"], low=1, high=20, kind=int
        ),
        "min_confidence": _number(
            justify.get("min_confidence"),
            DEFAULTS["justify"]["min_confidence"],
            low=0.0,
            high=1.0,
            kind=float,
        ),
    }
    limits = cfg.get("precision") if isinstance(cfg.get("precision"), dict) else {}
    out["precision"] = {
        "min_samples": _number(
            limits.get("min_samples"),
            DEFAULTS["precision"]["min_samples"],
            low=1,
            high=10_000,
            kind=int,
        ),
        "threshold": _number(
            limits.get("threshold"),
            DEFAULTS["precision"]["threshold"],
            low=0.0,
            high=1.0,
            kind=float,
        ),
        "demote": limits.get("demote") is not False,
    }
    comment = cfg.get("completion_comment")
    # YAML 1.1 reads a bare ``off`` as false and ``on`` as true.
    if comment is False:
        comment = "off"
    elif comment is True:
        comment = "all"
    out["completion_comment"] = comment if comment in ("all", "high", "off") else "all"
    out["final_notice"] = cfg.get("final_notice") is not False
    out["retention_days"] = _number(
        cfg.get("retention_days"), DEFAULTS["retention_days"], low=0, high=3650, kind=int
    )
    return out


def get() -> Dict[str, Any]:
    """The active configuration, re-read when the file changes or the env override does."""
    path = _config_path()
    override = os.environ.get("YSK_WATCH_REPORT_ONLY", "")
    try:
        stat = path.stat()
        stamp: Optional[Tuple[str, float, int, str]] = (
            str(path),
            stat.st_mtime,
            stat.st_size,
            override,
        )
    except OSError:
        stamp = (str(path), 0.0, 0, override)
    if _CACHE["cfg"] is not None and _CACHE["stamp"] == stamp:
        return _CACHE["cfg"]
    data = _yaml_load(path) or {}
    cfg = _sanitize(_merge(DEFAULTS, _section(data)))
    if override.strip().lower() in {"1", "true", "yes", "on"}:
        cfg["report_only"] = True
    elif override.strip().lower() in {"0", "false", "no", "off"}:
        cfg["report_only"] = False
    _CACHE["cfg"] = cfg
    _CACHE["stamp"] = stamp
    return cfg


def reset() -> None:
    """Drop cached configuration and allowlists (tests, and a config edit mid-session)."""
    _CACHE["cfg"] = None
    _CACHE["stamp"] = None
    _CACHE["allow"] = {}
    _CACHE["reviews"] = None
    _CACHE["reviews_stamp"] = None


def threshold(name: str) -> int:
    try:
        return int(get()["thresholds"][name])
    except (KeyError, TypeError, ValueError):
        return int(DEFAULTS["thresholds"][name])


# Rules a repository can never allowlist for itself. Claims are settled by the ledger and the
# tree, and these tripwires record something that happened (a push, a secret read, a delete,
# an attribution, an edit to the watcher's own state); a file in the watched repository is not
# allowed to say otherwise.
NOT_ALLOWLISTABLE = frozenset(
    {
        "unverified_claim",
        "stale_test_evidence",
        "truncated_result_unremarked",
        "forge_push_guard",
        "secret_touched",
        "destructive_cmd",
        "ai_attribution",
        "config_tampered",
    }
)
ALLOWLIST_FILE = ".ysk-watch.yaml"
_GIT_SHOW_TIMEOUT_S = 5.0


def _committed_allowlist(repo_root: str) -> Tuple[str, str]:
    """``(blob id, text)`` of ``.ysk-watch.yaml`` at HEAD, or empty strings.

    The committed copy, never the working tree: an exception the watched run writes and does
    not commit has no effect, and one it commits is a visible change to history.
    """

    def run(args: List[str]) -> str:
        try:
            proc = subprocess.run(
                ["git", "-C", repo_root, *args],
                capture_output=True,
                text=True,
                timeout=_GIT_SHOW_TIMEOUT_S,
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return ""
        return proc.stdout if proc.returncode == 0 else ""

    blob = run(["rev-parse", "--verify", "-q", f"HEAD:{ALLOWLIST_FILE}"]).strip()
    if not blob:
        return "", ""
    cached = _CACHE["allow"].get(blob)
    if cached is not None:
        return blob, cached
    text = run(["cat-file", "blob", blob])
    if len(_CACHE["allow"]) > _ALLOW_CACHE_MAX:
        _CACHE["allow"].clear()
    _CACHE["allow"][blob] = text
    return blob, text


def _entry(raw: Any) -> Optional[Dict[str, str]]:
    if not isinstance(raw, dict):
        return None
    rule, path, reason = raw.get("rule"), raw.get("path"), raw.get("reason")
    if not isinstance(rule, str) or not rule or len(rule) > 64 or rule.strip() in ("*", ""):
        return None
    if rule in NOT_ALLOWLISTABLE:
        return None
    if path is not None and (not isinstance(path, str) or not path.strip() or len(path) > 200):
        return None
    if reason is not None and (not isinstance(reason, str) or len(reason) > 200):
        return None
    entry = {"rule": rule.strip(), "reason": (reason or "").strip()}
    if path:
        entry["path"] = path.strip()
    return entry


def allowlist_for(repo_root: Optional[str]) -> Dict[str, Any]:
    """Expected exceptions committed in the repository being worked on.

    Returns ``{"entries": [...], "blob": <object id>}``. Each entry must name one rule (no
    ``*``), a rule outside ``NOT_ALLOWLISTABLE``, and optionally a path; malformed entries are
    ignored rather than guessed at.
    """
    if not repo_root:
        return {}
    blob, text = _committed_allowlist(repo_root)
    if not blob:
        return {}
    data = _yaml_text(text) or {}
    raw = data.get("allow")
    entries = [entry for entry in (_entry(item) for item in (raw if isinstance(raw, list) else []))]
    return {"entries": [entry for entry in entries if entry], "blob": blob}


def _matches(path_pattern: str, evidence: str) -> bool:
    """A glob over the evidence's paths, or an exact path suffix; never a substring."""
    pattern = path_pattern.strip().lstrip("./")
    if not pattern:
        return False
    for piece in re.split(r",\s*|:\s+", evidence):
        piece = piece.strip()
        if not piece:
            continue
        if piece == pattern or piece.endswith("/" + pattern):
            return True
        if fnmatch.fnmatchcase(piece, pattern) or fnmatch.fnmatchcase(piece, "*/" + pattern):
            return True
    return False


def finding_allowed(finding: Dict[str, Any], allowlist: Dict[str, Any]) -> Optional[str]:
    """The reason a finding is expected, or ``None`` when it is not allowlisted."""
    category = str(finding.get("category") or "")
    if category in NOT_ALLOWLISTABLE:
        return None
    evidence = str(finding.get("evidence") or "")
    for entry in allowlist.get("entries") or []:
        if entry.get("rule") != category:
            continue
        path_pattern = entry.get("path")
        if path_pattern and not _matches(path_pattern, evidence):
            continue
        return entry.get("reason") or f"allowlisted in {ALLOWLIST_FILE}"
    return None


# --- measured precision ---------------------------------------------------------------------
# A rule's revision is bumped whenever its matching logic changes. Review marks carry the
# revision they were made against, and only marks for the current revision count: a rule that
# was fixed after collecting benign marks must not stay demoted on evidence about the old code.
RULE_REVISIONS: Dict[str, int] = {}
_DEFAULT_REVISION = 1
_Z95 = 1.96


def rule_revision(rule: str) -> int:
    return int(RULE_REVISIONS.get(rule, _DEFAULT_REVISION))


def wilson_bounds(confirmed: int, total: int, z: float = _Z95) -> Tuple[float, float]:
    """The Wilson score interval for a proportion: honest at the small counts review produces.

    Raw precision treats 2 of 5 as 0.40; the interval says anything from 0.12 to 0.77 is
    consistent with it, which is not evidence the rule is noisy.
    """
    if total <= 0:
        return 0.0, 1.0
    p = confirmed / total
    z2 = z * z
    centre = p + z2 / (2 * total)
    spread = z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total))
    denom = 1 + z2 / total
    return max(0.0, (centre - spread) / denom), min(1.0, (centre + spread) / denom)


def reviews_path() -> Path:
    return log_dir() / "reviews.json"


def load_reviews() -> Dict[str, Dict[str, Any]]:
    """Review marks, cached by file identity: the hook grades findings on every tool call."""
    path = reviews_path()
    try:
        stat = path.stat()
        stamp: Optional[Tuple[str, int, int]] = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return {}
    if _CACHE["reviews"] is not None and _CACHE["reviews_stamp"] == stamp:
        return dict(_CACHE["reviews"])
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    reviews = data if isinstance(data, dict) else {}
    _CACHE["reviews"] = reviews
    _CACHE["reviews_stamp"] = stamp
    return dict(reviews)


def save_reviews(reviews: Dict[str, Dict[str, Any]]) -> None:
    """Write review marks atomically, so a hook reading them never sees half a file."""
    path = reviews_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # A fresh, exclusively created temp file: a planted symlink at a fixed name cannot
    # redirect the write.
    fd, tmp = tempfile.mkstemp(prefix=".reviews.", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(reviews, indent=2, sort_keys=True))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _CACHE["reviews"] = None
    _CACHE["reviews_stamp"] = None


def precision(reviews: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
    """Per-rule confirmed/benign counts, the ratio, and its 95% Wilson interval.

    Marks made against an older revision of a rule are counted in ``stale`` and left out of
    the ratio.
    """
    reviews = load_reviews() if reviews is None else reviews
    out: Dict[str, Dict[str, Any]] = {}
    for entry in reviews.values():
        if not isinstance(entry, dict):
            continue
        rule = str(entry.get("rule") or "")
        status = str(entry.get("status") or "")
        if not rule or status not in ("confirmed", "benign"):
            continue
        row = out.setdefault(rule, {"confirmed": 0, "benign": 0, "stale": 0})
        try:
            revision = int(entry.get("rule_rev") or _DEFAULT_REVISION)
        except (TypeError, ValueError):
            revision = _DEFAULT_REVISION
        if revision != rule_revision(rule):
            row["stale"] += 1
            continue
        row[status] += 1
    for row in out.values():
        total = row["confirmed"] + row["benign"]
        row["precision"] = round(row["confirmed"] / total, 3) if total else None
        low, high = wilson_bounds(row["confirmed"], total)
        row["lower"] = round(low, 3)
        row["upper"] = round(high, 3)
        row["samples"] = total
    return out


def _noisy(row: Dict[str, Any], limits: Dict[str, Any]) -> bool:
    """Demote only when even the optimistic end of the interval is under the threshold."""
    if row.get("precision") is None:
        return False
    if int(row.get("samples") or 0) < int(limits.get("min_samples") or 5):
        return False
    try:
        threshold = float(limits.get("threshold") or 0.5)
    except (TypeError, ValueError):
        threshold = 0.5
    return float(row.get("upper", 1.0)) < threshold


def apply_precision(severity: str, category: str) -> Tuple[str, bool]:
    """Demote a rule that measurement says is mostly noise.

    A rule needs ``min_samples`` reviewed findings, and the upper end of its 95% Wilson
    interval has to sit under the threshold: 0 of 5 confirmed demotes (upper 0.43), 2 of 5
    does not (upper 0.77). A watcher that silences itself on thin data is worse than a
    noisy one.
    """
    if severity != "high":
        return severity, False
    cfg = get()["precision"]
    if not cfg.get("demote", True):
        return severity, False
    row = precision().get(category)
    if not row or not _noisy(row, cfg):
        return severity, False
    return "warn", True


def rules_below_threshold(cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    limits: Dict[str, Any] = cfg or get()["precision"]
    return sorted(rule for rule, row in precision().items() if _noisy(row, limits))


# --- check-log files --------------------------------------------------------------------------

# ``checks.jsonl`` is today's log; ``checks-YYYY-MM-DD.jsonl`` is a finished day and
# ``checks-YYYY-MM-DD.N.jsonl`` a size rollover within one. ``checks.jsonl.1`` is the backup
# name older releases wrote; it is still read.
_CHECK_NAME_RE = re.compile(r"^checks(?:-(\d{4}-\d{2}-\d{2})(?:\.\d+)?)?\.jsonl(?:\.1)?$")


def check_logs() -> List[Path]:
    """Every checks log in the directory, rotated or not, oldest first."""
    directory = log_dir()
    try:
        files = [
            path
            for path in directory.iterdir()
            if not path.is_symlink() and path.is_file() and _CHECK_NAME_RE.match(path.name)
        ]
        return sorted(files, key=lambda path: path.stat().st_mtime)
    except OSError:
        return []


def prune_check_logs(now: Optional[float] = None) -> List[Path]:
    """Delete finished-day logs older than ``retention_days``; returns what was removed.

    Only dated files are candidates. Today's ``checks.jsonl`` is never touched, and a
    retention of 0 or less keeps everything.
    """
    try:
        days = int(get().get("retention_days") or 0)
    except (TypeError, ValueError):
        days = int(DEFAULTS["retention_days"])
    if days <= 0:
        return []
    cutoff = time.strftime("%Y-%m-%d", time.localtime((now or time.time()) - days * 86400))
    removed: List[Path] = []
    for path in check_logs():
        match = _CHECK_NAME_RE.match(path.name)
        stamp = match.group(1) if match else None
        if not stamp or stamp >= cutoff:
            continue
        try:
            path.unlink()
            removed.append(path)
        except OSError:
            continue
    return removed


def iter_checks(since_seconds: Optional[float] = None):
    """Yield each parsed check line, newest files last; unreadable lines are skipped."""
    cutoff = time.time() - since_seconds if since_seconds else None
    for path in check_logs():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            if cutoff is not None:
                try:
                    if float(record.get("ts") or 0) < cutoff:
                        continue
                except (TypeError, ValueError):
                    continue
            yield record
