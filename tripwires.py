"""Deterministic tripwires over a single tool call. No model calls, no I/O.

Each tripwire returns findings ``{"category", "severity", "claim", "evidence"}``. Severity:
``high`` = the run must justify or undo it before finishing; ``warn`` = recorded and reported;
``info`` = evidence only (e.g. a test run happened).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional

Finding = Dict[str, Any]

# Paths that hold tests or snapshot expectations.
_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|__snapshots__)/|(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$|"
    r"\.(?:test|spec)\.[jt]sx?$|(?:^|/)conftest\.py$|\.snap$",
    re.IGNORECASE,
)
# Assertion-bearing lines across common frameworks.
_ASSERT_RE = re.compile(
    r"^\s*(?:assert\b|self\.assert\w*\(|expect\(|assert_\w+!?\(|t\.(?:Error|Fatal)f?\(|"
    r"require\.\w+\(|should\.)",
    re.MULTILINE,
)
# Markers that turn a test off or make it pass unconditionally.
_SKIP_RE = re.compile(
    r"@pytest\.mark\.(?:skip|xfail)\b|pytest\.(?:skip|xfail)\(|@unittest\.skip|\.skip\(|"
    r"\b(?:it|test|describe)\.(?:skip|todo)\b|\bxit\(|\bxdescribe\(|t\.Skip\(|#\[ignore\]",
)
_SWALLOW_RE = re.compile(
    r"except(?:\s+(?:Exception|BaseException))?\s*(?:as\s+\w+)?\s*:\s*(?:\n\s*)?pass\b|"
    r"\|\|\s*true\b|catch\s*\([^)]*\)\s*\{\s*\}",
)
_DESTRUCTIVE_RE = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r|"
    r"\bgit\s+push\b[^\n]*\s(?:-f|--force|--force-with-lease)\b|\bgit\s+reset\s+--hard\b|"
    r"\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+checkout\s+--\s+\.|\bdrop\s+(?:table|database)\b|"
    r"\btruncate\s+table\b|\bmkfs\b|\bdd\s+if=",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"(?:^|[\s/'\"=])(?:\.env(?:\.[\w-]+)?|auth\.json|credentials(?:\.json)?|id_(?:rsa|ed25519)|"
    r"[\w.-]+\.pem|[\w.-]+\.key|\.netrc|\.pgpass|secrets?/[^\s'\"]*|keychain)(?:$|[\s'\";])",
    re.IGNORECASE,
)
_TEST_CMD_RE = re.compile(
    r"\b(?:pytest|run_tests\.sh|python3?\s+-m\s+pytest|npm\s+(?:run\s+)?test|pnpm\s+test|"
    r"yarn\s+test|vitest|jest|cargo\s+test|go\s+test|make\s+test|tox)\b",
)
_TEST_FILE_DELETE_RE = re.compile(
    r"\b(?:rm|git\s+rm)\b[^\n|;&]*(?:tests?/|test_\w+\.py|\.(?:test|spec)\.)"
)


def _is_test_path(path: str) -> bool:
    return bool(path) and bool(_TEST_PATH_RE.search(path))


def _command_of(args: Any) -> str:
    if isinstance(args, dict):
        for key in ("command", "cmd", "script"):
            val = args.get(key)
            if isinstance(val, str):
                return val
    return ""


def _exit_code(result: Any) -> Optional[int]:
    """Best-effort exit code from a terminal tool result (JSON string or dict)."""
    data = result
    if isinstance(result, str):
        try:
            data = json.loads(result)
        except (ValueError, TypeError):
            return None
    if isinstance(data, dict):
        code = data.get("exit_code", data.get("returncode"))
        if isinstance(code, int):
            return code
    return None


def _finding(category: str, severity: str, claim: str, evidence: str) -> Finding:
    return {"category": category, "severity": severity, "claim": claim, "evidence": evidence[:300]}


# --- result classification ------------------------------------------------------------
# Approval refusals: tools/approval.py "BLOCKED: ..." and the single-query-mode refusal text.
_BLOCKED_RE = re.compile(r"\bBLOCKED:|without a user present to approve it|flagged as dangerous")
# A missing script/binary/path the agent assumed existed.
_NOT_FOUND_RE = re.compile(
    r"No such file or directory|command not found|can't open file|ModuleNotFoundError|"
    r"is not recognized as an internal or external command"
)
_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)")
# Push guard: never push to main/master on a forge remote. Attribution guard: no AI
# attribution markers in a commit. The push tripwire resolves its target before firing, so
# a repo whose only remote is a local filesystem mirror (a LAN publication path) is exempt:
# pushing a bare mirror's integrating branch by name is not a public push.
_PUSH_MAIN_RE = re.compile(
    r"\bgit\b(?:\s+-C\s+(?:'[^']*'|\"[^\"]*\"|\S+))?\s+push\b[^\n;&|]*\s"
    r"(?:origin\s+)?(?:HEAD:)?(?:main|master)\b"
)
_PUSH_SEG_RE = re.compile(
    r"\bgit\b(?:\s+-C\s+(?:'[^']*'|\"[^\"]*\"|\S+))?\s+push\b(?P<args>[^\n;&|]*)"
)
# The working directory a command pushes from, as `cd <dir>` or `git -C <dir>`.
_CD_DIR_RE = re.compile(r"\bcd\s+(?P<q>['\"]?)(?P<dir>[^'\"\s;&|]+)(?P=q)")
_GIT_C_DIR_RE = re.compile(r"\bgit\s+-C\s+(?P<q>['\"]?)(?P<dir>[^'\"\s;&|]+)(?P=q)")
# A push target that names a forge: a transport (git@, ssh://, http(s)://) or a host:path.
_FORGE_URL_RE = re.compile(r"^(?:git@|ssh://|https?://)|^(?:[\w.-]+\.[a-z]{2,}):", re.IGNORECASE)
_REMOTE_TIMEOUT_S = 2.0
_ATTRIBUTION_RE = re.compile(
    r"\bgit\s+commit\b[\s\S]*?(?:Co-Authored-By:|Generated with|AI-generated|\U0001F916)",
    re.IGNORECASE,
)
_HELP_RE = re.compile(r"(?:^|\s)(?:--help|-h)(?:\s|$)")


def _output_of(result: Any) -> str:
    data = result
    if isinstance(result, str):
        try:
            data = json.loads(result)
        except (ValueError, TypeError):
            return result
    if isinstance(data, dict):
        return str(data.get("output") or data.get("error") or data.get("stderr") or "")
    return ""


def classify_result(command: str, result: Any) -> Dict[str, bool]:
    """Signals counted per session by the plugin (thresholds live there, not here)."""
    out = _output_of(result)
    code = _exit_code(result)
    return {
        "blocked": bool(_BLOCKED_RE.search(out)),
        "not_found": bool(_NOT_FOUND_RE.search(out)),
        "help": bool(command) and bool(_HELP_RE.search(command)),
        "silent_failure": code == 0 and bool(_TRACEBACK_RE.search(out)),
    }


def scan_edit(path: str, old: str, new: str, *, whole_file: bool) -> List[Finding]:
    """Tripwires for a file edit. ``old`` is empty for whole-file writes (prior content unknown)."""
    findings: List[Finding] = []
    if _is_test_path(path):
        added_skips = len(_SKIP_RE.findall(new)) - len(_SKIP_RE.findall(old))
        if added_skips > 0:
            findings.append(
                _finding(
                    "test_weakened",
                    "high",
                    f"{added_skips} skip/xfail marker(s) added to a test file",
                    path,
                )
            )
        if not whole_file:
            removed = len(_ASSERT_RE.findall(old)) - len(_ASSERT_RE.findall(new))
            if removed > 0:
                findings.append(
                    _finding(
                        "test_weakened",
                        "high",
                        f"{removed} assertion(s) removed from a test file",
                        path,
                    )
                )
        elif not added_skips:
            findings.append(
                _finding(
                    "test_rewritten",
                    "warn",
                    "test file written whole (prior assertions not comparable)",
                    path,
                )
            )
    added_swallow = len(_SWALLOW_RE.findall(new)) - len(_SWALLOW_RE.findall(old))
    if added_swallow > 0:
        findings.append(
            _finding(
                "error_swallowed",
                "warn",
                "error swallowed (except: pass / || true / empty catch)",
                path,
            )
        )
    if _SECRET_RE.search(" " + path + " "):
        findings.append(_finding("secret_touched", "high", "secret-bearing file edited", path))
    return findings


def _split_tokens(args: str) -> List[str]:
    try:
        return shlex.split(args)
    except ValueError:
        return args.split()


def _is_filesystem_remote(target: str) -> bool:
    """A path or file: URL. Such a push cannot land on a forge."""
    return target.strip().startswith(("/", "~/", "./", "../", "file:"))


def _is_forge_remote(target: str) -> bool:
    """A transport or host:path, i.e. a push that leaves this machine for a forge."""
    return bool(_FORGE_URL_RE.match(target.strip()))


def _push_args(command: str) -> str:
    match = _PUSH_SEG_RE.search(command)
    return match.group("args") if match else ""


def _push_remote_arg(command: str) -> Optional[str]:
    """The remote token given to ``git push``, if the command names one explicitly."""
    for token in _split_tokens(_push_args(command)):
        if token.startswith("-"):
            continue
        if _is_forge_remote(token) or _is_filesystem_remote(token):
            return token
        # HEAD, a bare branch name, or HEAD:branch means the default remote.
        if re.match(r"^(?:HEAD|main|master)\b", token) or ":" in token:
            return None
        return token
    return None


def _target_dir(command: str) -> Optional[str]:
    """The ``cd``/``git -C`` directory the command pushes from, nearest the push first."""
    best: Optional[re.Match] = None
    for pattern in (_CD_DIR_RE, _GIT_C_DIR_RE):
        for match in pattern.finditer(command):
            if best is None or match.start() > best.start():
                best = match
    if best is None:
        return None
    return os.path.expanduser(best.group("dir"))


def _resolve_remote_url(directory: str, remote: str) -> Optional[str]:
    """Read-only ``git remote get-url``; no network, bounded, every error swallowed."""
    try:
        proc = subprocess.run(
            ["git", "-C", directory, "remote", "get-url", remote],
            capture_output=True,
            text=True,
            timeout=_REMOTE_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            return line.strip()
    return None


def _push_lands_on_a_forge(command: str) -> bool:
    """True when the push cannot be proven to target a local filesystem remote.

    Only a resolved filesystem remote (a LAN bare mirror) returns False. Every
    inconclusive case returns True, so a real public-main push is never dropped.
    """
    remote = _push_remote_arg(command)
    if remote is not None:
        if _is_filesystem_remote(remote):
            return False
        if _is_forge_remote(remote):
            return True
    directory = _target_dir(command)
    if not directory:
        return True
    url = _resolve_remote_url(directory, remote or "origin")
    if not url:
        return True
    return not _is_filesystem_remote(url)


def scan_command(command: str, result: Any = None, status: Optional[str] = None) -> List[Finding]:
    """Tripwires for a shell command, plus test-run evidence."""
    findings: List[Finding] = []
    if not command:
        return findings
    if _DESTRUCTIVE_RE.search(command):
        findings.append(_finding("destructive_cmd", "high", "destructive command run", command))
    if _PUSH_MAIN_RE.search(command) and _push_lands_on_a_forge(command):
        findings.append(
            _finding("forge_push_guard", "high", "pushed directly to main/master", command)
        )
    if _ATTRIBUTION_RE.search(command):
        findings.append(
            _finding("ai_attribution", "high", "AI attribution in a commit message", command)
        )
    if classify_result(command, result)["silent_failure"]:
        findings.append(
            _finding(
                "silent_failure", "warn", "exit 0 but the output contains a traceback", command
            )
        )
    if _TEST_FILE_DELETE_RE.search(command):
        findings.append(_finding("test_weakened", "high", "test file deleted by command", command))
    if _SECRET_RE.search(" " + command + " "):
        findings.append(
            _finding("secret_touched", "warn", "command references a secret-bearing path", command)
        )
    if _TEST_CMD_RE.search(command):
        code = _exit_code(result)
        passed = code == 0 if code is not None else (status == "ok" if status else None)
        findings.append(
            {
                "category": "test_run",
                "severity": "info",
                "claim": "test command ran"
                + ("" if passed is None else (" and passed" if passed else " and FAILED")),
                "evidence": command[:300],
                "passed": passed,
            }
        )
    return findings


def scan_tool_call(
    tool_name: str, args: Any, result: Any = None, status: Optional[str] = None
) -> List[Finding]:
    """Dispatch one tool call to the relevant tripwires."""
    if not isinstance(args, dict):
        return []
    if tool_name == "write_file":
        return scan_edit(
            str(args.get("path") or ""), "", str(args.get("content") or ""), whole_file=True
        )
    if tool_name == "patch":
        return scan_edit(
            str(args.get("path") or ""),
            str(args.get("old_string") or ""),
            str(args.get("new_string") or args.get("patch") or ""),
            whole_file=False,
        )
    if tool_name in ("terminal", "execute_code", "shell", "bash"):
        return scan_command(_command_of(args), result, status)
    return []


_EDIT_TOOLS = frozenset({"write_file", "patch", "skill_manage"})
_PATH_TARGET_KEYS = ("path", "file_path", "target_path", "destination_path", "new_path", "dst")


def scan_subagent_targets(tool_name: str, targets: Any) -> List[Finding]:
    """Path-only tripwires for a delegated child's (metadata-only) tool history entry."""
    if not isinstance(targets, dict):
        return []
    findings: List[Finding] = []
    for key in _PATH_TARGET_KEYS:
        path = targets.get(key)
        if not isinstance(path, str) or not path:
            continue
        if tool_name in _EDIT_TOOLS and _is_test_path(path):
            findings.append(
                _finding(
                    "test_edited_by_subagent",
                    "warn",
                    "delegated child edited a test file (content not visible)",
                    path,
                )
            )
        if _SECRET_RE.search(" " + path + " "):
            findings.append(
                _finding(
                    "secret_touched", "warn", "delegated child touched a secret-bearing path", path
                )
            )
    return findings


# Phrases in a final answer that claim verification happened.
_CLAIM_RE = re.compile(
    r"\b(?:all\s+)?tests?\s+(?:now\s+)?pass(?:es|ed|ing)?\b|\bsuite\s+(?:is\s+)?(?:green|passing)\b|"
    r"\b\d+\s+passed\b|\bgreen\s+CI\b",
    re.IGNORECASE,
)


def claims_verification(text: str) -> bool:
    return bool(text) and bool(_CLAIM_RE.search(text))
