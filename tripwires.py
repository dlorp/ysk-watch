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
from typing import Any, Dict, List, Optional, Tuple

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
        for key in ("command", "cmd", "script", "code"):
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


def _window(text: str, start: int, end: int, *, pad: int = 90) -> str:
    """Evidence around a match with explicit offsets, so a high finding stays auditable.

    A 300-character prefix of a long command can omit the token that made the tripwire
    fire (the match may sit past the cut). Window around the match instead and record
    where it was found.
    """
    if not text:
        return ""
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    core = " ".join(text[lo:hi].split())
    lead = "..." if lo > 0 else ""
    trail = "..." if hi < len(text) else ""
    return f"[{start}:{end}] {lead}{core}{trail}"[:300]


def _match_evidence(text: str, pattern: "re.Pattern[str]") -> str:
    match = pattern.search(text)
    if not match:
        return text[:300]
    return _window(text, match.start(), match.end())


# --- result classification ------------------------------------------------------------
# Approval refusals: tools/approval.py "BLOCKED: ..." and the single-query-mode refusal text.
_BLOCKED_RE = re.compile(r"\bBLOCKED:|without a user present to approve it|flagged as dangerous")
# A missing script/binary/path the agent assumed existed.
_NOT_FOUND_RE = re.compile(
    r"No such file or directory|command not found|can't open file|ModuleNotFoundError|"
    r"is not recognized as an internal or external command"
)
_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)")
# Host truncation markers. When a result was cut, a claim of completeness later in the
# turn is about the visible slice, not the whole output.
_TRUNCATED_RE = re.compile(
    r"OUTPUT TRUNCATED|truncation_note|next_offset|full output \(\d+ chars\) saved to|"
    r"output_total_chars",
    re.IGNORECASE,
)
_SAVED_OUTPUT_RE = re.compile(r"(?:saved to|full output)[^\n]*?(/[\w./@+-]+\.log)")
# A final answer that claims it covered everything.
_COMPLETE_RE = re.compile(r"\b(?:all|every|entire|full|complete|exhaustive)\b", re.IGNORECASE)
# ...unless it says it did not.
_PARTIAL_RE = re.compile(
    r"\b(?:partial(?:ly)?|excerpt|sample|subset|not exhaustive|truncated|the first \d+)\b",
    re.IGNORECASE,
)
_DOC_PATH_RE = re.compile(
    r"\.(?:md|rst|txt|adoc|markdown)$|(?:^|/)docs?/|(?:^|/)CHANGELOG", re.IGNORECASE
)
# Push guard: never push to main/master on a forge remote.
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
        "truncated": bool(_TRUNCATED_RE.search(out)),
    }


def _saved_output_path(output: str) -> Optional[str]:
    """The on-disk path the host reported for a truncated result, if it named one."""
    match = _SAVED_OUTPUT_RE.search(output or "")
    return match.group(1) if match else None


def claims_completeness(text: str) -> bool:
    """True when the text asserts it covered everything and does not qualify that."""
    if not text or _PARTIAL_RE.search(text):
        return False
    return bool(_COMPLETE_RE.search(text))


def is_doc_path(path: str) -> bool:
    return bool(path) and bool(_DOC_PATH_RE.search(path))


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


def _is_filesystem_remote(target: str) -> bool:
    """A path or file: URL. Such a push cannot land on a forge."""
    return target.strip().startswith(("/", "~/", "./", "../", "file:"))


def _is_forge_remote(target: str) -> bool:
    """A transport or host:path, i.e. a push that leaves this machine for a forge."""
    return bool(_FORGE_URL_RE.match(target.strip()))


def _segments(command: str) -> List[str]:
    """Split a compound shell command on ``;``, ``&&``, ``||``, ``|`` and newlines.

    A push is resolved within its own segment, so the directory that matters is the one
    in effect at the push, not the last ``cd`` anywhere in the string.
    """
    segments: List[str] = []
    buf: List[str] = []
    quote = ""
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in ";|&\n":
            segments.append("".join(buf))
            buf = []
            while i < len(command) and command[i] in ";|&\n":
                i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


_ASSIGN_RE = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$", re.DOTALL)
_VAR_RE = re.compile(
    r"\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?P<plain>[A-Za-z_][A-Za-z0-9_]*)"
)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_PREFIX_WORDS = frozenset({"env", "sudo", "time", "command", "nohup", "nice"})


def _expand(token: str, env: Dict[str, str]) -> str:
    def repl(match: "re.Match[str]") -> str:
        name = match.group("braced") or match.group("plain")
        return env.get(name, match.group(0))

    return _VAR_RE.sub(repl, token)


def _tokens(segment: str) -> List[str]:
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return segment.split()


def _git_subcommand(
    tokens: List[str], start: int
) -> Tuple[Optional[str], List[str], Optional[str]]:
    """From a ``git`` token: (subcommand, remaining args, ``-C`` directory)."""
    directory: Optional[str] = None
    i = start + 1
    while i < len(tokens):
        token = tokens[i]
        if token == "-C" and i + 1 < len(tokens):
            directory = tokens[i + 1]
            i += 2
            continue
        if token in ("-c", "--git-dir", "--work-tree", "-C"):
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        return token, tokens[i + 1 :], directory
    return None, [], directory


_MAIN_REF_RE = re.compile(r"^\+?(?:HEAD:)?(?:refs/heads/)?(?:main|master)$")
_PUSH_DEFAULT_REMOTE = "origin"


def _push_invocations(command: str) -> List[Dict[str, Any]]:
    """Every real ``git push`` in the command, with the working directory at that push.

    Walks segments left to right, tracking ``cd`` and ``VAR=value`` assignments, expanding
    variables before use. Quoted text is not a command: ``echo "git push origin main"``
    yields nothing, while ``bash -c "git push origin main"`` is followed into its payload.
    """
    found: List[Dict[str, Optional[str]]] = []
    env: Dict[str, str] = {}
    cwd: Optional[str] = None
    for segment in _segments(command):
        tokens = _tokens(segment)
        if not tokens:
            continue
        # Carry assignments forward; a push later in the command sees them.
        idx = 0
        while idx < len(tokens):
            assign = _ASSIGN_RE.match(tokens[idx])
            if not assign:
                break
            env[assign.group("name")] = _expand(assign.group("value"), env)
            idx += 1
        if idx >= len(tokens):
            continue
        tokens = tokens[idx:]
        head = os.path.basename(_expand(tokens[0], env))
        if head == "cd" and len(tokens) > 1:
            cwd = os.path.expanduser(_expand(tokens[1], env))
            continue
        if head in _SHELLS and "-c" in tokens[1:]:
            pos = tokens.index("-c")
            found.extend(_push_invocations(" ".join(tokens[pos + 1 :])))
            continue
        while tokens and tokens[0] in _PREFIX_WORDS:
            tokens = tokens[1:]
        if not tokens or os.path.basename(_expand(tokens[0], env)) != "git":
            continue
        sub, args, dash_c = _git_subcommand(tokens, 0)
        here = cwd
        if dash_c:
            here = os.path.expanduser(_expand(dash_c, env))
        if sub != "push":
            continue
        remote: Optional[str] = None
        refs: List[str] = []
        for token in args:
            token = _expand(token, env)
            if token.startswith("-"):
                continue
            if remote is None and not _MAIN_REF_RE.match(token) and ":" not in token:
                remote = token
                continue
            refs.append(token)
        found.append({"directory": here, "remote": remote, "refs": refs})
    return found


def _push_targets_main(invocation: Dict[str, Optional[str]]) -> bool:
    refs = invocation.get("refs") or []
    return any(_MAIN_REF_RE.match(str(ref)) for ref in refs)


def _push_lands_on_a_forge(directory: Optional[str], remote: Optional[str]) -> bool:
    """True when the push cannot be proven to target a local filesystem remote.

    Only a resolved filesystem remote (a LAN bare mirror) returns False. Every
    inconclusive case returns True, so a real public-main push is never dropped.
    """
    if remote is not None:
        if _is_filesystem_remote(remote):
            return False
        if _is_forge_remote(remote):
            return True
    here = directory or os.getcwd()
    url = _resolve_remote_url(here, remote or _PUSH_DEFAULT_REMOTE)
    if not url:
        return True
    return not _is_filesystem_remote(url)


# --- destructive commands graded by target --------------------------------------------
# Deleting a cache, temp, build or workspace path is housekeeping; deleting a repository,
# a home directory or an unexpanded path is not. Severity follows the target, not the verb.
_SAFE_DELETE_SEGMENTS = frozenset(
    {
        ".cache",
        "cache",
        "caches",
        ".tmp",
        "tmp",
        "temp",
        ".temp",
        "scratch",
        ".scratch",
        "workspace",
        "workspaces",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "__pycache__",
        "node_modules",
        ".tox",
        "dist",
        "build",
        ".build",
        "target",
    }
)
_SAFE_DELETE_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/")
_REPO_DESTRUCTIVE_RE = re.compile(
    r"\bgit\s+push\b[^\n;&|]*\s(?:-f|--force|--force-with-lease)\b|\bgit\s+reset\s+--hard\b|"
    r"\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+checkout\s+--\s+\.|\bdrop\s+(?:table|database)\b|"
    r"\btruncate\s+table\b|\bmkfs\b|\bdd\s+if=",
    re.IGNORECASE,
)


def _delete_targets(command: str) -> List[str]:
    """Targets of every ``rm`` in the command, variables left unexpanded on purpose."""
    targets: List[str] = []
    for segment in _segments(command):
        tokens = _tokens(segment)
        for i, token in enumerate(tokens):
            if os.path.basename(token) != "rm":
                continue
            for arg in tokens[i + 1 :]:
                if arg.startswith("-"):
                    continue
                targets.append(os.path.expanduser(arg))
    return targets


def _is_scratch_target(target: str) -> bool:
    if not target or "$" in target:
        return False
    if target.startswith(_SAFE_DELETE_PREFIXES):
        return True
    text = target.rstrip("/")
    if ".hermes" in text and any(
        part in text for part in ("/cache", "/logs", "/workspaces", "/scratch")
    ):
        return True
    return any(part in _SAFE_DELETE_SEGMENTS for part in text.replace("\\", "/").split("/"))


def _destructive_findings(command: str) -> List[Finding]:
    findings: List[Finding] = []
    if not _DESTRUCTIVE_RE.search(command):
        return findings
    rm_hit = re.search(r"\brm\s+-[a-zA-Z]*[rf]", command)
    repo_hit = _REPO_DESTRUCTIVE_RE.search(command)
    if rm_hit:
        targets = _delete_targets(command)
        if targets and all(_is_scratch_target(t) for t in targets):
            findings.append(
                _finding(
                    "destructive_cmd",
                    "info",
                    "recursive delete inside a scratch, cache or build path",
                    _window(command, rm_hit.start(), rm_hit.end()),
                )
            )
        else:
            findings.append(
                _finding(
                    "destructive_cmd",
                    "high",
                    "destructive command run",
                    _window(command, rm_hit.start(), rm_hit.end()),
                )
            )
    if repo_hit:
        findings.append(
            _finding(
                "destructive_cmd",
                "high",
                "destructive command run",
                _window(command, repo_hit.start(), repo_hit.end()),
            )
        )
    return findings


def scan_command(command: str, result: Any = None, status: Optional[str] = None) -> List[Finding]:
    """Tripwires for a shell command, plus test-run evidence."""
    findings: List[Finding] = []
    if not command:
        return findings
    findings.extend(_destructive_findings(command))
    for invocation in _push_invocations(command):
        if not _push_targets_main(invocation):
            continue
        directory = invocation.get("directory")
        remote = invocation.get("remote")
        if not _push_lands_on_a_forge(directory, remote):
            continue
        match = re.search(r"\bgit\b[\s\S]*?\bpush\b", command)
        evidence = _window(command, match.start(), match.end()) if match else command
        findings.append(
            _finding("forge_push_guard", "high", "pushed directly to main/master", evidence)
        )
        break
    if _ATTRIBUTION_RE.search(command):
        findings.append(
            _finding(
                "ai_attribution",
                "high",
                "AI attribution in a commit message",
                _match_evidence(command, _ATTRIBUTION_RE),
            )
        )
    signals = classify_result(command, result)
    if signals["silent_failure"]:
        findings.append(
            _finding(
                "silent_failure",
                "warn",
                "exit 0 but the output contains a traceback",
                _match_evidence(command, _TRACEBACK_RE),
            )
        )
    if signals["truncated"]:
        output = _output_of(result)
        saved = _saved_output_path(output)
        findings.append(
            _finding(
                "truncated_result",
                "info",
                "tool result was truncated by the host"
                + (f"; full output saved to {saved}" if saved else ""),
                _match_evidence(output, _TRUNCATED_RE),
            )
        )
        if saved:
            findings[-1]["saved_path"] = saved
    if _TEST_FILE_DELETE_RE.search(command):
        findings.append(
            _finding(
                "test_weakened",
                "high",
                "test file deleted by command",
                _match_evidence(command, _TEST_FILE_DELETE_RE),
            )
        )
    if _SECRET_RE.search(" " + command + " "):
        findings.append(
            _finding(
                "secret_touched",
                "warn",
                "command references a secret-bearing path",
                _match_evidence(command, _SECRET_RE),
            )
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
