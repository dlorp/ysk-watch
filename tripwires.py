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
_SECRET_RE = re.compile(
    r"(?:^|[\s/'\"=])(?:\.env(?:\.[\w-]+)?|auth\.json|credentials(?:\.json)?|id_(?:rsa|ed25519)|"
    r"[\w.-]+\.pem|[\w.-]+\.key|\.netrc|\.pgpass|secrets?/[^\s'\"]*|keychain)(?:$|[\s'\";])",
    re.IGNORECASE,
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
_ATTRIBUTION_MARKER_RE = re.compile(
    r"Co-Authored-By:|Generated with|AI-generated|\U0001F916", re.IGNORECASE
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


def _diff_line_text(line: str) -> str:
    return line[1:] if line[:1] in ("+", "-") else line


def diff_path(diff: str) -> str:
    """The path a unified diff writes to, if it names one."""
    for line in (diff or "").splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target.startswith("b/"):
                target = target[2:]
            return target
    return ""


def scan_diff(diff: str, path: str = "") -> List[Finding]:
    """Tripwires for a unified diff: a removed assertion matters as much as an added skip."""
    added = [
        _diff_line_text(line)
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    removed = [
        _diff_line_text(line)
        for line in diff.splitlines()
        if line.startswith("-") and not line.startswith("---")
    ]
    added_text = "\n".join(added)
    removed_text = "\n".join(removed)
    findings: List[Finding] = []
    evidence = path or "unified diff"
    added_skips = len(_SKIP_RE.findall(added_text))
    if added_skips > 0:
        findings.append(
            _finding(
                "test_weakened",
                "high",
                f"{added_skips} skip/xfail marker(s) added to a test file",
                evidence,
            )
        )
    removed_asserts = len(_ASSERT_RE.findall(removed_text))
    if removed_asserts > 0:
        findings.append(
            _finding(
                "test_weakened",
                "high",
                f"{removed_asserts} assertion(s) removed from a test file",
                evidence,
            )
        )
    added_swallow = len(_SWALLOW_RE.findall(added_text))
    if added_swallow > 0:
        findings.append(
            _finding(
                "error_swallowed",
                "warn",
                "error swallowed (except: pass / || true / empty catch)",
                evidence,
            )
        )
    return findings


def scan_edit(path: str, old: str, new: str, *, whole_file: bool, diff: str = "") -> List[Finding]:
    """Tripwires for a file edit. ``old`` is empty for whole-file writes (prior content unknown).

    A patch tool may send a unified diff instead of an ``old``/``new`` pair; then the diff is
    the only honest view of what changed, and a removed ``-@pytest.mark.skip`` line must not
    look like an added one.
    """
    if diff:
        target = path or diff_path(diff)
        findings = scan_diff(diff, target)
        if target and _SECRET_RE.search(" " + target + " "):
            findings.append(
                _finding("secret_touched", "high", "secret-bearing file edited", target)
            )
        return findings
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


def _segments_with_ops(command: str) -> List[Tuple[str, str]]:
    """Split a compound shell command, keeping the operator that introduced each segment.

    The operator matters: a test run piped into ``tail`` or followed by ``|| true`` has no
    usable exit status, so an exit code of 0 from such a chain is not passing evidence.
    """
    segments: List[Tuple[str, str]] = []
    buf: List[str] = []
    op = ""
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
            start = i
            while i < len(command) and command[i] in ";|&\n":
                i += 1
            text = "".join(buf).strip()
            if text:
                segments.append((text, op))
            op = command[start:i]
            buf = []
            continue
        buf.append(ch)
        i += 1
    text = "".join(buf).strip()
    if text:
        segments.append((text, op))
    return segments


def _segments(command: str) -> List[str]:
    """Split a compound shell command on ``;``, ``&&``, ``||``, ``|`` and newlines.

    A push is resolved within its own segment, so the directory that matters is the one
    in effect at the push, not the last ``cd`` anywhere in the string.
    """
    return [text for text, _op in _segments_with_ops(command)]


def strip_quotes(command: str) -> str:
    """The command with quoted spans removed.

    Quoted text is data, not syntax: ``grep -rn 'git reset --hard' docs/`` and a commit
    message that mentions a destructive command are not destructive commands.
    """
    out: List[str] = []
    quote = ""
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == quote:
                quote = ""
                out.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# --- redaction ---------------------------------------------------------------------------
# Token shapes and KEY=value assignments that must never reach the ledger or the model.
_REDACT_RULES: Tuple[Tuple["re.Pattern[str]", str], ...] = (
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=\-]{8,}"), r"\1 «redacted»"),
    (re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_\-]{8,}"), "«redacted»"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}"), "«redacted»"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{10,}"), "«redacted»"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}\b"), "«redacted»"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"), "«redacted»"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{8,}"), "«redacted»"),
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|token|secret|password|passwd|pwd|"
            r"credential)[A-Za-z0-9_-]*)\s*[:=]\s*[\"']?([^\s\"',;&]{4,})"
        ),
        r"\1=«redacted»",
    ),
)
_ALREADY_REDACTED_RE = re.compile(r"«redacted[^»]*»")


def redact(text: str) -> str:
    """Strip credentials from any text bound for disk or for a model provider.

    Runs on the way in, not at display time: once a token is in ``checks.jsonl`` it is on
    disk, and once it is in the aux payload the provider has it.
    """
    if not text:
        return text
    out = _ALREADY_REDACTED_RE.sub("«redacted»", text)
    for pattern, repl in _REDACT_RULES:
        out = pattern.sub(repl, out)
    return out


def redact_obj(value: Any) -> Any:
    """``redact`` applied recursively to a JSON-shaped value."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_obj(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_obj(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_obj(item) for item in value)
    return value


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


_MAIN_BRANCHES = frozenset({"main", "master"})
_PUSH_DEFAULT_REMOTE = "origin"


def _ref_destination(ref: str) -> str:
    """The branch a refspec writes to: ``feature:main`` writes to ``main``."""
    text = ref.strip().lstrip("+")
    destination = text.split(":")[-1] if ":" in text else text
    destination = destination.strip()
    if destination.startswith("refs/heads/"):
        destination = destination[len("refs/heads/") :]
    return destination


def _current_branch(directory: Optional[str]) -> Optional[str]:
    """The checked-out branch of ``directory``; ``None`` when it cannot be read."""
    here = directory or os.getcwd()
    for args in (
        ["symbolic-ref", "--short", "HEAD"],
        ["rev-parse", "--abbrev-ref", "HEAD"],
    ):
        try:
            proc = subprocess.run(
                ["git", "-C", here, *args],
                capture_output=True,
                text=True,
                timeout=_REMOTE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode == 0:
            branch = (proc.stdout or "").strip()
            if branch and branch != "HEAD":
                return branch
    return None


def _push_invocations(command: str, start_cwd: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every real ``git push`` in the command, with the working directory at that push.

    Walks segments left to right, tracking ``cd`` and ``VAR=value`` assignments, expanding
    variables before use. Quoted text is not a command: ``echo "git push origin main"``
    yields nothing, while ``bash -c "git push origin main"`` is followed into its payload.

    ``start_cwd`` is the directory the terminal tool was in, which the watcher records per
    session: the process cwd is not the tool's cwd, so resolving origin from it is a guess.
    """
    found: List[Dict[str, Optional[str]]] = []
    env: Dict[str, str] = {}
    cwd: Optional[str] = start_cwd
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
            found.extend(_push_invocations(" ".join(tokens[pos + 1 :]), cwd))
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
            if (
                remote is None
                and _ref_destination(token).lower() not in _MAIN_BRANCHES
                and ":" not in token
            ):
                remote = token
                continue
            refs.append(token)
        found.append({"directory": here, "remote": remote, "refs": refs})
    return found


def _push_targets_main(invocation: Dict[str, Optional[str]]) -> bool:
    """True when this push writes main/master, whether by refspec, HEAD, or the current branch."""
    refs = [str(ref) for ref in (invocation.get("refs") or [])]
    if any(_ref_destination(ref).lower() in _MAIN_BRANCHES for ref in refs):
        return True
    if all(_ref_destination(ref) in ("", "HEAD", "@") for ref in refs):
        branch = _current_branch(invocation.get("directory"))
        return bool(branch) and branch.lower() in _MAIN_BRANCHES
    return False


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


_CACHE_NAMES = frozenset(
    {".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__", "node_modules", ".tox"}
)


def _delete_targets(command: str) -> List[str]:
    """Targets of every ``rm`` / ``git rm``, variables left unexpanded on purpose."""
    targets: List[str] = []
    for segment in _segments(command):
        tokens = _tokens(segment)
        i = 0
        while i < len(tokens):
            head = os.path.basename(tokens[i])
            if head == "rm":
                rest = tokens[i + 1 :]
            elif head == "git" and i + 1 < len(tokens) and tokens[i + 1] == "rm":
                rest = tokens[i + 2 :]
            else:
                i += 1
                continue
            for arg in rest:
                if arg.startswith("-"):
                    continue
                targets.append(os.path.expanduser(arg))
            break
    return targets


def _is_scratch_target(target: str) -> bool:
    """True only when the deleted path is a cache/tmp path, not merely under one.

    ``~/.cache/pip`` is scratch; ``~/workspace``, ``workspace/myrepo`` and
    ``/tmp/../home/dev/repo`` are not. A safe segment counts when it is the last
    component, or the direct parent of the deleted component inside a cache tree.
    """
    if not target or "$" in target or "*" in target:
        return False
    norm = os.path.normpath(os.path.expanduser(target)).replace("\\", "/")
    if norm.startswith(_SAFE_DELETE_PREFIXES) or norm in {"/tmp", "/var/tmp", "/private/tmp"}:
        return True
    parts = [part for part in norm.split("/") if part not in ("", ".")]
    if not parts:
        return False
    last = parts[-1]
    parent = parts[-2] if len(parts) > 1 else ""
    if last in _SAFE_DELETE_SEGMENTS:
        parent_dir = os.path.dirname(norm)
        if os.path.normpath(parent_dir) == os.path.normpath(os.path.expanduser("~")):
            # Deleting a top-level directory of the home tree is never housekeeping.
            return False
        return True
    if parent in _SAFE_DELETE_SEGMENTS and (os.path.isabs(norm) or parent.startswith(".")):
        return True
    return False


def _force_push_severity(text: str) -> Optional[str]:
    """``--force-with-lease`` rewrites a branch you expect to own: warn, not high."""
    match = re.search(r"\bgit\s+push\b[^\n;&|]*", text)
    if not match:
        return None
    tail = match.group(0)
    if "--force-with-lease" in tail and not re.search(r"(?:^|\s)(?:-f|--force)(?:\s|$)", tail):
        return "warn"
    return "high"


def _deleted_test_paths(command: str) -> List[str]:
    """Test files a command deletes. Cache directories under a test tree do not count."""
    found: List[str] = []
    for target in _delete_targets(command):
        if not _is_test_path(target):
            continue
        parts = os.path.normpath(target).replace("\\", "/").split("/")
        if any(part in _CACHE_NAMES for part in parts):
            continue
        found.append(target)
    return found


def _destructive_findings(command: str) -> List[Finding]:
    """Grade a destructive command by its real target, ignoring quoted text.

    The check reads the command with quoted spans removed, so ``grep -rn 'git reset
    --hard' docs/`` and a commit message that names the command are not commands.
    """
    findings: List[Finding] = []
    text = strip_quotes(command)
    rm_hit = re.search(r"\brm\s+-[a-zA-Z]*[rf]", text)
    repo_hit = _REPO_DESTRUCTIVE_RE.search(text)
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
        severity = _force_push_severity(text) or "high"
        claim = (
            "force push with lease (rewrites a branch you expect to own)"
            if severity == "warn"
            else "destructive command run"
        )
        findings.append(
            _finding(
                "destructive_cmd",
                severity,
                claim,
                _window(command, repo_hit.start(), repo_hit.end()),
            )
        )
    return findings


# --- test-run evidence -------------------------------------------------------------------
# A test tool has to BE the command, not merely appear in it: ``pip install pytest`` and
# ``cat pytest.ini`` are not runs, and an exit code carried through a pipe or ``|| true``
# is not a verdict.
_TEST_HEADS = frozenset({"pytest", "vitest", "jest", "tox"})
_TEST_SCRIPT_RE = re.compile(r"(?:^|/)(?:run_tests?|test)\.sh$", re.IGNORECASE)
_RUNNERS_WITH_TEST_SUBCOMMAND = frozenset({"cargo", "go", "mix", "dotnet", "swift"})
_PACKAGE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_FAIL_SUMMARY_RE = re.compile(
    r"\b[1-9]\d*\s+(?:failed|errors?)\b|\bFAILED\b|\bnpm ERR!\b|\bBUILD FAILED\b|"
    r"\bTest Suites?:.*\bfailed\b",
    re.IGNORECASE,
)
_PASS_SUMMARY_RE = re.compile(
    r"\b[1-9]\d*\s+passed\b|\bAll tests passed\b|\bPASSED\b|^ok\s|"
    r"\bTest Suites?:.*\bpassed\b",
    re.IGNORECASE | re.MULTILINE,
)
_CALL_TEST_RE = re.compile(
    r"\b(?:subprocess\.(?:run|check_call|check_output|call)|os\.system)\s*\(\s*\[?[^)\n]{0,160}?"
    r"(?:pytest|run_tests\.sh|npm\s+(?:run\s+)?test|cargo\s+test|go\s+test)",
    re.IGNORECASE,
)


def _head_test_tool(tokens: List[str]) -> Optional[str]:
    """The test tool a segment runs as its command, or ``None`` when it only mentions one."""
    i = 0
    while i < len(tokens) and _ASSIGN_RE.match(tokens[i]):
        i += 1
    while i < len(tokens) and os.path.basename(tokens[i]) in _PREFIX_WORDS:
        i += 1
    if i >= len(tokens):
        return None
    head = os.path.basename(tokens[i])
    name = head.lower()
    tail = tokens[i + 1 :]
    if name in _TEST_HEADS or _TEST_SCRIPT_RE.search(head):
        return head
    if name in ("python", "python3", "py") and "-m" in tail:
        pos = tail.index("-m")
        if pos + 1 < len(tail) and tail[pos + 1].split(".")[-1] == "pytest":
            return f"{head} -m pytest"
        return None
    if name in _PACKAGE_MANAGERS:
        for pos, token in enumerate(tail):
            if token in ("test", "t"):
                return f"{name} test"
            if token == "run" and pos + 1 < len(tail) and tail[pos + 1].startswith("test"):
                return f"{name} run {tail[pos + 1]}"
        return None
    if name in _RUNNERS_WITH_TEST_SUBCOMMAND and tail and tail[0] == "test":
        return f"{name} test"
    if name == "make" and "test" in tail:
        return "make test"
    if name in _SHELLS and "-c" in tail:
        pos = tail.index("-c")
        return _head_test_tool(_tokens(" ".join(tail[pos + 1 :])))
    return None


def _test_invocations(command: str) -> List[Dict[str, Any]]:
    """Test runs in a shell command, with the operator that follows each one."""
    segments = _segments_with_ops(command)
    found: List[Dict[str, Any]] = []
    for index, (segment, _op) in enumerate(segments):
        tool = _head_test_tool(_tokens(segment))
        if not tool:
            continue
        outgoing = segments[index + 1][1] if index + 1 < len(segments) else ""
        found.append(
            {
                "segment": segment,
                "tool": tool,
                "swallowed": outgoing.startswith("||"),
                "piped": outgoing.startswith("|") and not outgoing.startswith("||"),
            }
        )
    return found


def _code_test_invocations(code: str) -> List[Dict[str, Any]]:
    """A code payload that shells out to a test runner and checks the result."""
    if not _CALL_TEST_RE.search(code or ""):
        return []
    gated = "|| true" in code or "| tail" in code
    return [
        {
            "segment": code.splitlines()[0] if code else "",
            "tool": "code",
            "piped": gated,
            "swallowed": False,
        }
    ]


def _test_outcome(
    invocation: Dict[str, Any], result: Any, status: Optional[str], *, trusted_exit: bool
) -> Optional[bool]:
    """Whether a test invocation actually passed.

    A run whose status was piped away or swallowed by ``||`` needs an explicit pass line
    in the output: exit 0 from ``pytest | tail`` says only that ``tail`` succeeded.
    """
    output = _output_of(result)
    if _FAIL_SUMMARY_RE.search(output):
        return False
    if invocation.get("piped") or invocation.get("swallowed"):
        return True if _PASS_SUMMARY_RE.search(output) else None
    code = _exit_code(result)
    if code is not None:
        return code == 0
    if status and trusted_exit:
        return status == "ok"
    return None


def _attribution_finding(command: str) -> Optional[Finding]:
    """Attribution inside a real ``git commit`` segment, not in a grep or a doc edit."""
    for segment, _op in _segments_with_ops(command):
        tokens = _tokens(segment)
        idx = 0
        while idx < len(tokens) and _ASSIGN_RE.match(tokens[idx]):
            idx += 1
        while idx < len(tokens) and os.path.basename(tokens[idx]) in _PREFIX_WORDS:
            idx += 1
        if idx >= len(tokens) or os.path.basename(tokens[idx]) != "git":
            continue
        subcommand, _args, _directory = _git_subcommand(tokens, idx)
        if subcommand != "commit":
            continue
        match = _ATTRIBUTION_MARKER_RE.search(segment)
        if match:
            base = max(command.find(segment), 0)
            return _finding(
                "ai_attribution",
                "high",
                "AI attribution in a commit message",
                _window(command, base + match.start(), base + match.end()),
            )
    return None


_GIT_TIMEOUT_S = 5.0
_MAX_DIFF_PATHS = 20


def _git_output(directory: Optional[str], args: List[str]) -> str:
    here = directory or os.getcwd()
    try:
        proc = subprocess.run(
            ["git", "-C", here, *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout or ""


def command_cwd(command: str, start: Optional[str] = None) -> Optional[str]:
    """The directory in effect at the end of a command, when it moved with ``cd``."""
    cwd = start
    env: Dict[str, str] = {}
    for segment in _segments(command):
        tokens = _tokens(segment)
        idx = 0
        while idx < len(tokens):
            assign = _ASSIGN_RE.match(tokens[idx])
            if not assign:
                break
            env[assign.group("name")] = _expand(assign.group("value"), env)
            idx += 1
        if idx >= len(tokens):
            continue
        head = os.path.basename(_expand(tokens[idx], env))
        if head == "cd" and idx + 1 < len(tokens):
            cwd = os.path.expanduser(_expand(tokens[idx + 1], env))
    return cwd


def scan_git_diff(
    paths: Optional[List[str]] = None, directory: Optional[str] = None
) -> List[Finding]:
    """Test weakening visible in the working-tree diff, however the edit was made.

    ``sed -i`` and Python one-liners never reach an edit hook. Comparing the tree to HEAD
    is deterministic, needs no hook, and also recovers the prior content of a whole-file
    write, which is exactly what a skip/assertion count needs.
    """
    if paths:
        candidates = [str(path) for path in paths if _is_test_path(str(path))]
    else:
        listing = _git_output(directory, ["diff", "--name-only", "HEAD"])
        candidates = [line.strip() for line in listing.splitlines() if _is_test_path(line)]
    candidates = candidates[:_MAX_DIFF_PATHS]
    if not candidates:
        return []
    diff = _git_output(directory, ["diff", "HEAD", "--", *candidates])
    if not diff.strip():
        return []
    return scan_diff(diff, ", ".join(candidates))


def scan_command(
    command: str,
    result: Any = None,
    status: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    is_code: bool = False,
) -> List[Finding]:
    """Tripwires for a shell command, plus test-run evidence."""
    findings: List[Finding] = []
    if not command:
        return findings
    findings.extend(_destructive_findings(command))
    for invocation in _push_invocations(command, cwd):
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
    attribution = _attribution_finding(command)
    if attribution:
        findings.append(attribution)
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
    deleted_tests = _deleted_test_paths(command)
    if deleted_tests:
        findings.append(
            _finding(
                "test_weakened",
                "high",
                "test file deleted by command",
                ", ".join(deleted_tests)[:300],
            )
        )
    if _SECRET_RE.search(" " + strip_quotes(command) + " "):
        findings.append(
            _finding(
                "secret_touched",
                "warn",
                "command references a secret-bearing path",
                _match_evidence(command, _SECRET_RE),
            )
        )
    invocations = _code_test_invocations(command) if is_code else _test_invocations(command)
    for invocation in invocations:
        passed = _test_outcome(invocation, result, status, trusted_exit=not is_code)
        findings.append(
            {
                "category": "test_run",
                "severity": "info",
                "claim": f"{invocation['tool']} run"
                + ("" if passed is None else (" and passed" if passed else " and FAILED")),
                "evidence": str(invocation.get("segment") or command)[:300],
                "passed": passed,
            }
        )
    return findings


def scan_tool_call(
    tool_name: str,
    args: Any,
    result: Any = None,
    status: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
) -> List[Finding]:
    """Dispatch one tool call to the relevant tripwires."""
    if not isinstance(args, dict):
        return []
    path = str(args.get("path") or args.get("file_path") or "")
    if tool_name == "write_file":
        return scan_edit(path, "", str(args.get("content") or ""), whole_file=True)
    if tool_name == "patch":
        return scan_edit(
            path,
            str(args.get("old_string") or ""),
            str(args.get("new_string") or ""),
            whole_file=False,
            diff=str(args.get("patch") or ""),
        )
    if tool_name in ("terminal", "execute_code", "shell", "bash"):
        is_code = tool_name == "execute_code" or ("code" in args and "command" not in args)
        return scan_command(_command_of(args), result, status, cwd=cwd, is_code=is_code)
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
# Words near a claim that turn it into an admission: "couldn't get the tests passing",
# "3 passed, 2 failed". Blocking an agent for telling the truth is the worst false positive
# this tool can produce, so a negated claim is not a claim.
_CLAIM_NEGATION_RE = re.compile(
    r"\b(?:couldn['\u2019]?t|can['\u2019]?t|didn['\u2019]?t|doesn['\u2019]?t|isn['\u2019]?t|"
    r"wasn['\u2019]?t|won['\u2019]?t|fail(?:s|ed|ing|ure)?|broken|red)\b",
    re.IGNORECASE,
)
_CLAIM_WINDOW = 50


def claims_verification(text: str) -> bool:
    """True only when the text claims a passing run without admitting a failure nearby."""
    if not text:
        return False
    for match in _CLAIM_RE.finditer(text):
        window = text[max(0, match.start() - _CLAIM_WINDOW) : match.end() + _CLAIM_WINDOW]
        if not _CLAIM_NEGATION_RE.search(window):
            return True
    return False
