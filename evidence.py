"""Ground truth for ysk-watch: git state, tree fingerprints and structured test results.

The tripwires reason about tool calls, which is exactly the wrong place to decide whether the
tests describe the code: a shell edit, a subagent edit and an editor save all leave the same
tree behind and only one of them reaches an edit hook. Git sees all three.

The same argument applies to test outcomes, with a caveat. A JUnit XML file, a
``--json-report`` document, ``go test -json`` output or a vitest JSON blob is the runner's own
report, but it is also a file or a stream the watched agent can write. Reports are therefore
only allowed to make a verdict worse: a report with failures turns a zero exit into a failed
run, and nothing parsed here turns an unknown outcome into a pass.

Every call here is read-only for the repository, bounded by a timeout, and returns
``None``/empty on any error.

The repository is also the watched agent's to configure, and git reads its config on every
call. Settings that would make git report less than is on disk, or run a program while the
tree is read, are overridden from the command line (which outranks every config file), and
files the index has been told to stop looking at are looked at anyway.
"""

from __future__ import annotations

import hashlib
import json
import os
import pyexpat
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree

_GIT_TIMEOUT_S = 5.0
_STAGE_TIMEOUT_S = 20.0
_MAX_LISTED_PATHS = 200
_PATHSPEC_CHUNK = 100
# A fingerprint killed mid-run (a worker crash or SIGKILL) skips its context manager's cleanup
# and leaves its throwaway index behind. Nothing older than this is still in use.
_TEMP_PREFIX = "ysk-watch-fp-"
_STALE_TEMP_AGE_S = 3600.0
_SWEEP_INTERVAL_S = 600.0
_SWEEP_MAX_REMOVALS = 50
_last_sweep = 0.0
_MAX_REPORT_BYTES = 8 * 1024 * 1024

# Config that changes what git reports about the working tree, or runs a program while it is
# read. ``core.fsmonitor`` names a program that answers "what changed?"; the untracked cache is
# index data that can list nothing; ``core.ignoreStat`` marks every file assume-unchanged;
# ``checkStat=minimal``, ``trustctime=false`` and ``fileMode=false`` let an edit that keeps
# size and mtime, or only flips the exec bit, look clean. Hooks (``post-index-change`` fires on
# the throwaway index) and promisor-remote fetches would run programs the repository names.
_HARDENED_CONFIG: Tuple[Tuple[str, str], ...] = (
    ("core.fsmonitor", "false"),
    ("core.untrackedCache", "false"),
    ("core.ignoreStat", "false"),
    ("core.checkStat", "default"),
    ("core.trustctime", "true"),
    ("core.fileMode", "true"),
    # A planted split index would make ``update-index`` on the throwaway index write a
    # ``sharedindex.*`` file into the real ``.git``.
    ("core.splitIndex", "false"),
    ("core.hooksPath", os.devnull),
    ("protocol.allow", "never"),
)
# Environment with the same purpose: no lazy fetch of missing objects from a promisor remote
# (``GIT_NO_LAZY_FETCH`` is honored from 2.39.4/2.45), an empty transport allow-list that
# outranks any ``protocol.<name>.allow`` in the repository's config, and no ``git replace``
# substitution of one object for another.
_HARDENED_ENV = {
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_ALLOW_PROTOCOL": "",
    "GIT_NO_REPLACE_OBJECTS": "1",
}
# Removed from every environment, inherited or passed: ``-c`` settings outrank the overrides,
# and the pathspec switches would change what ``:(literal)`` names match or make git refuse
# the literal pathspecs the diff scans use.
_STRIPPED_ENV = (
    "GIT_CONFIG_PARAMETERS",
    "GIT_COMMON_DIR",
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
)

# Docs by extension only. A directory name says nothing about what is in it: ``src/docs/``
# can hold code, and ``requirements.txt`` changes what the tests run against.
_DOC_PATH_RE = re.compile(r"\.(?:md|markdown|rst|adoc)$", re.IGNORECASE)


def is_doc(path: str) -> bool:
    """A prose file cannot break a test; changes to one are not stale evidence."""
    return bool(path) and bool(_DOC_PATH_RE.search(path))


def hardened_env(
    env: Optional[Dict[str, str]] = None, extra: Tuple[Tuple[str, str], ...] = ()
) -> Dict[str, str]:
    """An environment for a read-only git call that repository config cannot steer.

    The overrides go in through ``GIT_CONFIG_COUNT`` rather than ``-c``: a key and its value
    travel separately, so a filter named ``a=b`` cannot be misparsed, and git passes them on
    to the processes it starts for submodules. ``GIT_CONFIG_COUNT`` entries already in the
    environment are kept; these come after them and so win.
    """
    if env is None:
        run_env = dict(os.environ)
        # Inherited settings that would point git at another repository or index. A caller
        # that passes ``env`` sets these on purpose (the fingerprint's throwaway index).
        for name in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        ):
            run_env.pop(name, None)
    else:
        run_env = dict(env)
    for name in _STRIPPED_ENV:
        run_env.pop(name, None)
    # ``git status`` refreshes the real index opportunistically and takes ``index.lock`` to
    # do it; without this, a watcher read could make the agent's own ``git add`` fail.
    run_env["GIT_OPTIONAL_LOCKS"] = "0"
    run_env.update(_HARDENED_ENV)
    try:
        count = max(0, int(run_env.get("GIT_CONFIG_COUNT") or 0))
    except ValueError:
        count = 0
    for key, value in (*_HARDENED_CONFIG, *extra):
        run_env[f"GIT_CONFIG_KEY_{count}"] = key
        run_env[f"GIT_CONFIG_VALUE_{count}"] = value
        count += 1
    run_env["GIT_CONFIG_COUNT"] = str(count)
    return run_env


def _run_git(
    directory: Optional[str],
    args: List[str],
    *,
    env: Optional[Dict[str, str]] = None,
    timeout: float = _GIT_TIMEOUT_S,
    input: Optional[str] = None,
    extra_config: Tuple[Tuple[str, str], ...] = (),
) -> Tuple[bool, str]:
    here = directory or os.getcwd()
    run_env = hardened_env(env, extra_config)
    try:
        proc = subprocess.run(
            ["git", "-C", here, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=run_env,
            input=input,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, ""
    return proc.returncode == 0, proc.stdout or ""


def git(directory: Optional[str], args: List[str]) -> str:
    """Read-only git output, empty on any failure (no repo, no git, timeout)."""
    ok, out = _run_git(directory, args)
    return out if ok else ""


def repo_root(directory: Optional[str]) -> Optional[str]:
    """The working-tree root for a directory, or ``None`` when it is not in a repository."""
    if directory and not os.path.isdir(directory):
        return None
    root = git(directory, ["rev-parse", "--show-toplevel"]).strip()
    return root or None


def _status_paths(
    directory: Optional[str],
    *,
    include_sources: bool = False,
    extra_config: Tuple[Tuple[str, str], ...] = (),
    timeout: float = _GIT_TIMEOUT_S,
) -> Optional[List[str]]:
    """Paths that differ from HEAD (staged, unstaged or untracked), root-relative.

    ``-z`` output, so names with spaces, quotes or non-ASCII bytes come back verbatim instead
    of C-quoted. A rename or copy entry is followed by its source path, which is skipped:
    the destination is the file that exists now. A submodule is compared by its commit
    (``--ignore-submodules=dirty``), whatever
    ``submodule.<name>.ignore`` says. ``None`` when git fails or times out: an empty list
    would say the tree matches HEAD.
    """
    ok, raw = _run_git(
        directory,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=dirty"],
        extra_config=extra_config,
        timeout=timeout,
    )
    if not ok:
        return None
    parts = raw.split("\0")
    names: List[str] = []
    index = 0
    while index < len(parts):
        entry = parts[index]
        index += 1
        if len(entry) < 4:
            continue
        code, path = entry[:2], entry[3:]
        source = ""
        if code[0] in "RC" or code[1] in "RC":
            source = parts[index] if index < len(parts) else ""
            index += 1
        if path and path not in names:
            names.append(path)
        # The fingerprint needs the source too: a path the tree must drop is as much a change
        # as the one it must add.
        if include_sources and source and source not in names:
            names.append(source)
    return names


def changed_paths(directory: Optional[str]) -> List[str]:
    """Every path the working tree differs from HEAD on, tracked or untracked, capped."""
    root = repo_root(directory)
    if not root:
        return []
    filters = filter_overrides(root)
    if filters is None:
        return []
    return (_status_paths(root, extra_config=filters) or [])[:_MAX_LISTED_PATHS]


# Never source, and rewritten by any Python or Node run: a repository that does not ignore
# them must not see a green run go stale because ``python -c`` wrote a ``.pyc``.
_CACHE_NAMES = (
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "node_modules",
    ".eggs",
    "htmlcov",
)
_CACHE_PATH_RE = re.compile(
    r"(?:^|/)(?:" + "|".join(re.escape(name) for name in _CACHE_NAMES) + r")/|\.py[co]$|"
    r"(?:^|/)\.coverage(?:\.[^/]*)?$|\.egg-info/"
)
_CACHE_PATHSPECS = [f":(exclude,glob)**/{name}/**" for name in _CACHE_NAMES] + [
    ":(exclude,glob)**/*.py[co]",
    ":(exclude,glob)**/.coverage*",
    ":(exclude,glob)**/*.egg-info/**",
]


def _git_path(root: str, name: str) -> Optional[str]:
    value = git(root, ["rev-parse", "--git-path", name]).strip()
    if not value:
        return None
    return value if os.path.isabs(value) else os.path.join(root, value)


def filter_overrides(root: str) -> Optional[Tuple[Tuple[str, str], ...]]:
    """Config that turns off every filter driver and config-defined hook, git-lfs included.

    A clean filter is a program git runs on a file's content before hashing it, and the
    repository chooses both the program (``filter.<name>.clean`` in ``.git/config``) and the
    files it applies to (``.gitattributes``). Run, it could make an edited file hash like the
    original. With the driver's commands empty and ``required`` off, the raw file is hashed,
    the same way on both sides of a comparison.

    From git 2.54 a hook can also be defined in config (``hook.<name>.command`` and
    ``.event``), which ``core.hooksPath`` does not reach. Each such name is disabled and
    stripped of its events. Older git ignores the keys.

    ``None`` when the config cannot be read:
    ``--get-regexp`` also fails when no key matches, so a failure counts only when listing
    the config fails too.
    """
    ok, raw = _run_git(root, ["config", "-z", "--get-regexp", r"^(filter|hook)\..*\."])
    if not ok:
        listed, _ = _run_git(root, ["config", "--list"])
        if not listed:
            return None
        raw = ""
    names = {"lfs"}
    hooks = set()
    for entry in raw.split("\0"):
        key = entry.split("\n", 1)[0]
        section, _, rest = key.partition(".")
        if "." not in rest:
            continue
        name = rest[: rest.rindex(".")]
        if section == "filter":
            names.add(name)
        elif section == "hook":
            hooks.add(name)
    overrides: List[Tuple[str, str]] = []
    for name in sorted(names):
        overrides += [
            (f"filter.{name}.clean", ""),
            (f"filter.{name}.process", ""),
            (f"filter.{name}.required", "false"),
        ]
    for name in sorted(hooks):
        overrides += [(f"hook.{name}.enabled", "false"), (f"hook.{name}.event", "")]
    return tuple(overrides)


def _global_excludes_file(root: str) -> Optional[str]:
    """The user's own excludes file: ``core.excludesFile`` from the global config, else git's
    default location. A repository-level setting is not consulted."""
    ok, value = _run_git(root, ["config", "--global", "--path", "--get", "core.excludesFile"])
    path = value.strip() if ok else ""
    if not path:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        path = os.path.join(base, "git", "ignore")
    return path if os.path.isfile(path) else None


def _hidden_paths(
    root: str, extra_config: Tuple[Tuple[str, str], ...]
) -> Optional[Tuple[List[str], List[str]]]:
    """Paths ``git status`` can be told not to report, as ``(flagged, untracked)``.

    ``flagged``: tracked files marked assume-unchanged or skip-worktree that exist on disk.
    Status trusts the mark and never looks at them. A skip-worktree file that is absent is
    an ordinary sparse checkout and is left alone.

    ``untracked``: untracked files, honoring ``.gitignore`` files and the user's global
    excludes file but not ``.git/info/exclude`` or a repository-level ``core.excludesFile``.
    Those two live in the repository's private, unreviewed state, so a rule there could hide
    a new source file without any tracked file changing. An untracked nested repository
    (listed as ``dir/``, such as a tool's worktree under ``.claude/worktrees/``) is left out:
    git would record only its commit id, and it is a repository of its own, fingerprinted on
    its own when the session works there.

    ``None`` when either listing fails: a partial list would name a tree that does not exist.
    """
    ok, raw = _run_git(root, ["ls-files", "-v", "-z"], timeout=_STAGE_TIMEOUT_S)
    if not ok:
        return None
    flagged: List[str] = []
    for entry in raw.split("\0"):
        if len(entry) < 3:
            continue
        tag, path = entry[0], entry[2:]
        # ``m`` is an unmerged entry: status reports it already, and update-index cannot
        # clear a mark on it.
        if (
            tag != "m"
            and (tag.islower() or tag == "S")
            and os.path.lexists(os.path.join(root, path))
        ):
            flagged.append(path)
    args = ["ls-files", "-z", "--others", "--exclude-per-directory=.gitignore"]
    excludes = _global_excludes_file(root)
    if excludes:
        args.append(f"--exclude-from={excludes}")
    ok, raw = _run_git(root, args, timeout=_STAGE_TIMEOUT_S, extra_config=extra_config)
    if not ok:
        return None
    return flagged, [path for path in raw.split("\0") if path and not path.endswith("/")]


def _within(directory: Optional[str], root: str) -> bool:
    """Whether ``directory`` lies inside the working tree git reported for it.

    ``core.worktree`` in a repository's config points git at another directory, so the tree
    read would not be the one the agent works in.
    """
    here = os.path.realpath(directory or os.getcwd())
    # Walk up rather than compare strings: on a case-insensitive filesystem the agent's cwd
    # and git's toplevel can name the same directory in different case.
    while True:
        try:
            if os.path.samefile(here, root):
                return True
        except OSError:
            return False
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def _sweep_stale_temp_dirs(now: Optional[float] = None) -> int:
    """Remove fingerprint temp directories that killed runs left behind; return the count.

    Only directories named with this module's prefix and untouched for ``_STALE_TEMP_AGE_S``
    are removed, so a fingerprint running in another process is never disturbed. Runs at most
    once per ``_SWEEP_INTERVAL_S`` per process.
    """
    global _last_sweep
    now = time.time() if now is None else now
    if now - _last_sweep < _SWEEP_INTERVAL_S:
        return 0
    _last_sweep = now
    # Without fd-based rmtree a directory swapped for a symlink between the checks below and the
    # removal could redirect it; leave the leftovers rather than risk that.
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        return 0
    try:
        entries = list(os.scandir(tempfile.gettempdir()))
    except OSError:
        return 0
    uid = os.getuid() if hasattr(os, "getuid") else None
    removed = 0
    for entry in entries:
        if removed >= _SWEEP_MAX_REMOVALS:
            break
        if not entry.name.startswith(_TEMP_PREFIX):
            continue
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if uid is not None and info.st_uid != uid:
            continue  # a shared temp directory: another user's run is not ours to remove
        if now - info.st_mtime < _STALE_TEMP_AGE_S:
            continue
        shutil.rmtree(entry.path, ignore_errors=True)
        if not os.path.exists(entry.path):
            removed += 1
    return removed


def tree_fingerprint(
    directory: Optional[str], *, include_docs: bool = False
) -> Optional[Dict[str, Any]]:
    """The git tree id of the working tree as it is on disk, docs excluded.

    The whole working tree (tracked changes and untracked, non-ignored files) is staged into
    a throwaway index whose new objects go to a throwaway object directory, and the tree id
    of that index is the fingerprint. Files marked assume-unchanged or skip-worktree are
    hashed from disk all the same, ``.git/info/exclude`` does not hide a file, and no filter
    driver, fsmonitor hook or index cache the repository configures is used (see
    ``_hidden_paths`` and ``filter_overrides``). The repository's own index and object store
    are only read. The name therefore depends on file contents and nothing else: ``git add`` and
    ``git commit`` after a green run leave it unchanged, while any content change, however
    it was made, changes it. Nothing is truncated and no file is named by size or mtime.

    Prose files (``.md``, ``.rst``, ``.adoc``) are reset to their HEAD version first, so a
    README edit after a green run is not stale evidence.

    Returns ``None`` outside a repository, before the first commit, when the repository's
    config points git at another working tree, or when git fails or times out. Callers
    decide what an unknown tree means; this function never guesses.
    """
    root = repo_root(directory)
    if not root or not _within(directory, root):
        return None
    head = git(root, ["rev-parse", "HEAD"]).strip()
    if not head:
        return None
    index_path = _git_path(root, "index")
    objects_path = _git_path(root, "objects")
    if not objects_path:
        return None
    filters = filter_overrides(root)
    if filters is None:
        return None
    status = _status_paths(
        root, include_sources=True, extra_config=filters, timeout=_STAGE_TIMEOUT_S
    )
    if status is None:
        return None
    hidden = _hidden_paths(root, filters)
    if hidden is None:
        return None
    flagged, untracked = hidden
    listed: List[str] = []
    seen = set()
    for path in (
        *status,
        *flagged,
        *untracked,
    ):
        if path not in seen:
            seen.add(path)
            listed.append(path)
    paths = [path for path in listed if not _CACHE_PATH_RE.search(path)]
    flagged = [path for path in flagged if path in paths]
    docs = [path for path in paths if is_doc(path)] if not include_docs else []
    code_paths = [path for path in paths if path not in docs]
    try:
        _sweep_stale_temp_dirs()
        with tempfile.TemporaryDirectory(prefix=_TEMP_PREFIX) as tmp:
            temp_index = os.path.join(tmp, "index")
            temp_objects = os.path.join(tmp, "objects")
            os.mkdir(temp_objects)
            env = dict(os.environ)
            env.update(
                GIT_INDEX_FILE=temp_index,
                GIT_OBJECT_DIRECTORY=temp_objects,
                GIT_ALTERNATE_OBJECT_DIRECTORIES=objects_path,
            )
            env.pop("GIT_DIR", None)
            env.pop("GIT_WORK_TREE", None)
            copied = False
            if index_path and os.path.isfile(index_path):
                try:
                    # The real index carries stat data, so unchanged files are not rehashed.
                    # copy2 keeps the index file's mtime: git's racy-clean check compares
                    # entries against it, and a fresh mtime would make a same-size edit made
                    # within the same second as the last index write look unchanged.
                    shutil.copy2(index_path, temp_index)
                    copied = True
                except OSError:
                    copied = False
            if not copied:
                ok, _ = _run_git(root, ["read-tree", "HEAD"], env=env, extra_config=filters)
                if not ok:
                    return None
            elif flagged:
                # The copied index still carries the marks, and ``update-index`` leaves a
                # skip-worktree entry alone even when it is named. Clear them in the copy.
                for mark in ("--no-assume-unchanged", "--no-skip-worktree"):
                    ok, _ = _run_git(
                        root,
                        ["update-index", mark, "-z", "--stdin"],
                        env=env,
                        timeout=_STAGE_TIMEOUT_S,
                        input="".join(path + "\0" for path in flagged),
                        extra_config=filters,
                    )
                    if not ok:
                        return None
            # Each changed path's object id goes into the throwaway index without the object
            # being written (``--info-only``): the tree id is the one ``git add -A`` would
            # produce, but no file content is copied into the temp directory, so a large
            # untracked file costs one read rather than its size on disk. Filter drivers are
            # off (``filter_overrides``): the raw file is hashed.
            # One process reads every path from stdin: a single index write and a single
            # timeout however many paths changed.
            if paths:
                ok, _ = _run_git(
                    root,
                    ["update-index", "--add", "--remove", "--info-only", "-z", "--stdin"],
                    env=env,
                    timeout=_STAGE_TIMEOUT_S,
                    input="".join(path.rstrip("/") + "\0" for path in paths),
                    extra_config=filters,
                )
                if not ok:
                    return None
            for start in range(0, len(docs), _PATHSPEC_CHUNK):
                chunk = docs[start : start + _PATHSPEC_CHUNK]
                ok, _ = _run_git(
                    root,
                    ["reset", "-q", "HEAD", "--", *[f":(literal){p}" for p in chunk]],
                    env=env,
                    extra_config=filters,
                )
                if not ok:
                    return None
            # The blobs hashed above were never written; trees are, and they are small.
            # write-tree re-hashes a racily clean entry (one written in the same second as
            # the index), so the filter overrides apply here too, as to every call above.
            ok, tree = _run_git(root, ["write-tree", "--missing-ok"], env=env, extra_config=filters)
            tree = tree.strip()
            if not ok or not tree:
                return None
    except OSError:
        return None
    return {
        "hash": tree[:12],
        "tree": tree,
        "head": head[:7],
        "root": root,
        "paths": code_paths[:20],
        "count": len(code_paths),
    }


# --- outside git -------------------------------------------------------------------------------
# Without a repository there is no tree id, but a shell edit after a green run is just as stale.
# The fallback names a directory by the size and modification time of its source-like files.
# Caches, environments and build output are skipped, since a test run writes them itself; a
# directory too large to walk quickly gets no name at all, and the caller keeps the hook-visible
# edit timeline rather than trusting a partial walk.

_DIR_MAX_FILES = 5000
_DIR_MAX_SECONDS = 1.0
_DIR_SKIP = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        ".next",
        "dist",
        "build",
        "target",
        "htmlcov",
        ".coverage",
        ".cache",
        ".idea",
        ".vscode",
        ".eggs",
        "coverage",
    }
)
_DIR_SOURCE_RE = re.compile(
    r"\.(?:py|pyi|js|jsx|mjs|cjs|ts|tsx|go|rs|java|kt|kts|scala|c|h|cc|cpp|hpp|cs|rb|php|"
    r"swift|m|mm|sh|bash|zsh|fish|lua|pl|r|jl|ex|exs|erl|hs|ml|sql|toml|ya?ml|json|ini|cfg|"
    r"conf|lock|txt|proto|graphql|vue|svelte)$|(?:^|/)(?:Makefile|Dockerfile|justfile)$",
    re.IGNORECASE,
)


def dir_fingerprint(directory: Optional[str]) -> Optional[Dict[str, Any]]:
    """A name for a directory outside git: size and mtime of every source-like file under it.

    Returns ``None`` for a missing directory, or one with more than 5,000 source files or that
    takes over a second to walk: an incomplete walk would name a tree that does not exist.
    """
    if not directory:
        return None
    root = os.path.realpath(directory)
    if not os.path.isdir(root):
        return None
    deadline = time.monotonic() + _DIR_MAX_SECONDS
    entries: List[str] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as listing:
                items = sorted(listing, key=lambda entry: entry.name)
        except OSError:
            continue
        for item in items:
            if time.monotonic() > deadline:
                return None
            try:
                if item.is_symlink():
                    continue
                if item.is_dir():
                    if item.name not in _DIR_SKIP and not item.name.endswith(".egg-info"):
                        stack.append(item.path)
                    continue
                relative = os.path.relpath(item.path, root)
                if is_doc(relative) or not _DIR_SOURCE_RE.search(relative):
                    continue
                info = item.stat()
            except OSError:
                continue
            # ctime and inode too: mtime can be set back by hand, ctime cannot.
            entries.append(
                f"{relative}\0{info.st_size}\0{info.st_mtime_ns}\0{info.st_ctime_ns}\0{info.st_ino}"
            )
            if len(entries) > _DIR_MAX_FILES:
                return None
    digest = hashlib.sha256("\n".join(sorted(entries)).encode("utf-8", "replace")).hexdigest()
    return {
        "hash": "d" + digest[:11],
        "tree": digest,
        "head": "",
        "root": root,
        "paths": [],
        "count": len(entries),
        "kind": "directory",
    }


def fingerprint(directory: Optional[str]) -> Optional[Dict[str, Any]]:
    """The git tree fingerprint inside a repository, the directory fingerprint outside one."""
    if not directory:
        return None
    if repo_root(directory):
        return tree_fingerprint(directory)
    if shutil.which("git") and _inside_git_metadata_tree(directory):
        # A repository git refuses to read (an unknown format version or extension, a
        # planted ``core.bare``) is not a plain directory: no weaker name stands in for it.
        # Without git installed at all, the directory rule applies everywhere, as documented.
        return None
    return dir_fingerprint(directory)


def _inside_git_metadata_tree(directory: str) -> bool:
    """Whether ``directory`` or any parent holds a ``.git`` entry."""
    here = os.path.realpath(directory)
    while True:
        if os.path.lexists(os.path.join(here, ".git")):
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def snapshot(
    directory: Optional[str], fingerprint: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """What the tree looked like when the turn asked to finish.

    ``git diff --stat`` and ``git status`` recorded together, so a finding about a claim can
    be read back against the tree that was current when the claim was made.
    """
    fingerprint = fingerprint or tree_fingerprint(directory)
    if fingerprint is None:
        return None
    root = fingerprint["root"]
    filters = filter_overrides(root) or ()
    _, diffstat = _run_git(
        root,
        ["diff", "--no-ext-diff", "--no-textconv", "--stat", "HEAD"],
        extra_config=filters,
    )
    _, status = _run_git(
        root,
        ["status", "--short", "--untracked-files=all", "--ignore-submodules=dirty"],
        extra_config=filters,
    )
    diffstat, status = diffstat[:2000], status[:2000]
    return {
        "tree": fingerprint["hash"],
        "head": fingerprint["head"],
        "changed": fingerprint["count"],
        "paths": fingerprint["paths"][:12],
        "diffstat": [line for line in diffstat.splitlines() if line.strip()][:20],
        "status": [line for line in status.splitlines() if line.strip()][:30],
    }


# --- structured test results --------------------------------------------------------------

_JUNIT_RE = re.compile(r"--junit-?xml(?:=|\s+)(\S+)")
_JSON_REPORT_RE = re.compile(r"--json-report-file(?:=|\s+)(\S+)")
# jest ``--json``; vitest ``--reporter=json`` (it has no ``--json``). Either may write to a
# file with ``--outputFile`` instead of stdout.
_RUNNER_JSON_FLAG_RE = re.compile(r"(?:^|\s)(?:--json|--reporter[=\s]json)(?:\s|$)")
_OUTPUT_FILE_RE = re.compile(r"--outputFile(?:=|\s+)(\S+)")
_GO_JSON_FLAG_RE = re.compile(r"(?:^|\s)-json(?:\s|$)")
# pytest's closing line, alone on its line: ``5 passed, 93 deselected in 0.21s``, optionally
# framed by ``=`` rules. Anchoring keeps a linter's "Found 2 errors" in the same output from
# being read as test errors.
_SUMMARY_LINE_RE = re.compile(
    r"^[=\s]*(?P<counts>\d+ [a-z]+(?:, \d+ [a-z]+)*) in [\d.]+s(?: \([^)]*\))?[=\s]*$",
    re.MULTILINE,
)
_SUMMARY_PART_RE = re.compile(r"(\d+) ([a-z]+)")
_COLLECTED_RE = re.compile(r"^collected (\d+) items?", re.MULTILINE)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SUMMARY_KEYS = {
    "passed": "passed",
    "xpassed": "passed",
    "xfailed": "skipped",
    "failed": "failed",
    "error": "errors",
    "errors": "errors",
    "skipped": "skipped",
    "deselected": "deselected",
}
_NARROWING_RE = re.compile(
    r"(?:^|\s)(?:-k\s|--deselect[=\s]|--last-failed\b|--failed-first\b|--lf\b|-x\b|"
    r"--exitfirst\b|--ignore[=\s]|--maxfail[=\s])"
)


def narrowing_flags(command: str) -> List[str]:
    """Flags that make a green run smaller than the suite it appears to stand for."""
    found: List[str] = []
    for match in _NARROWING_RE.finditer(command or ""):
        token = match.group(0).strip()
        if token and token not in found:
            found.append(token)
    return found


def _read_report(path: str, not_before: Optional[float]) -> str:
    """A report file's text, or empty when it cannot be the report of this run.

    Only a regular file is read (``/dev/zero`` or a FIFO would exhaust memory or block the
    host process), the read is capped, and a file not modified since the previous tool call
    finished is ignored: a report written ahead of time is not evidence of this run.
    """
    try:
        info = os.stat(path)
    except OSError:
        return ""
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_REPORT_BYTES:
        return ""
    if not_before is not None and info.st_mtime < not_before:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(_MAX_REPORT_BYTES + 1)
    except OSError:
        return ""
    return "" if len(text) > _MAX_REPORT_BYTES else text


def _int(value: Any) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return number if 0 <= number < 10_000_000 else 0


_MAX_XML_BYTES = 1024 * 1024
# CVE-2025-59375: expat before 2.7.2 can be driven into disproportionate allocation by a small
# document, DTD or not. A report the watched agent can write is not parsed on such a build.
_EXPAT_SAFE = tuple(getattr(pyexpat, "version_info", (0, 0, 0))) >= (2, 7, 2)


def _parse_junit(text: str) -> Optional[Dict[str, Any]]:
    if not text.strip() or len(text) > _MAX_XML_BYTES or not _EXPAT_SAFE:
        return None
    # The report is local, but a test can write it: no DOCTYPE means no entity expansion,
    # which is the only XML attack surface left in the stdlib parser (it never fetches
    # external entities). Reject the document rather than parse an untrusted one.
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.IGNORECASE):
        return None
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        return None
    total = failed = errors = skipped = 0
    for suite in suites:
        total += _int(suite.get("tests"))
        failed += _int(suite.get("failures"))
        errors += _int(suite.get("errors"))
        skipped += _int(suite.get("skipped"))
    if not total:
        return None
    return {
        "source": "junit",
        "total": total,
        "passed": max(0, total - failed - errors - skipped),
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
    }


def _parse_pytest_json(text: str) -> Optional[Dict[str, Any]]:
    if not text.strip():
        return None
    data = json.loads(text)
    summary = data.get("summary") if isinstance(data, dict) else None
    if not isinstance(summary, dict):
        return None
    total = _int(summary.get("total"))
    if not total:
        return None
    return {
        "source": "pytest-json",
        "total": total,
        "passed": _int(summary.get("passed")),
        "failed": _int(summary.get("failed")),
        "errors": _int(summary.get("error")),
        "skipped": _int(summary.get("skipped")),
    }


def _parse_runner_json(output: str) -> Optional[Dict[str, Any]]:
    """Jest/vitest JSON results: one object holding ``numTotalTests``.

    Decoded from the object's own opening brace, so a console line printed before it (stderr
    merged into the result) does not break the parse.
    """
    start = output.find('{"num')
    if start < 0:
        start = output.find("{")
    if start < 0:
        return None
    data, _ = json.JSONDecoder().raw_decode(output[start:])
    if not isinstance(data, dict) or "numTotalTests" not in data:
        return None
    total = _int(data.get("numTotalTests"))
    if not total:
        return None
    return {
        "source": "runner-json",
        "total": total,
        "passed": _int(data.get("numPassedTests")),
        "failed": _int(data.get("numFailedTests")),
        "errors": 0,
        "skipped": _int(data.get("numPendingTests")),
    }


def _parse_go_json(output: str) -> Optional[Dict[str, Any]]:
    """``go test -json``: one event per test action."""
    passed = failed = skipped = 0
    seen = False
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(event, dict) or not event.get("Test"):
            continue
        action = event.get("Action")
        if action == "pass":
            passed += 1
            seen = True
        elif action == "fail":
            failed += 1
            seen = True
        elif action == "skip":
            skipped += 1
            seen = True
    if not seen:
        return None
    return {
        "source": "go-test-json",
        "total": passed + failed + skipped,
        "passed": passed,
        "failed": failed,
        "errors": 0,
        "skipped": skipped,
    }


def _parse_summary_line(output: str) -> Optional[Dict[str, Any]]:
    """The fallback: pytest's own closing summary line, when no structure was produced."""
    output = _ANSI_RE.sub("", output or "")
    lines = list(_SUMMARY_LINE_RE.finditer(output))
    if not lines:
        return None
    counts: Dict[str, int] = {}
    for number, word in _SUMMARY_PART_RE.findall(lines[-1].group("counts")):
        key = _SUMMARY_KEYS.get(word)
        if key:
            counts[key] = counts.get(key, 0) + _int(number)
    if not counts:
        return None
    # ``total`` is what the run exercised. Deselected tests were collected and then not run,
    # so they are reported beside it, not inside it: ``-k`` must shrink the number.
    deselected = counts.get("deselected", 0)
    collected = _COLLECTED_RE.findall(output)
    if collected:
        total = max(0, _int(collected[-1]) - deselected)
    else:
        total = sum(counts.get(name, 0) for name in ("passed", "failed", "errors", "skipped"))
    if not total:
        return None
    return {
        "source": "summary-line",
        "total": total,
        "passed": counts.get("passed", 0),
        "failed": counts.get("failed", 0),
        "errors": counts.get("errors", 0),
        "skipped": counts.get("skipped", 0),
        "deselected": deselected,
    }


def parse_results(
    command: str,
    output: str,
    directory: Optional[str] = None,
    *,
    not_before: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Test counts from the runner's own report, falling back to its summary line.

    A JUnit/JSON path named in the command is resolved against the directory the command
    ran in, and must have been written after ``not_before`` (the end of the previous tool
    call). Runner JSON is read only when the command asked for it. Anything unreadable or
    malformed returns ``None`` and the caller keeps exit-code evidence; no exception leaves.
    """
    try:
        here = directory or os.getcwd()
        command = command or ""
        output = output or ""
        for pattern, parser in ((_JUNIT_RE, _parse_junit), (_JSON_REPORT_RE, _parse_pytest_json)):
            match = pattern.search(command)
            if not match:
                continue
            path = os.path.expanduser(match.group(1).strip("'\""))
            if not os.path.isabs(path):
                path = os.path.join(here, path)
            parsed = parser(_read_report(path, not_before))
            if parsed:
                return parsed
        if _RUNNER_JSON_FLAG_RE.search(command):
            match = _OUTPUT_FILE_RE.search(command)
            if match:
                path = os.path.expanduser(match.group(1).strip("'\""))
                if not os.path.isabs(path):
                    path = os.path.join(here, path)
                source = _read_report(path, not_before)
            else:
                source = output
            parsed = _parse_runner_json(source) if source else None
            if parsed:
                return parsed
        if _GO_JSON_FLAG_RE.search(command):
            parsed = _parse_go_json(output)
            if parsed:
                return parsed
        return _parse_summary_line(output)
    except (ValueError, TypeError, RecursionError, OverflowError, MemoryError):
        return None
