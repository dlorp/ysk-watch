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
import sys
import tempfile
import threading
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


# Where a git someone else installed usually lives. On a host where ``git`` on PATH is a file the
# watched agent's own user can rewrite (a wrapper script in ``/usr/local/bin``), every answer
# the watcher gets from git would be the agent's to choose.
# macOS's /usr/bin/git is a shim that looks the real binary up; the Command Line Tools copy
# is the binary itself.
_SYSTEM_GIT_DIRS = (
    "/Library/Developer/CommandLineTools/usr/bin",
    "/usr/bin",
    "/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
)
_git_binary_cache: Dict[str, Optional[str]] = {}


def _owned_by_someone_else(path: str) -> bool:
    """``path`` and every directory above it belong to root and only root can write them."""
    here = os.path.realpath(path)
    while True:
        try:
            info = os.stat(here)
        except OSError:
            return False
        if info.st_uid != 0 or info.st_mode & 0o022:
            return False
        parent = os.path.dirname(here)
        if parent == here:
            return True
        here = parent


def git_binary() -> Optional[str]:
    """The git to run: the one on PATH when root owns it, else a root-owned system git.

    ``None`` when there is no git on PATH at all (the directory fingerprint then applies). When
    no root-owned git exists, the one on PATH is used: nothing better is available.
    """
    found = shutil.which("git")
    if not found:
        return None
    if found not in _git_binary_cache:
        choice = found
        if not _owned_by_someone_else(found):
            for directory in _SYSTEM_GIT_DIRS:
                candidate = os.path.join(directory, "git")
                if os.path.isfile(candidate) and _owned_by_someone_else(candidate):
                    choice = candidate
                    break
        _git_binary_cache[found] = choice
    return _git_binary_cache[found]


# git prints paths as the bytes it read from the filesystem. They are decoded as Python's os
# functions encode a path (the filesystem encoding, with surrogateescape), never by the locale:
# under a Latin-1 locale on a UTF-8 filesystem every non-ASCII name read back as a file that
# did not exist, and a strict decode turned any undecodable name into a failed git call. A
# path read from git now names the same file when it goes back to ``lstat`` or to git.
# Output is taken as bytes and decoded by ``decode_output``.
GIT_TEXT: Dict[str, str] = {
    "encoding": sys.getfilesystemencoding(),
    "errors": sys.getfilesystemencodeerrors(),
}


def decode_output(data: Optional[bytes]) -> str:
    """git's output as text, decoded by ``GIT_TEXT``.

    Bytes in, decoded here: text mode would also translate newlines, and a file named
    ``helper\\r.py`` would read back as ``helper\\n.py``, a file that does not exist.
    """
    return (data or b"").decode(**GIT_TEXT)


def printable(text: str) -> str:
    """``text`` with any byte the filesystem encoding could not decode written as ``\\udcXX``.

    A path decoded with surrogateescape cannot be encoded to UTF-8 as it is, so it could not go
    into a ledger line, a JSON payload or a chat message. Everything else passes unchanged.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _run_git(
    directory: Optional[str],
    args: List[str],
    *,
    env: Optional[Dict[str, str]] = None,
    timeout: float = _GIT_TIMEOUT_S,
    input: Optional[str] = None,
    extra_config: Tuple[Tuple[str, str], ...] = (),
    stderr_fails: Tuple[str, ...] = (),
) -> Tuple[bool, str]:
    """Run git; ``(succeeded, stdout)``. ``stderr_fails`` names warnings that make the call a
    failure although git exits 0 (a directory it could not read, for one)."""
    here = directory or os.getcwd()
    run_env = hardened_env(env, extra_config)
    if stderr_fails:
        # The markers are git's English messages; gettext would translate them. Paths are
        # bytes to git whatever the locale, so this changes only the message text.
        run_env = dict(run_env, LC_ALL="C", LANGUAGE="")
    try:
        proc = subprocess.run(
            [git_binary() or "git", "-C", here, *args],
            capture_output=True,
            timeout=timeout,
            env=run_env,
            input=None if input is None else input.encode(**GIT_TEXT),
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, ""
    if stderr_fails:
        err = decode_output(proc.stderr)
        if any(marker in err for marker in stderr_fails):
            return False, ""
    return proc.returncode == 0, decode_output(proc.stdout)


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
# them must not see a green run go stale because ``python -c`` wrote a ``.pyc``. A ``.pyc``
# outside ``__pycache__`` is not a cache: Python imports it with no source beside it.
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
    r"(?:^|/)(?:" + "|".join(re.escape(name) for name in _CACHE_NAMES) + r")/|"
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


# Editor and OS droppings a global excludes file usually hides. That file is the agent's to
# write too, so it is not read; these few names are excluded by the watcher itself.
_JUNK_EXCLUDES = (
    "--exclude=.DS_Store",
    "--exclude=Thumbs.db",
    "--exclude=*.swp",
    "--exclude=*~",
    "--exclude=.idea/",
    "--exclude=.vscode/",
    "--exclude=.direnv/",
    "--exclude=/.claude/settings.local.json",
)
# Tool worktrees: repositories of their own that the session's tools create inside a checkout.
# git lists what it can read and only warns about a directory it cannot open, exit status 0.
# A file in such a directory can still be run by exact path, so the listing is a failure.
_UNREADABLE_DIR_WARNINGS = ("could not open directory",)

_TOOL_WORKTREE_RE = re.compile(r"^(?:\.claude/worktrees|\.worktrees)/")


def _untracked_paths(
    root: str,
    extra_config: Tuple[Tuple[str, str], ...],
    env: Dict[str, str],
    timeout: float = _STAGE_TIMEOUT_S,
) -> Optional[Tuple[List[str], List[str]]]:
    """Untracked files and nested repositories, as ``(files, repositories)``.

    Listed against ``env``'s index, a throwaway one read from HEAD: the repository's own index
    could claim any directory is a submodule, and git never lists what is inside one. Only
    ``.gitignore`` files hide a file. Not ``.git/info/exclude``, a repository-level
    ``core.excludesFile`` or the user's global excludes file: all three are files the watched
    agent can write without any tracked file changing. A nested repository is listed as
    ``dir/``; tool worktrees (``.claude/worktrees/``) are left out.

    ``None`` when the listing fails: a partial list would name a tree that does not exist.
    """
    args = ["ls-files", "-z", "--others", "--exclude-per-directory=.gitignore", *_JUNK_EXCLUDES]
    ok, raw = _run_git(
        root,
        args,
        env=env,
        timeout=timeout,
        extra_config=extra_config,
        stderr_fails=_UNREADABLE_DIR_WARNINGS,
    )
    if not ok:
        return None
    files: List[str] = []
    repos: List[str] = []
    for path in raw.split("\0"):
        if not path:
            continue
        if path.endswith("/"):
            if not _TOOL_WORKTREE_RE.match(path) and not _CACHE_PATH_RE.search(path):
                repos.append(path.rstrip("/"))
        else:
            files.append(path)
    return files, repos


def _ignored_gitignores(
    root: str,
    extra_config: Tuple[Tuple[str, str], ...],
    env: Dict[str, str],
    timeout: float = _STAGE_TIMEOUT_S,
) -> Optional[List[str]]:
    """Untracked ``.gitignore`` files that are themselves ignored, caches aside.

    A ``.gitignore`` whose own rules match it (``*``) hides itself along with the files it
    was planted to hide, so the untracked listing names neither. Counting the file itself
    is enough: creating or changing one after a green run changes the fingerprint.
    """
    args = [
        "ls-files",
        "-z",
        "--others",
        "--ignored",
        "--exclude-per-directory=.gitignore",
        "--",
        ":(glob)**/.gitignore",
        *_CACHE_PATHSPECS,
    ]
    ok, raw = _run_git(
        root,
        args,
        env=env,
        timeout=timeout,
        extra_config=extra_config,
        stderr_fails=_UNREADABLE_DIR_WARNINGS,
    )
    if not ok:
        return None
    return [path for path in raw.split("\0") if path and not _CACHE_PATH_RE.search(path)]


# A self-ignoring .gitignore in one of these, beside nothing tracked and nothing importable, is
# a tool marking its own output. pytest skips them when collecting.
_TOOL_DIR_NAMES = frozenset({"build", "dist"})
_IMPORTABLE_RE = re.compile(r"(?:\.(?:py|pth|pyi|js|mjs|cjs|ts|tsx)|^conftest\.py)$")


def _tool_owned(root: str, path: str, tracked_dirs: "set[str]") -> bool:
    """A self-ignoring ``.gitignore`` a tool wrote into a directory of its own.

    Caches and runtimes mark themselves this way (``.cache/``, a Python runtime's
    ``generation-*/``). Such a file sits under a dot-directory or ``build``/``dist``, nothing
    tracked lives in that directory, and nothing beside it could be imported. One planted
    next to source, or beside a ``conftest.py``, still counts.
    """
    parent = os.path.dirname(path)
    if not parent or parent in tracked_dirs:
        return False
    parts = parent.split("/")
    if not any(part.startswith(".") or part.lower() in _TOOL_DIR_NAMES for part in parts):
        return False
    seen = 0
    for _, _, files in os.walk(os.path.join(root, parent)):
        for name in files:
            seen += 1
            if _IMPORTABLE_RE.search(name) or seen > 5000:
                return False
    return True


def _head_entries(
    root: str, extra_config: Tuple[Tuple[str, str], ...], timeout: float = _STAGE_TIMEOUT_S
) -> Optional[Dict[str, Tuple[str, str]]]:
    """``path -> (mode, object id)`` for every entry of HEAD's tree."""
    ok, raw = _run_git(
        root,
        ["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
        timeout=timeout,
        extra_config=extra_config,
    )
    if not ok:
        return None
    entries: Dict[str, Tuple[str, str]] = {}
    for entry in raw.split("\0"):
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and path:
            entries[path] = (parts[0], parts[2])
    return entries


def _index_entries(
    root: str, extra_config: Tuple[Tuple[str, str], ...], timeout: float = _STAGE_TIMEOUT_S
) -> Optional[Dict[str, Tuple[str, str, str]]]:
    """``path -> (mode, object id, tag)`` from the repository's own index.

    Only the names, modes and the skip-worktree tag are used: the index is the watched
    agent's to rewrite, so its object ids and stat data never decide what a file contains.
    """
    ok, raw = _run_git(
        root, ["ls-files", "-s", "-v", "-z"], timeout=timeout, extra_config=extra_config
    )
    if not ok:
        return None
    entries: Dict[str, Tuple[str, str, str]] = {}
    for entry in raw.split("\0"):
        if len(entry) < 3:
            continue
        tag = entry[0]
        meta, _, path = entry[2:].partition("\t")
        parts = meta.split()
        if len(parts) == 3 and path:
            entries[path] = (parts[0], parts[1], tag)
    return entries


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


_STAT_CACHE_MAX_AGE_S = 30 * 86400.0


def _prune_stat_caches(now: float) -> None:
    """Remove stat caches untouched for a month (repositories and worktrees long gone)."""
    try:
        entries = list(os.scandir(_cache_dir()))
    except OSError:
        return
    for entry in entries:
        try:
            if (
                entry.name.endswith(".json")
                and entry.is_file(follow_symlinks=False)
                and now - entry.stat(follow_symlinks=False).st_mtime > _STAT_CACHE_MAX_AGE_S
            ):
                os.unlink(entry.path)
        except OSError:
            continue


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
    _prune_stat_caches(now)
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


# --- the watcher's own stat cache -------------------------------------------------------------
# The repository's index records, per file, an object id and the stat data it was hashed at.
# It is the watched agent's to rewrite: an index that pairs an edited file's current stat
# data with the old object id would make git report the file clean and the tree keep its
# old name. The fingerprint therefore never takes content from the index. It hashes files
# itself, raw (no filter, eol, ident or encoding conversion), and remembers what it hashed in
# a cache of its own, keyed on size, mtime, ctime, inode and mode. ctime cannot be set back by
# hand, so an edit that restores mtime and size still misses the cache. The cache lives under
# ``$HERMES_HOME`` with the watcher's other files (see the README's trust note).

_STAT_CACHE_VERSION = 2
# A file changed within this window of being hashed could change again inside the same
# timestamp tick; it is hashed again next time rather than remembered.
_RACY_NS = 2_000_000_000
_HASH_CHUNK = 1 << 20
# Files not in the stat cache are hashed on this many threads: reads and hashlib both release
# the GIL, so a first fingerprint of a large tree is bound by the disk, not one core.
_HASH_WORKERS = 4
_PARALLEL_MIN_FILES = 16
_MAX_CACHE_BYTES = 64 * 1024 * 1024
_OBJECT_FORMATS = {"sha1": 40, "sha256": 64}
_MODES = frozenset({"100644", "100755", "120000"})
_cache_dir_provider: Optional[Any] = None


def set_cache_dir_provider(provider: Any) -> None:
    """Let the plugin place the stat cache under ``$HERMES_HOME`` (a callable returning a path)."""
    global _cache_dir_provider
    _cache_dir_provider = provider


def _cache_dir() -> str:
    """``YSK_WATCH_CACHE_DIR``, else the plugin's directory, else ``$XDG_CACHE_HOME/ysk-watch``."""
    override = os.environ.get("YSK_WATCH_CACHE_DIR")
    if override:
        return override
    if _cache_dir_provider is not None:
        try:
            return str(_cache_dir_provider())
        except Exception:
            pass
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "ysk-watch", "stat")


def _stat_cache_path(git_dir: str) -> str:
    key = hashlib.sha256(os.path.realpath(git_dir).encode("utf-8", "surrogateescape"))
    return os.path.join(_cache_dir(), key.hexdigest()[:24] + ".json")


def _valid_cache_entry(entry: Any) -> bool:
    if not isinstance(entry, list) or len(entry) != 7:
        return False
    size, mtime, ctime, ino, mode, algo, oid = entry
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (size, mtime, ctime, ino)):
        return False
    width = _OBJECT_FORMATS.get(algo) if isinstance(algo, str) else None
    return (
        mode in _MODES
        and width is not None
        and isinstance(oid, str)
        and re.fullmatch(f"[0-9a-f]{{{width}}}", oid) is not None
    )


def _load_stat_cache(path: str) -> Dict[str, List[Any]]:
    """Read a cache file: a regular file only, size-capped, every entry validated.

    Anything else (a FIFO, a symlink, a huge or deeply nested document, a malformed entry) is
    an empty cache: the files are hashed again, which is slower and always correct.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return {}
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_CACHE_BYTES:
            return {}
        chunks = []
        while True:
            chunk = os.read(fd, _HASH_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        data = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, ValueError, RecursionError, MemoryError):
        return {}
    finally:
        os.close(fd)
    if not isinstance(data, dict) or data.get("v") != _STAT_CACHE_VERSION:
        return {}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        return {}
    return {k: v for k, v in entries.items() if isinstance(k, str) and _valid_cache_entry(v)}


def _save_stat_cache(path: str, entries: Dict[str, List[Any]]) -> None:
    """Write the cache atomically; a failed write only costs a rehash next time."""
    directory = os.path.dirname(path)
    tmp = ""
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".stat-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"v": _STAT_CACHE_VERSION, "entries": entries}, fh, separators=(",", ":"))
        os.replace(tmp, path)
        tmp = ""
    except (OSError, ValueError):
        pass
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _blob_id(data: bytes, algo: str) -> str:
    digest = hashlib.new(algo)
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()


def _hash_file(
    path: str, info: os.stat_result, algo: str, deadline: Optional[float] = None
) -> Optional[str]:
    """The blob id of a regular file's raw bytes; ``None`` if it changed while being read or
    the deadline passed."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            return None
        digest = hashlib.new(algo)
        digest.update(b"blob %d\0" % info.st_size)
        total = 0
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return None
            chunk = os.read(fd, _HASH_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        if total != info.st_size or os.fstat(fd).st_mtime_ns != info.st_mtime_ns:
            return None
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def _hash_files(
    items: List[Tuple[str, os.stat_result]], algo: str, deadline: Optional[float]
) -> List[Optional[str]]:
    """``_hash_file`` over many files, on the calling thread and up to ``_HASH_WORKERS - 1``
    daemon threads.

    Results are in the order of ``items``. The threads are daemons, and every file read and
    every claim of the next file checks the deadline, so a caller that stops waiting (the
    pre-run hook's budget) never holds the interpreter open. When no thread can be started the
    calling thread hashes everything.
    """
    results: List[Optional[str]] = [None] * len(items)
    if len(items) < _PARALLEL_MIN_FILES:
        for i, (full, info) in enumerate(items):
            results[i] = _hash_file(full, info, algo, deadline)
        return results
    lock = threading.Lock()
    position = [0]

    def work() -> None:
        while True:
            if deadline is not None and time.monotonic() > deadline:
                return  # the rest stay None: unread, as at the deadline in _hash_file
            with lock:
                i = position[0]
                position[0] += 1
            if i >= len(items):
                return
            full, info = items[i]
            try:
                results[i] = _hash_file(full, info, algo, deadline)
            except Exception:  # a worker must never die silently with work left unclaimed
                results[i] = None

    started = []
    for _ in range(min(_HASH_WORKERS, len(items)) - 1):
        thread = threading.Thread(target=work, name="ysk-watch-hash", daemon=True)
        try:
            thread.start()
        except RuntimeError:  # no thread to be had: the calling thread does the rest
            break
        started.append(thread)
    work()
    for thread in started:
        thread.join()
    return results


# Index modes as git records them (``create_ce_mode``): any other regular-file mode keeps
# only its owner-execute bit, so ``100664`` is ``100644`` and ``100775`` is ``100755``.
_TREE_MODES = {
    "100644": b"100644",
    "100755": b"100755",
    "120000": b"120000",
    "160000": b"160000",
}
_REGULAR_MODE_RE = re.compile(r"100[0-7]{3}")


def _tree_mode(mode: str) -> Optional[bytes]:
    known = _TREE_MODES.get(mode)
    if known is None and _REGULAR_MODE_RE.fullmatch(mode):
        known = b"100755" if int(mode, 8) & 0o100 else b"100644"
    return known


def _tree_id(
    entries: Dict[str, Tuple[str, str]], algo: str
) -> Optional[Tuple[str, List[Tuple[str, str, str]]]]:
    """The tree id of ``entries`` in git's tree format, and the entries no tree can hold.

    Built in memory, as ``git write-tree`` builds it: entries sorted by name with a directory
    compared as ``name/``, each ``<mode> <name>NUL<raw id>``. For every set of entries git
    accepts, the id is the one git writes. git would also drop some entries without failing:
    names it refuses (``.git`` in an HFS or NTFS spelling, ``git~1``, a symlinked
    ``.gitmodules``) and one side of a name that is both a file and a directory. Here the first
    kind is part of the tree like any other name, and the second is returned beside the id
    (``(path, mode, oid)``) so the caller can fold it into the name: a file git would ignore
    still changes the fingerprint when it changes.

    ``None`` for a mode no index records or a malformed object id.
    """
    width = _OBJECT_FORMATS.get(algo)
    if width is None:
        return None
    hex_id = re.compile(f"[0-9a-f]{{{width}}}")
    root: Dict[str, Any] = {}
    clashes: List[Tuple[str, str, str]] = []
    try:
        # Sorted, so which side of a file/directory clash lands in the tree never depends on
        # the order the listings came in.
        for path, (mode, oid) in sorted(entries.items()):
            mode_bytes = _tree_mode(mode)
            # git refuses the null id ("cache entry has null sha1"), so no tree holds it.
            if mode_bytes is None or not hex_id.fullmatch(oid) or not oid.strip("0"):
                return None
            *dirs, name = path.split("/")
            node: Any = root
            for part in dirs:
                child = node.get(part)
                if child is None:
                    child = node[part] = {}
                elif not isinstance(child, dict):
                    node = None
                    break
                node = child
            if node is None or name in node:
                clashes.append((path, mode, oid))
                continue
            node[name] = (mode_bytes, bytes.fromhex(oid))
        return _hash_tree(root, algo).hex(), clashes
    except RecursionError:
        return None


def _hash_tree(node: Dict[str, Any], algo: str) -> bytes:
    """The binary id of one tree object, its subtrees hashed first."""
    items = []
    for name, value in node.items():
        raw = os.fsencode(name)  # the bytes git read from the filesystem
        if isinstance(value, dict):
            items.append((raw + b"/", b"40000", raw, _hash_tree(value, algo)))
        else:
            items.append((raw, value[0], raw, value[1]))
    items.sort(key=lambda item: item[0])
    body = b"".join(mode + b" " + raw + b"\0" + oid for _, mode, raw, oid in items)
    digest = hashlib.new(algo)
    digest.update(b"tree %d\0" % len(body))
    digest.update(body)
    return digest.digest()


def _hash_symlink(path: str, algo: str) -> Optional[str]:
    """A symlink's blob is its target text, as git stores it."""
    try:
        target = os.fsencode(os.readlink(path))
    except OSError:
        return None
    return _blob_id(target, algo)


def _remaining(deadline: Optional[float], default: float) -> float:
    """A per-call timeout that does not outrun the overall deadline."""
    if deadline is None:
        return default
    return max(0.5, min(default, deadline - time.monotonic()))


def _plain_dir_digest(
    path: str,
    algo: str,
    deadline: Optional[float],
    cache: Optional[Dict[str, List[Any]]] = None,
    fresh: Optional[Dict[str, List[Any]]] = None,
    prefix: str = "",
    found_links: Optional[List[str]] = None,
    budget: Optional[List[int]] = None,
    prune: Optional["set[str]"] = None,
    covered: Optional[Any] = None,
) -> Optional[str]:
    """Content of a directory as one digest, every file in it; ``""`` when empty.

    Used for submodules and repositories inside the checkout: their own ``.gitignore`` and
    index are theirs to write, so nothing in them is consulted. Files are hashed raw (through
    the outer stat cache, keyed ``prefix/relative``); caches and ``.git`` are skipped and
    symlinked directories are hashed as links, not followed. Every symlink met is added to
    ``found_links`` so the caller can follow the ones that leave the tree. ``budget`` is
    ``[files, bytes]`` still allowed (bytes count only files hashed now, so a reading cut off
    by it resumes); past it the digest is ``None``. Directories in ``prune`` are not entered,
    and files ``covered(full_path)`` vouches for are counted elsewhere and left out.

    A directory that cannot be listed makes the digest ``None``: a file in it can still be
    opened by exact path.
    """
    now_ns = time.time_ns()
    lines: List[str] = []
    errors: List[OSError] = []
    if prune and path in prune:
        return ""
    for current, dirs, files in os.walk(path, onerror=errors.append):
        # Checked per directory as well as per file: a tree of empty directories has no file
        # to check at.
        if deadline is not None and time.monotonic() > deadline:
            return None
        if budget is not None:
            budget[0] -= 1
            if budget[0] < 0:
                return None
        # A symlinked directory is not followed (os.walk would skip it silently): its target
        # text is hashed like a symlinked file's, so retargeting it changes the digest.
        links = [d for d in dirs if os.path.islink(os.path.join(current, d))]
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in _CACHE_NAMES
            and d != ".git"
            and d not in links
            and not (prune and os.path.join(current, d) in prune)
        )
        for name in sorted([*files, *links]):
            if deadline is not None and time.monotonic() > deadline:
                return None
            full = os.path.join(current, name)
            if covered is not None and covered(full):
                continue
            try:
                info = os.lstat(full)
            except OSError:
                return None
            relative = os.path.relpath(full, path)
            if stat.S_ISLNK(info.st_mode):
                mode = "120000"
                if found_links is not None:
                    found_links.append(full)
            elif stat.S_ISREG(info.st_mode):
                mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
            else:
                continue
            if budget is not None:
                budget[0] -= 1
                if budget[0] < 0:
                    return None
            key = [info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino, mode, algo]
            cached = (cache or {}).get(prefix + relative)
            if cached is not None and cached[:6] == key:
                oid = cached[6]
            elif mode == "120000":
                oid = _hash_symlink(full, algo)
            else:
                if budget is not None:
                    budget[1] -= info.st_size
                    if budget[1] < 0:
                        return None
                oid = _hash_file(full, info, algo, deadline)
            if oid is None:
                return None
            if fresh is not None and now_ns - info.st_mtime_ns > _RACY_NS:
                if now_ns - info.st_ctime_ns > _RACY_NS:
                    fresh[prefix + relative] = key + [oid]
            lines.append(f"{relative}\0{info.st_mode & 0o170777:o}\0{oid}")
    if errors:
        return None
    if not lines:
        return ""
    return "p" + hashlib.sha256(os.fsencode("\n".join(lines))).hexdigest()


# Stat-cache keys for files read through a symlink are absolute paths behind this prefix; a
# path from git is relative and never starts with "/".
_OUTSIDE_PREFIX = "//"
# What may be read through symlinks, all links together: files walked, and bytes hashed now
# (cached files cost nothing, so a reading cut off by the byte budget resumes). Past either the
# reading is unknown: a link to a home directory or a dataset cannot be vouched for in a hook.
_OUTSIDE_MAX_FILES = 20000
_OUTSIDE_MAX_BYTES = 512 * 1024 * 1024


def _linked_targets(
    root: str,
    git_dir: str,
    links: List[str],
    from_disk: "set[str]",
    algo: str,
    deadline: Optional[float],
    cache: Dict[str, List[Any]],
    fresh: Dict[str, List[Any]],
) -> Optional[List[str]]:
    """What symlinks point at that the fingerprint does not otherwise read, one record per link.

    The tree holds a link's text, but the tests load what it points at. Behind
    ``src/impl.py -> /elsewhere/impl.py``, ``-> ../build/impl.py`` (ignored) or
    ``-> ../.git/impl.py``, an edit to the target changed nothing the tree records. A target
    is skipped only when it is a file inside the tree that was hashed from disk
    (``from_disk``). Otherwise each link gives ``link NUL target NUL digest``: the file's blob
    id, a directory's content digest (files inside the tree hashed from disk, the tree itself
    when the target holds it, and ``.git`` are left out; links inside are followed the same
    way), ``absent``, or the file type of a FIFO or device, which is never opened. Each target
    is read once.

    ``None`` past the deadline, when something cannot be read or listed, or past the file or
    byte budget: unknown, never partial.
    """
    real_root = os.path.realpath(root)
    root_prefix = os.path.join(root, "")
    real_prefix = os.path.join(real_root, "")
    # The tree and its git directory are read by the fingerprint itself, and the stat cache is
    # rewritten by every reading: a link to a directory holding any of them leaves them out.
    prune = {real_root, os.path.realpath(git_dir), os.path.realpath(_cache_dir())}

    def counted(full: str) -> bool:
        return full.startswith(real_prefix) and full[len(real_prefix) :] in from_disk

    budget = [_OUTSIDE_MAX_FILES, _OUTSIDE_MAX_BYTES]
    done: Dict[str, str] = {}
    records: List[str] = []
    queue = list(links)
    now_ns = time.time_ns()
    while queue:
        if deadline is not None and time.monotonic() > deadline:
            return None
        link = queue.pop()
        target = os.path.realpath(link)
        digest = done.get(target)
        if digest is None:
            try:
                info = os.lstat(target)
            except OSError:
                digest = "absent"
            else:
                if stat.S_ISREG(info.st_mode):
                    if counted(target):
                        done[target] = ""
                        continue  # an entry of its own, hashed from disk
                    budget[0] -= 1
                    if budget[0] < 0:
                        return None
                    mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
                    key = [
                        info.st_size,
                        info.st_mtime_ns,
                        info.st_ctime_ns,
                        info.st_ino,
                        mode,
                        algo,
                    ]
                    cached = cache.get(_OUTSIDE_PREFIX + target)
                    if cached is not None and cached[:6] == key:
                        digest = cached[6]
                    else:
                        budget[1] -= info.st_size
                        if budget[1] < 0:
                            return None
                        digest = _hash_file(target, info, algo, deadline)
                        if digest is None:
                            return None
                    if (
                        now_ns - info.st_mtime_ns > _RACY_NS
                        and now_ns - info.st_ctime_ns > _RACY_NS
                    ):
                        fresh[_OUTSIDE_PREFIX + target] = key + [digest]
                    digest = f"{mode}:{digest}"
                elif stat.S_ISDIR(info.st_mode):
                    inner: List[str] = []
                    sub = _plain_dir_digest(
                        target,
                        algo,
                        deadline,
                        cache,
                        fresh,
                        _OUTSIDE_PREFIX + os.path.join(target, ""),
                        inner,
                        budget,
                        # A link straight at the git directory is followed (its content is
                        # not otherwise read); one at the tree itself reads nothing new.
                        prune - {target} if target != real_root else prune,
                        counted,
                    )
                    if sub is None:
                        return None
                    queue.extend(inner)
                    digest = f"dir:{sub}"
                elif stat.S_ISLNK(info.st_mode):
                    # realpath stops at a loop: the link it stopped at is named by its text.
                    try:
                        digest = "loop:" + os.readlink(target)
                    except OSError:
                        return None
                else:
                    digest = f"type:{stat.S_IFMT(info.st_mode):o}"
            done[target] = digest
        if not digest:
            continue
        label = link[len(root_prefix) :] if link.startswith(root_prefix) else link
        records.append(f"{label}\0{target}\0{digest}")
    return sorted(records)


def _bounded_linked_targets(
    root: str,
    git_dir: str,
    links: List[str],
    from_disk: "set[str]",
    algo: str,
    deadline: Optional[float],
    cache: Dict[str, List[Any]],
    fresh: Dict[str, List[Any]],
) -> Optional[List[str]]:
    """``_linked_targets`` on a daemon thread, given up at the deadline.

    ``realpath`` and ``lstat`` on an attacker-chosen target (an automount such as ``/net``)
    can block in the kernel, where no deadline check runs; the hook stops waiting instead.
    The thread only reads ``cache`` and writes a dict of its own, merged into ``fresh`` when
    it finished in time, so a thread left behind changes nothing.
    """
    own: Dict[str, List[Any]] = {}
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["records"] = _linked_targets(
                root, git_dir, links, from_disk, algo, deadline, cache, own
            )
        except Exception:
            box["records"] = None

    if links:
        thread = threading.Thread(target=run, name="ysk-watch-links", daemon=True)
        try:
            thread.start()
        except RuntimeError:
            run()
        else:
            thread.join(_remaining(deadline, _STAGE_TIMEOUT_S))
            if thread.is_alive():
                return None
    else:
        box["records"] = []
    records = box.get("records")
    if records is not None:
        fresh.update(own)
    return records


def _nested_entry(
    path: str,
    recorded: str,
    algo: str,
    deadline: Optional[float],
    cache: Dict[str, List[Any]],
    fresh: Dict[str, List[Any]],
    prefix: str,
    found_links: Optional[List[str]] = None,
) -> Optional[Tuple[str, str]]:
    """``(commit, content digest)`` for a repository inside the working tree.

    A submodule, or an untracked repository someone created in the checkout, is code the
    tests can import, and an uncommitted edit in it changes nothing the outer repository
    records. Its files are all hashed (``_plain_dir_digest``) and the digest is folded into
    the outer name; its own ``.gitignore`` hides nothing. The commit is its HEAD when it has
    one, else the one the outer tree records.
    """
    if deadline is not None and time.monotonic() > deadline:
        return None

    def bounded(args: List[str]) -> str:
        # The nested repository's config is the agent's to write (an include of a FIFO blocks
        # git), so each call gets only what is left of the deadline.
        ok, out = _run_git(path, args, timeout=_remaining(deadline, _GIT_TIMEOUT_S))
        return out if ok else ""

    head = ""
    if os.path.lexists(os.path.join(path, ".git")):
        toplevel = bounded(["rev-parse", "--show-toplevel"]).strip()
        if toplevel and os.path.realpath(toplevel) == os.path.realpath(path):
            head = bounded(["rev-parse", "--verify", "-q", "HEAD"]).strip()
    digest = _plain_dir_digest(path, algo, deadline, cache, fresh, prefix, found_links)
    if digest is None:
        return None
    return (head or recorded), digest


def _hash_linked_docs(
    root: str,
    entries: Dict[str, Tuple[str, str]],
    algo: str,
    deadline: Optional[float],
    from_disk: "set[str]",
) -> bool:
    """A code path that is a symlink to a prose file makes that file code.

    Prose keeps its HEAD version in the fingerprint; through a symlink, its current bytes are
    what gets imported, so they are hashed. ``False`` when such a file cannot be read.
    """
    for path, (mode, _) in list(entries.items()):
        if mode != "120000" or is_doc(path):
            continue
        try:
            link = os.readlink(os.path.join(root, path))
        except OSError:
            continue
        target = os.path.normpath(os.path.join(os.path.dirname(path), link))
        if os.path.isabs(link) or target.startswith("..") or not is_doc(target):
            continue
        full = os.path.join(root, target)
        try:
            info = os.lstat(full)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        oid = _hash_file(full, info, algo, deadline)
        if oid is None:
            return False
        entries[target] = ("100755" if info.st_mode & stat.S_IXUSR else "100644", oid)
        from_disk.add(target)
    return True


def tree_fingerprint(
    directory: Optional[str],
    *,
    include_docs: bool = False,
    deadline: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """The git tree id of the working tree as it is on disk, docs excluded.

    Every path in HEAD, in the index and untracked (non-ignored) is looked at on disk and
    its content hashed raw: no filter driver, eol, ident or encoding conversion, fsmonitor or
    index stat cache the repository configures is used, and assume-unchanged and skip-worktree
    marks do not hide a file. The untracked listing is taken against a throwaway index read
    from HEAD, so an index that calls a directory a submodule hides nothing in it. Only
    ``.gitignore`` files hide an untracked file; one that ignores itself counts as content.
    The tree id of those entries is the fingerprint, computed in memory as ``git write-tree``
    would. Names git would drop (an HFS or NTFS spelling of ``.git``, a file where a directory
    is) still count; nothing is handed to git to build.
    The repository's own index and object store are only read. Unchanged files are recognized
    by the watcher's own stat cache; the rest are hashed on a few threads.

    The name depends on file contents and nothing else: ``git add`` and ``git commit`` after
    a green run leave it unchanged, while any content change, however it was made, changes
    it. Prose files (``.md``, ``.rst``, ``.adoc``) keep their HEAD version, so a README edit
    after a green run is not stale evidence. Submodules and nested repositories fold in their
    own fingerprints. A file checked out with converted line endings differs from its HEAD
    blob, consistently: it is reported as changed, and it never hides a later edit.

    ``deadline`` (a ``time.monotonic()`` value) bounds the whole call. Files hashed before it
    passes are remembered, so a large first fingerprint finishes over several calls.

    Returns ``None`` outside a repository, before the first commit, when the repository's
    config points git at another working tree, when git fails, or at the deadline. Callers
    decide what an unknown tree means; this function never guesses.
    """
    try:
        return _tree_fingerprint(directory, include_docs, deadline)
    except Exception:
        # Anything unexpected (a RecursionError from a long symlink chain in Python 3.11's
        # realpath, a thread that cannot start) is an unread tree, never an exception that
        # stops the hook and lets the claim through.
        return None


def _tree_fingerprint(
    directory: Optional[str], include_docs: bool, deadline: Optional[float]
) -> Optional[Dict[str, Any]]:
    root = repo_root(directory)
    if not root or not _within(directory, root):
        return None
    head = git(root, ["rev-parse", "HEAD"]).strip()
    git_dir = git(root, ["rev-parse", "--absolute-git-dir"]).strip()
    objects_path = _git_path(root, "objects")
    if not head or not git_dir or not objects_path:
        return None
    algo = git(root, ["rev-parse", "--show-object-format"]).strip() or "sha1"
    if algo not in _OBJECT_FORMATS:
        return None
    filters = filter_overrides(root)
    if filters is None:
        return None
    try:
        _sweep_stale_temp_dirs()
        with tempfile.TemporaryDirectory(prefix=_TEMP_PREFIX) as tmp:
            head_env = dict(_base_env(), GIT_INDEX_FILE=os.path.join(tmp, "head-index"))
            # Three independent reads of the repository, run side by side.
            head_entries, index_entries, read_head = _concurrently(
                lambda: _head_entries(root, filters, _remaining(deadline, _STAGE_TIMEOUT_S)),
                lambda: _index_entries(root, filters, _remaining(deadline, _STAGE_TIMEOUT_S)),
                lambda: _run_git(
                    root,
                    ["read-tree", "HEAD"],
                    env=head_env,
                    timeout=_remaining(deadline, _STAGE_TIMEOUT_S),
                    extra_config=filters,
                )[0],
            )
            if head_entries is None or index_entries is None or read_head is not True:
                return None
            return _fingerprint_in(
                tmp,
                root,
                head,
                git_dir,
                algo,
                filters,
                head_entries,
                index_entries,
                head_env,
                include_docs,
                deadline,
            )
    except OSError:
        return None


def _base_env() -> Dict[str, str]:
    """The inherited environment without the variables that point git at another repository."""
    env = dict(os.environ)
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return env


def _concurrently(*calls: Any) -> List[Any]:
    """Run independent calls on daemon threads; each result, or ``None`` if it raised."""
    results: List[Any] = [None] * len(calls)

    def run(i: int) -> None:
        try:
            results[i] = calls[i]()
        except Exception:
            results[i] = None

    started = []
    for i in range(len(calls)):
        thread = threading.Thread(target=run, args=(i,), name="ysk-watch-git", daemon=True)
        try:
            thread.start()
        except RuntimeError:  # no thread to be had: run it here instead
            run(i)
            continue
        started.append(thread)
    for thread in started:
        thread.join()
    return results


def _fingerprint_in(
    tmp: str,
    root: str,
    head: str,
    git_dir: str,
    algo: str,
    filters: Tuple[Tuple[str, str], ...],
    head_entries: Dict[str, Tuple[str, str]],
    index_entries: Dict[str, Tuple[str, str, str]],
    head_env: Dict[str, str],
    include_docs: bool,
    deadline: Optional[float],
) -> Optional[Dict[str, Any]]:
    """``tree_fingerprint``'s work, with ``tmp`` as the scratch directory and ``head_env``'s
    index already read from HEAD."""
    listed, gitignores = _concurrently(
        lambda: _untracked_paths(root, filters, head_env, _remaining(deadline, _STAGE_TIMEOUT_S)),
        lambda: _ignored_gitignores(
            root, filters, head_env, _remaining(deadline, _STAGE_TIMEOUT_S)
        ),
    )
    if listed is None or gitignores is None:
        return None
    untracked, nested_repos = listed
    tracked_dirs = set()
    for path in head_entries:
        parent = os.path.dirname(path)
        while parent and parent not in tracked_dirs:
            tracked_dirs.add(parent)
            parent = os.path.dirname(parent)
    gitignores = [path for path in gitignores if not _tool_owned(root, path, tracked_dirs)]

    # Index names are candidates too (a file staged and then hidden), but never a gitlink the
    # index alone records: that directory's files come from the HEAD-index listing above.
    index_names = [path for path, (mode, _, _) in index_entries.items() if mode != "160000"]
    candidates: Dict[str, None] = {}
    for path in (*head_entries, *index_names, *untracked, *gitignores):
        candidates.setdefault(path, None)
    cache_path = _stat_cache_path(git_dir)
    cache = _load_stat_cache(cache_path)
    fresh: Dict[str, List[Any]] = {}
    entries: Dict[str, Tuple[str, str]] = {}
    nested: List[Tuple[str, str]] = []
    now_ns = time.time_ns()

    def give_up() -> None:
        # Keep what was hashed so the next call does not start over.
        if fresh:
            _save_stat_cache(cache_path, {**cache, **fresh})

    linked: Dict[str, bool] = {}

    def under_link(parent: str) -> bool:
        """Whether ``parent`` or a directory between it and the root is a symlink.

        Each directory is looked at once (one ``lstat``) however many paths sit under it.
        ``realpath`` per path did the same check with one ``lstat`` per component per path.
        """
        if not parent:
            return False
        chain = []
        here = parent
        while here and here not in linked:
            chain.append(here)
            here = os.path.dirname(here)
        known = linked[here] if here else False
        for directory in reversed(chain):
            known = known or os.path.islink(os.path.join(root, directory))
            linked[directory] = known
        return linked[parent]

    def remember(path: str, info: os.stat_result, key: List[Any], oid: str) -> None:
        if now_ns - info.st_mtime_ns > _RACY_NS and now_ns - info.st_ctime_ns > _RACY_NS:
            fresh[path] = key + [oid]

    # Every symlink in the tree (and in nested repositories), followed after the walk, and
    # every path whose content was read from disk rather than kept from HEAD.
    symlinks: List[str] = []
    from_disk: "set[str]" = set()
    # Regular files the stat cache does not vouch for, hashed together after the walk.
    pending: List[Tuple[str, str, os.stat_result, str, List[Any]]] = []
    for walked, path in enumerate(candidates):
        # The walk only stats files, so the deadline is checked every few hundred paths (and
        # before each nested repository); the hashing that follows checks it on every read and
        # keeps what it finished.
        if deadline is not None and walked % 256 == 0 and time.monotonic() > deadline:
            give_up()
            return None
        if _CACHE_PATH_RE.search(path):
            continue
        if under_link(os.path.dirname(path)):
            # An ancestor is a symlink (a directory replaced by a link): the link itself is the
            # entry, as with ``git add -A``; what it points at is outside this tree.
            continue
        if not include_docs and is_doc(path):
            if path in head_entries:
                entries[path] = head_entries[path]
            continue
        recorded_head = head_entries.get(path)
        full = os.path.join(root, path)
        try:
            info = os.lstat(full)
        except OSError:
            # Absent: deleted, whatever the index marks say. (A sparse checkout reads as
            # deleted files, the same way every time; ``core.sparseCheckout`` is the agent's to
            # set, so it cannot excuse a deletion.)
            continue
        if recorded_head and recorded_head[0] == "160000" and stat.S_ISDIR(info.st_mode):
            sub = _nested_entry(
                full, recorded_head[1], algo, deadline, cache, fresh, path + "/", symlinks
            )
            if sub is None:
                give_up()
                return None
            entries[path] = ("160000", sub[0])
            if sub[1]:
                nested.append((path, sub[1]))
            continue
        if stat.S_ISLNK(info.st_mode):
            mode = "120000"
            if os.path.basename(path) not in _CACHE_NAMES:
                # A link named like a cache (``.venv -> ~/.virtualenvs/x``) is a cache, as
                # the directory of that name would be.
                symlinks.append(full)
        elif stat.S_ISREG(info.st_mode):
            mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
        else:
            continue  # a directory where a file was (its files are untracked), or a device
        key = [info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino, mode, algo]
        cached = cache.get(path)
        if cached is not None and cached[:6] == key:
            oid = cached[6]
        elif mode == "120000":
            oid = _hash_symlink(full, algo)
            if oid is None:
                give_up()
                return None
        else:
            pending.append((path, full, info, mode, key))
            continue
        entries[path] = (mode, oid)
        from_disk.add(path)
        remember(path, info, key, oid)
    if pending:
        oids = _hash_files([(full, info) for _, full, info, _, _ in pending], algo, deadline)
        unread = False
        for (path, _, info, mode, key), hashed in zip(pending, oids):
            if hashed is None:
                unread = True  # changed while read, unreadable, or the deadline passed
                continue
            entries[path] = (mode, hashed)
            from_disk.add(path)
            remember(path, info, key, hashed)
        if unread:
            give_up()
            return None
    for path in nested_repos:
        # An untracked repository inside the checkout: importable code, not committed here.
        sub = _nested_entry(
            os.path.join(root, path), "", algo, deadline, cache, fresh, path + "/", symlinks
        )
        if sub is None:
            give_up()
            return None
        if sub[1]:
            nested.append((path + "/", sub[1]))
    if not include_docs and not _hash_linked_docs(root, entries, algo, deadline, from_disk):
        give_up()
        return None
    outside = _bounded_linked_targets(
        root, git_dir, symlinks, from_disk, algo, deadline, cache, fresh
    )
    if outside is None:
        give_up()
        return None
    if fresh != cache:
        _save_stat_cache(cache_path, fresh)

    built = _tree_id(entries, algo)
    if built is None:
        return None
    tree, clashes = built

    changes = {
        path: (entries[path][1] if path in entries else "", path in head_entries)
        for path in {**head_entries, **entries}
        if entries.get(path) != head_entries.get(path)
    }
    changed = sorted(path for path in changes if include_docs or not is_doc(path))
    changed += sorted(path for path, _ in nested if path.endswith("/"))
    # The full id: a 48-bit prefix is a birthday search away for an agent that writes both
    # the code a green run sees and the code it swaps in. ``short`` is for display only.
    name = tree
    if nested or clashes or outside:
        folded = tree + "".join(f"\n{path}\0{inner}" for path, inner in sorted(nested))
        # Entries no tree can hold (a file where a directory is). The \x01 marker keeps them
        # apart from the nested digests.
        folded += "".join(f"\n\x01{path}\0{mode}\0{oid}" for path, mode, oid in clashes)
        # What symlinks leaving the tree point at; \x02 keeps these apart too.
        folded += "".join(f"\n\x02{record}" for record in outside)
        name = "s" + hashlib.sha256(os.fsencode(folded)).hexdigest()
    return {
        "hash": name,
        "short": name[:12],
        "tree": tree,
        "head": head[:7],
        "head_full": head,
        "root": root,
        "paths": changed[:20],
        "count": len(changed),
        # path -> (object id, or "" when deleted; whether HEAD has it), for every path that
        # differs from HEAD. Lets a caller tell what changed between two readings.
        "changes": changes,
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
        "hash": "d" + digest,
        "short": "d" + digest[:11],
        "tree": digest,
        "head": "",
        "root": root,
        "paths": [],
        "count": len(entries),
        "kind": "directory",
    }


def fingerprint(
    directory: Optional[str], *, deadline: Optional[float] = None
) -> Optional[Dict[str, Any]]:
    """The git tree fingerprint inside a repository, the directory fingerprint outside one.

    Never raises: any failure is ``None``, an unread tree.
    """
    try:
        return _fingerprint(directory, deadline)
    except Exception:
        return None


def _fingerprint(directory: Optional[str], deadline: Optional[float]) -> Optional[Dict[str, Any]]:
    if not directory:
        return None
    if repo_root(directory):
        return tree_fingerprint(directory, deadline=deadline)
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
    # Never a second fingerprint here: the caller's ran under a deadline, and an unread tree
    # stays unread rather than being read again without one.
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
