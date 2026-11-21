"""The fingerprint's fast paths name exactly the tree the git-only path named.

The tree id is built in memory instead of by ``update-index`` and ``write-tree``, files the
stat cache does not vouch for are hashed on several threads, and the symlinked-ancestor check
looks at each directory once. The tree must be the one git writes for every input git accepts,
and the inputs git would quietly drop must still count.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture
def evidence():
    spec = importlib.util.spec_from_file_location("ysk_fp_speed", PLUGIN_DIR / "evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    run_env = dict(env or os.environ)
    probe = subprocess.run(
        ["git", "-C", str(repo), "config", "user.email"], capture_output=True, text=True
    )
    if not probe.stdout.strip():  # CI runners have no identity configured
        run_env.update(
            GIT_AUTHOR_NAME="ysk test",
            GIT_AUTHOR_EMAIL="test@example.invalid",
            GIT_COMMITTER_NAME="ysk test",
            GIT_COMMITTER_EMAIL="test@example.invalid",
        )
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=run_env, check=True
    )
    return proc.stdout


def _init(path: Path, *init_args: str) -> Path:
    path.mkdir(parents=True)
    try:
        subprocess.run(
            ["git", "init", "-q", *init_args, str(path)], check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        pytest.skip(f"git cannot init {init_args}")
    return path


def _awkward_tree(repo: Path) -> None:
    """Names whose order git decides with its ``name/`` rule, plus every entry mode."""
    # The directory ``a`` sorts as ``a/``: after ``a-b`` and ``a.b``, before ``a0``.
    for name in ("a.b", "a-b", "a0", "Z", "z", "space name.py"):
        (repo / name).write_text(f"{name}\n")
    (repo / ".gitignore").write_text("*.log\n")
    for name in ("a/x.py", "a/b/c.txt", "ab/x", "unicode/été.py", ".github/ci.yml"):
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(f"{name}\n")
    deep = repo.joinpath(*[f"d{i}" for i in range(40)])
    deep.mkdir(parents=True)
    (deep / "leaf.py").write_text("leaf\n")
    tool = repo / "tool.sh"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    os.symlink("a/x.py", repo / "link.py")


def _index_entries(repo: Path) -> dict:
    entries = {}
    for line in _git(repo, "ls-files", "-s", "-z").split("\0"):
        if line:
            meta, _, path = line.partition("\t")
            mode, oid, _stage = meta.split()
            entries[path] = (mode, oid)
    return entries


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_the_in_memory_tree_is_the_one_git_writes(evidence, tmp_path, object_format):
    repo = _init(tmp_path / "r", f"--object-format={object_format}")
    _awkward_tree(repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    head = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},vendor/sub")
    entries = _index_entries(repo)
    assert {mode for mode, _ in entries.values()} == {"100644", "100755", "120000", "160000"}
    assert evidence._tree_id(entries, object_format) == (_git(repo, "write-tree").strip(), [])


def test_an_empty_tree_is_gits_empty_tree(evidence):
    assert evidence._tree_id({}, "sha1") == ("4b825dc642cb6eb9a060e54bf8d69288fbee4904", [])


OID = "a" * 40
OTHER = "b" * 40


def test_modes_are_recorded_as_an_index_records_them(evidence):
    def tree(mode):
        return evidence._tree_id({"x": (mode, OID)}, "sha1")[0]

    assert tree("100664") == tree("100644") != tree("100775") == tree("100755")


@pytest.mark.parametrize(
    "entry",
    [
        ("040000", OID),
        ("100644", OID[:-1]),
        ("100644", "g" * 40),
        ("100644", OID[:-2] + "  "),
        ("100644", "0" * 40),
    ],
)
def test_a_mode_no_index_records_or_a_bad_id_is_no_tree(evidence, entry):
    assert evidence._tree_id({"x": entry}, "sha1") is None


@pytest.mark.parametrize(
    "path",
    [
        ".git/config",
        "x/.GIT/y",
        "x/.git /y",
        "GIT~1/conftest.py",
        ".git.:x/y",
        ".g\u200cit/y",
        "a\\b",
        "gitmod~1",
        ".gitmodules/x",
    ],
)
def test_names_git_would_drop_are_part_of_the_tree(evidence, path):
    """``update-index --index-info`` skips a path it refuses and still exits 0, so handing
    these to git would leave the file out of the fingerprint."""
    base = evidence._tree_id({"keep.py": ("100644", OID)}, "sha1")[0]
    with_it = evidence._tree_id({"keep.py": ("100644", OID), path: ("120000", OID)}, "sha1")
    changed = evidence._tree_id({"keep.py": ("100644", OID), path: ("120000", OTHER)}, "sha1")
    assert with_it[1] == [] and len({base, with_it[0], changed[0]}) == 3


def test_a_file_where_a_directory_is_comes_back_beside_the_tree(evidence):
    entries = {"notes.md": ("100644", OID), "notes.md/conftest.py": ("100644", OTHER)}
    tree, clashes = evidence._tree_id(entries, "sha1")
    assert clashes == [("notes.md/conftest.py", "100644", OTHER)]
    reordered = dict(reversed(list(entries.items())))
    assert evidence._tree_id(reordered, "sha1") == (tree, clashes)


def _staged_tree(repo: Path) -> str:
    """``git add -A`` into a throwaway index and object directory: what a full stage names."""
    with tempfile.TemporaryDirectory() as tmp:
        index = os.path.join(tmp, "index")
        objects = os.path.join(tmp, "objects")
        os.mkdir(objects)
        shutil.copy2(repo / ".git" / "index", index)
        env = dict(
            os.environ,
            GIT_INDEX_FILE=index,
            GIT_OBJECT_DIRECTORY=objects,
            GIT_ALTERNATE_OBJECT_DIRECTORIES=str(repo / ".git" / "objects"),
        )
        _git(repo, "add", "-A", env=env)
        return _git(repo, "write-tree", env=env).strip()


def test_a_file_git_would_ignore_still_changes_the_fingerprint(evidence, tmp_path):
    repo = _init(tmp_path / "r")
    (repo / "keep.py").write_text("keep\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    hidden = repo / "GIT~1"
    hidden.mkdir()
    (hidden / "conftest.py").write_text("X = 1\n")
    before = evidence.tree_fingerprint(str(repo))
    (hidden / "conftest.py").write_text("X = 2\n")
    after = evidence.tree_fingerprint(str(repo))
    assert "GIT~1/conftest.py" in after["changes"]
    assert before["hash"] != after["hash"]


def test_code_put_where_a_prose_file_was_still_counts(evidence, tmp_path):
    repo = _init(tmp_path / "r")
    (repo / "notes.md").write_text("# notes\n")
    (repo / "keep.py").write_text("keep\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    (repo / "notes.md").unlink()
    (repo / "notes.md").mkdir()
    (repo / "notes.md" / "conftest.py").write_text("X = 1\n")
    before = evidence.tree_fingerprint(str(repo))
    (repo / "notes.md" / "conftest.py").write_text("X = 2\n")
    after = evidence.tree_fingerprint(str(repo))
    assert before is not None and after is not None
    assert before["hash"] != after["hash"]


def test_a_directory_replaced_by_a_symlink_is_the_link(evidence, tmp_path):
    repo = _init(tmp_path / "r")
    (repo / "src" / "deep").mkdir(parents=True)
    (repo / "src" / "deep" / "calc.py").write_text("ok\n")
    (repo / "keep.py").write_text("keep\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "deep").mkdir(parents=True)
    (elsewhere / "deep" / "calc.py").write_text("tampered\n")
    shutil.rmtree(repo / "src")
    os.symlink(elsewhere, repo / "src")
    fingerprint = evidence.tree_fingerprint(str(repo))
    assert fingerprint["tree"] == _staged_tree(repo)
    assert "src" in fingerprint["changes"] and "src/deep/calc.py" in fingerprint["changes"]
    assert fingerprint["changes"]["src/deep/calc.py"][0] == ""


def _files(root: Path, count: int) -> list:
    root.mkdir()
    items = []
    for i in range(count):
        path = root / f"f{i}.bin"
        path.write_bytes(os.urandom(64 + i * 997))
        items.append((str(path), os.lstat(path)))
    return items


def test_parallel_hashing_gives_gits_blob_ids_in_order(evidence, tmp_path):
    items = _files(tmp_path / "files", 40)
    assert len(items) >= evidence._PARALLEL_MIN_FILES
    expected = [
        subprocess.run(
            ["git", "hash-object", "--no-filters", path], capture_output=True, text=True
        ).stdout.strip()
        for path, _ in items
    ]
    assert evidence._hash_files(items, "sha1", None) == expected


def test_a_file_changed_after_its_stat_is_not_hashed(evidence, tmp_path):
    items = _files(tmp_path / "files", 30)
    Path(items[7][0]).write_bytes(b"different length")
    results = evidence._hash_files(items, "sha1", None)
    assert results[7] is None
    assert all(oid for i, oid in enumerate(results) if i != 7)


def test_a_passed_deadline_hashes_nothing(evidence, tmp_path):
    items = _files(tmp_path / "files", 30)
    assert evidence._hash_files(items, "sha1", 0.0) == [None] * 30


def test_hashing_cut_short_keeps_its_work_for_the_next_reading(evidence, tmp_path, monkeypatch):
    import json
    import time

    repo = _init(tmp_path / "r")
    for i in range(40):
        (repo / f"m{i}.py").write_text(f"X = {i}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "many")
    time.sleep(2.2)  # past the racy window, so hashed files may be remembered
    real = evidence._hash_file
    budget = {"left": 10}

    def runs_out(path, info, algo, deadline=None):
        budget["left"] -= 1
        return real(path, info, algo, deadline) if budget["left"] >= 0 else None

    monkeypatch.setattr(evidence, "_hash_file", runs_out)
    assert evidence.tree_fingerprint(str(repo)) is None
    monkeypatch.setattr(evidence, "_hash_file", real)
    (cache,) = (tmp_path / "ysk-stat-cache").glob("*.json")
    assert len(json.loads(cache.read_text())["entries"]) == 10
    resumed = evidence.tree_fingerprint(str(repo))
    assert resumed["tree"] == _git(repo, "rev-parse", "HEAD^{tree}").strip()


def test_code_put_where_a_directory_of_prose_was_still_counts(evidence, tmp_path):
    """HEAD's prose is kept as it was, so ``calc.py/README.md`` and an on-disk ``calc.py`` meet
    in one listing. git would keep one and drop the other without a word."""
    repo = _init(tmp_path / "r")
    (repo / "calc.py").mkdir()
    (repo / "calc.py" / "README.md").write_text("# docs\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    shutil.rmtree(repo / "calc.py")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    before = evidence.tree_fingerprint(str(repo))
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    after = evidence.tree_fingerprint(str(repo))
    assert before["hash"] != after["hash"]


def test_hashing_works_when_no_thread_can_start(evidence, tmp_path, monkeypatch):
    import threading

    items = _files(tmp_path / "files", 30)
    expected = evidence._hash_files(items, "sha1", None)

    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    assert evidence._hash_files(items, "sha1", None) == expected
    assert evidence._concurrently(lambda: 1, lambda: 2) == [1, 2]
