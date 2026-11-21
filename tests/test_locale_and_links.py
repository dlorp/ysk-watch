"""Paths git prints are read as the filesystem names them, and symlinks out of the tree count.

Two ways an edit could change the code the tests ran on with the fingerprint unchanged: git's
output was decoded by the locale, so under a Latin-1 locale on a UTF-8 filesystem every
non-ASCII path read back as a file that did not exist; and a symlink that leaves the working
tree was recorded by its text only, so the file it points at could change unseen.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / file, submodule_search_locations=[str(PLUGIN_DIR)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def evidence():
    return _load("ysk_locale_links", "evidence.py")


def _git(repo: Path, *args: str) -> str:
    env = dict(os.environ)
    probe = subprocess.run(
        ["git", "-C", str(repo), "config", "user.email"], capture_output=True, text=True
    )
    if not probe.stdout.strip():  # CI runners have no identity configured
        env.update(
            GIT_AUTHOR_NAME="ysk test",
            GIT_AUTHOR_EMAIL="test@example.invalid",
            GIT_COMMITTER_NAME="ysk test",
            GIT_COMMITTER_EMAIL="test@example.invalid",
        )
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "proj"
    (path / "src").mkdir(parents=True)
    (path / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "initial")
    return path


# --- decoding ----------------------------------------------------------------------------------


def test_git_output_is_decoded_as_the_filesystem_encodes_paths(evidence):
    assert evidence.GIT_TEXT == {
        "encoding": sys.getfilesystemencoding(),
        "errors": sys.getfilesystemencodeerrors(),
    }


_CHILD = textwrap.dedent(
    """
    import importlib.util, json, locale, sys
    spec = importlib.util.spec_from_file_location("ev", sys.argv[1])
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)
    first = ev.tree_fingerprint(sys.argv[2])
    open(sys.argv[3], "w", encoding="utf-8").write("X = 2\\n")
    second = ev.tree_fingerprint(sys.argv[2])
    print(json.dumps({
        "locale": locale.getpreferredencoding(False),
        "changes": sorted(first["changes"]),
        "same": first["hash"] == second["hash"],
    }))
    """
)


def test_a_latin1_locale_still_sees_non_ascii_paths(evidence, repo, tmp_path):
    if sys.getfilesystemencoding().lower().replace("-", "") != "utf8":
        pytest.skip("needs a UTF-8 filesystem encoding")
    name = repo / "src" / "été.py"
    name.write_text("X = 1\n", encoding="utf-8")
    env = dict(
        os.environ,
        LC_ALL="en_US.ISO8859-1",
        LANG="en_US.ISO8859-1",
        PYTHONUTF8="0",
        PYTHONCOERCECLOCALE="0",
        YSK_WATCH_CACHE_DIR=str(tmp_path / "child-cache"),
    )
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, str(PLUGIN_DIR / "evidence.py"), str(repo), str(name)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    if result["locale"].lower().replace("-", "").replace("_", "") not in ("iso88591", "latin1"):
        pytest.skip(f"no Latin-1 locale on this host ({result['locale']})")
    assert "src/été.py" in result["changes"]
    assert result["same"] is False


def test_an_undecodable_path_is_read_and_can_be_written_out(evidence, repo):
    raw = os.path.join(os.fsencode(repo), b"src", b"bad\xff.py")
    try:
        with open(raw, "wb") as fh:
            fh.write(b"X = 1\n")
    except OSError:
        pytest.skip("this filesystem refuses names that are not UTF-8")
    first = evidence.tree_fingerprint(str(repo))
    with open(raw, "wb") as fh:
        fh.write(b"X = 2\n")
    second = evidence.tree_fingerprint(str(repo))
    assert first and second and first["hash"] != second["hash"]
    (path,) = [p for p in second["changes"] if p.startswith("src/bad")]
    assert os.fsencode(path) == b"src/bad\xff.py"
    shown = evidence.printable(path)
    shown.encode("utf-8")
    assert shown == "src/bad\\udcff.py"


def test_printable_leaves_ordinary_text_alone(evidence):
    text = "café — \U0001f600 tab\there"
    assert evidence.printable(text) is text


def test_redaction_makes_escaped_paths_writable():
    tripwires = _load("ysk_locale_tripwires", "tripwires.py")
    out = tripwires.redact("changed src/bad\udcff.py")
    out.encode("utf-8")
    assert "\\udcff" in out


# --- symlinks that leave the tree --------------------------------------------------------------


def test_an_edit_behind_a_symlinked_file_outside_the_tree_is_seen(evidence, repo, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "impl.py").write_text("X = 1\n")
    os.symlink(outside / "impl.py", repo / "src" / "impl.py")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "link")
    before = evidence.tree_fingerprint(str(repo))
    (outside / "impl.py").write_text("X = 3\n")
    after = evidence.tree_fingerprint(str(repo))
    assert before["tree"] == after["tree"]  # the link's text did not change
    assert before["hash"] != after["hash"]


def test_a_symlinked_directory_outside_the_tree_is_read_whole(evidence, repo, tmp_path):
    outside = tmp_path / "pkg"
    (outside / "sub").mkdir(parents=True)
    (outside / "mod.py").write_text("A = 1\n")
    os.symlink(outside, repo / "pkg")
    first = evidence.tree_fingerprint(str(repo))
    (outside / "sub" / "new.py").write_text("B = 1\n")
    second = evidence.tree_fingerprint(str(repo))
    (outside / "mod.py").write_text("A = 2\n")
    third = evidence.tree_fingerprint(str(repo))
    assert len({first["hash"], second["hash"], third["hash"]}) == 3


def test_links_inside_a_followed_directory_are_followed(evidence, repo, tmp_path):
    far = tmp_path / "far"
    far.mkdir()
    (far / "deep.py").write_text("D = 1\n")
    near = tmp_path / "near"
    near.mkdir()
    os.symlink(far / "deep.py", near / "deep.py")
    os.symlink(near, repo / "near")
    before = evidence.tree_fingerprint(str(repo))
    (far / "deep.py").write_text("D = 2\n")
    assert evidence.tree_fingerprint(str(repo))["hash"] != before["hash"]


def test_a_dangling_link_counts_until_its_target_appears(evidence, repo, tmp_path):
    target = tmp_path / "later.py"
    os.symlink(target, repo / "src" / "later.py")
    before = evidence.tree_fingerprint(str(repo))
    assert before is not None
    target.write_text("L = 1\n")
    assert evidence.tree_fingerprint(str(repo))["hash"] != before["hash"]


def test_a_link_loop_or_a_fifo_outside_is_named_not_read(evidence, repo, tmp_path):
    os.symlink(tmp_path / "loop-b", tmp_path / "loop-a")
    os.symlink(tmp_path / "loop-a", tmp_path / "loop-b")
    os.symlink(tmp_path / "loop-a", repo / "src" / "loop.py")
    os.mkfifo(tmp_path / "pipe")
    os.symlink(tmp_path / "pipe", repo / "src" / "pipe.py")
    assert evidence.tree_fingerprint(str(repo)) is not None


def test_too_much_behind_links_is_unknown_not_partial(evidence, repo, tmp_path, monkeypatch):
    big = tmp_path / "big"
    big.mkdir()
    for i in range(10):
        (big / f"f{i}.py").write_text(f"N = {i}\n")
    os.symlink(big, repo / "big")
    monkeypatch.setattr(evidence, "_OUTSIDE_MAX_FILES", 5)
    assert evidence.tree_fingerprint(str(repo)) is None
    monkeypatch.setattr(evidence, "_OUTSIDE_MAX_FILES", 50)
    assert evidence.tree_fingerprint(str(repo)) is not None


def test_links_that_stay_inside_change_nothing(evidence, repo):
    os.symlink("calc.py", repo / "src" / "alias.py")
    fingerprint = evidence.tree_fingerprint(str(repo))
    assert fingerprint["hash"] == fingerprint["tree"]


def test_a_link_out_of_a_nested_repository_is_followed(evidence, repo, tmp_path):
    outside = tmp_path / "shared.py"
    outside.write_text("S = 1\n")
    helpers = repo / "helpers"
    helpers.mkdir()
    subprocess.run(["git", "init", "-q", str(helpers)], check=True, capture_output=True)
    os.symlink(outside, helpers / "shared.py")
    before = evidence.tree_fingerprint(str(repo))
    outside.write_text("S = 2\n")
    assert evidence.tree_fingerprint(str(repo))["hash"] != before["hash"]


# --- review round: names, targets inside the tree, unreadable directories, bounds --------------


def test_names_are_full_length_ids(evidence, repo, tmp_path):
    plain = evidence.tree_fingerprint(str(repo))
    assert plain["hash"] == plain["tree"] and len(plain["hash"]) == 40
    assert plain["short"] == plain["hash"][:12]
    (tmp_path / "x.py").write_text("X = 1\n")
    os.symlink(tmp_path / "x.py", repo / "src" / "x.py")
    folded = evidence.tree_fingerprint(str(repo))
    assert folded["hash"].startswith("s") and len(folded["hash"]) == 65


def test_a_carriage_return_in_a_name_is_not_a_newline(evidence, repo):
    tracked = repo / "src" / "helper\r.py"
    tracked.write_text("H = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "cr")
    untracked = repo / "src" / "u\r.js"
    untracked.write_text("U = 1\n")
    before = evidence.tree_fingerprint(str(repo))
    assert "src/u\r.js" in before["changes"]
    tracked.write_text("H = 2\n")
    middle = evidence.tree_fingerprint(str(repo))
    untracked.write_text("U = 2\n")
    after = evidence.tree_fingerprint(str(repo))
    assert len({before["hash"], middle["hash"], after["hash"]}) == 3


@pytest.mark.parametrize("target", ["__pycache__/impl.py", ".git/impl.py", "build/impl.py"])
def test_a_link_to_a_file_the_tree_does_not_hash_reads_it(evidence, repo, target):
    (repo / ".gitignore").write_text("build/\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "ignore build")
    full = repo / target
    full.parent.mkdir(exist_ok=True)
    full.write_text("V = 1\n")
    os.symlink(os.path.relpath(full, repo / "src"), repo / "src" / "impl.py")
    before = evidence.tree_fingerprint(str(repo))
    full.write_text("V = 2\n")
    assert evidence.tree_fingerprint(str(repo))["hash"] != before["hash"]


def test_an_absolute_link_to_prose_in_the_tree_reads_it(evidence, repo):
    notes = repo / "notes.md"
    notes.write_text("one\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "notes")
    os.symlink(notes.resolve(), repo / "src" / "notes_loader.py")
    before = evidence.tree_fingerprint(str(repo))
    notes.write_text("two\n")
    assert evidence.tree_fingerprint(str(repo))["hash"] != before["hash"]


def test_a_link_to_a_file_the_tree_hashes_adds_nothing(evidence, repo):
    os.symlink((repo / "src" / "calc.py").resolve(), repo / "src" / "alias.py")
    fingerprint = evidence.tree_fingerprint(str(repo))
    assert fingerprint["hash"] == fingerprint["tree"]


def test_a_link_to_an_ancestor_does_not_read_the_tree_or_the_cache(evidence, repo):
    (repo / ".gitignore").write_text("build/\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "ignore build")
    os.symlink("..", repo / "up")
    before = evidence.tree_fingerprint(str(repo))
    (repo / "build").mkdir()
    (repo / "build" / "out.log").write_text("test output\n")
    again = evidence.tree_fingerprint(str(repo))
    assert again is not None and again["hash"] == before["hash"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
@pytest.mark.parametrize("where", ["untracked", "outside"])
def test_a_directory_that_cannot_be_listed_is_no_fingerprint(evidence, repo, tmp_path, where):
    base = repo / "pkg" if where == "untracked" else tmp_path / "out"
    hidden = base / "sub"
    hidden.mkdir(parents=True)
    (hidden / "m.py").write_text("M = 1\n")
    if where == "outside":
        os.symlink(base, repo / "lib")
    hidden.chmod(0o311)
    try:
        assert evidence.tree_fingerprint(str(repo)) is None
    finally:
        hidden.chmod(0o755)
    assert evidence.tree_fingerprint(str(repo)) is not None


def test_a_link_named_like_a_cache_is_a_cache(evidence, repo, tmp_path, monkeypatch):
    env = tmp_path / "venv-elsewhere"
    env.mkdir()
    for i in range(5):
        (env / f"f{i}.py").write_text("x\n")
    os.symlink(env, repo / ".venv")
    monkeypatch.setattr(evidence, "_OUTSIDE_MAX_FILES", 1)
    fingerprint = evidence.tree_fingerprint(str(repo))
    assert fingerprint is not None and fingerprint["hash"] == fingerprint["tree"]


def test_too_many_bytes_behind_links_is_unknown(evidence, repo, tmp_path, monkeypatch):
    (tmp_path / "weights.bin").write_bytes(b"\0" * 4096)
    os.symlink(tmp_path / "weights.bin", repo / "src" / "weights.bin")
    monkeypatch.setattr(evidence, "_OUTSIDE_MAX_BYTES", 1024)
    assert evidence.tree_fingerprint(str(repo)) is None
    monkeypatch.setattr(evidence, "_OUTSIDE_MAX_BYTES", 1 << 20)
    assert evidence.tree_fingerprint(str(repo)) is not None


def test_empty_directories_count_against_the_budget(evidence, repo, tmp_path, monkeypatch):
    out = tmp_path / "hollow"
    for i in range(50):
        (out / f"d{i}").mkdir(parents=True)
    os.symlink(out, repo / "hollow")
    monkeypatch.setattr(evidence, "_OUTSIDE_MAX_FILES", 10)
    assert evidence.tree_fingerprint(str(repo)) is None


def test_a_failure_anywhere_is_no_fingerprint_not_an_exception(
    evidence, repo, tmp_path, monkeypatch
):
    os.symlink(tmp_path / "t.py", repo / "src" / "t.py")

    def deep(path, *a, **k):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(evidence.os.path, "realpath", deep)
    assert evidence.tree_fingerprint(str(repo)) is None
    assert evidence.fingerprint(str(repo)) is None


def test_a_long_symlink_chain_never_raises(evidence, repo, tmp_path):
    chain = tmp_path / "chain"
    chain.mkdir()
    (chain / "end.py").write_text("E = 1\n")
    previous = "end.py"
    for i in range(1200):
        os.symlink(previous, chain / f"l{i}")
        previous = f"l{i}"
    os.symlink(chain / previous, repo / "src" / "impl.py")
    result = evidence.fingerprint(str(repo))
    assert result is None or "hash" in result


def test_a_cached_file_behind_a_link_still_sees_an_edit(evidence, repo, tmp_path):
    import time

    target = tmp_path / "shared.py"
    target.write_text("S = 1\n")
    os.symlink(target, repo / "src" / "shared.py")
    time.sleep(2.2)  # past the racy window, so the target is remembered
    first = evidence.tree_fingerprint(str(repo))
    assert evidence.tree_fingerprint(str(repo))["hash"] == first["hash"]
    stamp = target.stat()
    target.write_text("S = 2\n")
    os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))  # mtime put back
    assert evidence.tree_fingerprint(str(repo))["hash"] != first["hash"]
