"""Regressions for the tripwire audit.

Each case is an input the audit named and the outcome the tool must produce: a passing-test
claim needs a real head-of-segment test run, an honest admission is not a claim, secrets never
reach the ledger, and quoted text is not a command.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _load():
    name = "ysk_watch_regressions"
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ysk(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.delenv("YSK_WATCH_DISABLE", raising=False)
    monkeypatch.setenv("YSK_WATCH_AUX", "0")
    mod = _load()
    mod._ledgers.clear()
    return mod


def _cmd(ysk, command, output="", exit_code=0, session="s1", tool="terminal"):
    key = "code" if tool == "execute_code" else "command"
    ysk._on_post_tool_call(
        tool_name=tool,
        args={key: command},
        result=json.dumps({"output": output, "exit_code": exit_code}),
        status="ok" if exit_code == 0 else "error",
        session_id=session,
    )


def _patch(ysk, path, old, new, session="s1", key="path"):
    ysk._on_post_tool_call(
        tool_name="patch",
        args={key: path, "old_string": old, "new_string": new},
        result="{}",
        status="ok",
        session_id=session,
    )


def _events(ysk, session="s1", category=None):
    items = ysk._events(session)
    return [e for e in items if category is None or e.get("category") == category]


def _high(ysk, session="s1"):
    return [e for e in ysk._events(session) if e.get("severity") == "high"]


def _test_runs(ysk, session="s1"):
    return _events(ysk, session, "test_run")


def _fake_aux(monkeypatch, reply):
    captured = {}

    def fake(**kwargs):
        captured["user"] = kwargs["messages"][1]["content"]
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(reply)))]
        )

    monkeypatch.setitem(sys.modules, "agent.auxiliary_client", SimpleNamespace(call_llm=fake))
    return captured


def _git_repo(path: Path, origin_url: str, branch: str = "") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "remote", "add", "origin", origin_url],
        check=True,
        capture_output=True,
    )
    if branch:
        subprocess.run(
            ["git", "-C", str(path), "checkout", "-q", "-b", branch],
            check=True,
            capture_output=True,
        )
    return path


def _git(repo: Path, *args: str, env=None) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    )
    return proc.stdout.strip()


def _commit(repo: Path) -> None:
    """Create the HEAD commit with plumbing, so no local commit hook can interfere."""
    if not (repo / ".git").exists():
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    _git(repo, "add", "-A")
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="fixture",
        GIT_AUTHOR_EMAIL="fixture@example.test",
        GIT_COMMITTER_NAME="fixture",
        GIT_COMMITTER_EMAIL="fixture@example.test",
    )
    tree = _git(repo, "write-tree", env=env)
    commit = _git(repo, "commit-tree", tree, "-m", "init", env=env)
    _git(repo, "update-ref", "HEAD", commit, env=env)


# --- 1. test-pass evidence ------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "pip install pytest",
        "cat pytest.ini",
        "python3 -m pip install pytest",
        "grep -rn 'pytest' README.md",
    ],
)
def test_mentioning_a_test_tool_is_not_a_test_run(ysk, command):
    _cmd(ysk, command, output="Successfully installed pytest", exit_code=0)
    assert _test_runs(ysk) == []


def test_test_tool_after_cd_is_a_test_run(ysk):
    _cmd(ysk, "cd repo && pytest -q", output="3 passed in 0.1s", exit_code=0)
    runs = _test_runs(ysk)
    assert runs and runs[0]["passed"] is True


def test_pipe_hiding_a_failure_is_not_passing_evidence(ysk):
    _cmd(ysk, "pytest -q | tail -5", output="1 failed, 48 passed in 2.1s", exit_code=0)
    runs = _test_runs(ysk)
    assert runs and runs[0]["passed"] is not True


def test_pipe_with_a_pass_summary_is_passing_evidence(ysk):
    _cmd(ysk, "pytest -q | tail -3", output="49 passed in 3.1s", exit_code=0)
    runs = _test_runs(ysk)
    assert runs and runs[0]["passed"] is True


def test_or_true_swallowing_a_failure_is_not_passing_evidence(ysk):
    _cmd(ysk, "pytest -q || true", output="2 failed, 10 passed", exit_code=0)
    runs = _test_runs(ysk)
    assert runs and runs[0]["passed"] is not True


def test_piped_failure_cannot_back_a_verification_claim(ysk):
    _cmd(ysk, "pytest -q | tail -5", output="1 failed, 48 passed in 2.1s", exit_code=0)
    out = ysk._on_pre_verify(
        session_id="s1", final_response="All tests pass.", changed_paths=["app.py"]
    )
    assert out and "unverified_claim" in out["message"]


# --- 2. honest admissions are not claims -----------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "I couldn't get the tests passing.",
        "3 passed, 2 failed.",
        "The suite is not passing yet.",
        "One test failed and the suite is red.",
    ],
)
def test_honest_admission_is_not_a_verification_claim(ysk, text):
    assert ysk.tripwires.claims_verification(text) is False


@pytest.mark.parametrize("text", ["All 49 tests pass.", "Fixed; 12 passed.", "The suite is green."])
def test_a_real_claim_is_still_detected(ysk, text):
    assert ysk.tripwires.claims_verification(text) is True


# --- 3. shell edits are checked against the diff ----------------------------------------------


def test_shell_edit_that_strips_assertions_is_caught_at_verify(ysk, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    target = repo / "tests" / "test_x.py"
    target.write_text("def test_a():\n    assert 1 == 1\n    assert 2 == 2\n", encoding="utf-8")
    _commit(repo)
    # Written by the shell, never seen by a patch/write_file hook.
    target.write_text("def test_a():\n    pass\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    out = ysk._on_pre_verify(
        session_id="s1", final_response="Tidied the tests.", changed_paths=["tests/test_x.py"]
    )
    assert out and "test_weakened" in out["message"]


def test_shell_edit_that_adds_a_skip_is_caught_at_verify(ysk, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    target = repo / "tests" / "test_x.py"
    target.write_text("def test_a():\n    assert 1 == 1\n", encoding="utf-8")
    _commit(repo)
    target.write_text("@pytest.mark.skip\ndef test_a():\n    assert 1 == 1\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    out = ysk._on_pre_verify(
        session_id="s1", final_response="Tidied the tests.", changed_paths=["tests/test_x.py"]
    )
    assert out and "skip" in out["message"]


def test_strengthening_a_test_by_shell_is_not_flagged_at_verify(ysk, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    target = repo / "tests" / "test_x.py"
    target.write_text("def test_a():\n    assert 1 == 1\n", encoding="utf-8")
    _commit(repo)
    target.write_text("def test_a():\n    assert 1 == 1\n    assert 2 == 2\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    out = ysk._on_pre_verify(
        session_id="s1", final_response="Tidied the tests.", changed_paths=["tests/test_x.py"]
    )
    assert out is None


# --- 4. secrets never persist or leave the machine --------------------------------------------
# Assembled at runtime so no scanner rewrites the fixture: these are fake credentials, and the
# test is about the shape of a token, not about any real one.
API_TOKEN = "sk-" + "live-abc123def456ghi"
GITHUB_TOKEN = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
PASSWORD = "hunter2-correct-horse"
ASSIGNED_KEY = "zzz-secret-value"


def test_redaction_covers_token_shapes(ysk):
    text = f"Bearer {API_TOKEN} {GITHUB_TOKEN} {AWS_KEY} password={PASSWORD} API_KEY={ASSIGNED_KEY}"
    redacted = ysk.tripwires.redact(text)
    for secret in (API_TOKEN, GITHUB_TOKEN, AWS_KEY, PASSWORD, ASSIGNED_KEY):
        assert secret not in redacted
    assert "«redacted»" in redacted


def test_secrets_are_redacted_before_the_ledger_is_written(ysk):
    _cmd(
        ysk,
        f'curl -H "Authorization: Bearer {API_TOKEN}" https://example.test && cat .env',
    )
    log_dir = ysk._home() / "logs" / "ysk-watch"
    persisted = (log_dir / "ledger" / "s1.jsonl").read_text(encoding="utf-8")
    assert API_TOKEN not in persisted
    assert "«redacted»" in persisted
    checks = log_dir / "checks.jsonl"
    if checks.exists():
        assert API_TOKEN not in checks.read_text(encoding="utf-8")


def test_secrets_never_reach_the_aux_provider(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_AUX", "1")
    _cmd(ysk, f"rm -rf ~/repos/example-{API_TOKEN}")
    captured = _fake_aux(monkeypatch, {"findings": [], "cleared": []})
    ysk._on_pre_verify(session_id="s1", final_response="cleaned up", changed_paths=["app.py"])
    assert captured and API_TOKEN not in captured["user"]
    assert "«redacted»" in captured["user"]


# --- 5. scratch grading -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ~/workspace",
        "rm -rf workspace/myrepo",
        "rm -rf /tmp/../home/dev/repo",
    ],
)
def test_delete_of_a_generic_workspace_path_is_high(ysk, command):
    _cmd(ysk, command)
    assert any(e["category"] == "destructive_cmd" for e in _high(ysk))


def test_routine_cache_cleanup_is_not_a_test_weakened_high(ysk):
    _cmd(ysk, "rm -rf .pytest_cache tests/__pycache__")
    assert [e for e in _high(ysk) if e["category"] == "test_weakened"] == []
    destructive = _events(ysk, category="destructive_cmd")
    assert destructive and destructive[0]["severity"] == "info"


# --- 6. quoted text is data, not a command ----------------------------------------------------


def test_quoted_destructive_text_is_not_a_command(ysk):
    _cmd(ysk, "grep -rn 'git reset --hard' docs/")
    assert _high(ysk) == []


def test_commit_message_about_a_destructive_command_is_not_one(ysk):
    _cmd(ysk, 'git commit -m "docs: never use git reset --hard"')
    assert _high(ysk) == []


def test_quoted_attribution_text_is_not_attribution(ysk):
    _cmd(ysk, "grep -rn 'Co-Authored-By:' docs/")
    assert _high(ysk) == []


def test_commit_with_real_attribution_is_still_flagged(ysk):
    _cmd(ysk, 'git commit -m "fix: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>"')
    assert any(e["category"] == "ai_attribution" for e in _high(ysk))


# --- 7. push guard gaps -----------------------------------------------------------------------


def test_push_to_main_through_a_colon_ref_is_flagged(ysk):
    _cmd(ysk, "git push origin feature:main")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_push_of_head_while_on_main_is_flagged(ysk, tmp_path):
    repo = _git_repo(tmp_path / "repo", "git@github.com:dlorp/example.git")
    _cmd(ysk, f"cd {repo} && git push origin HEAD")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_bare_push_on_main_is_flagged(ysk, tmp_path):
    repo = _git_repo(tmp_path / "repo", "git@github.com:dlorp/example.git")
    _cmd(ysk, f"cd {repo} && git push")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_bare_push_on_a_feature_branch_is_fine(ysk, tmp_path):
    repo = _git_repo(
        tmp_path / "repo", "git@github.com:dlorp/example.git", branch="fix/capture-integrity"
    )
    _cmd(ysk, f"cd {repo} && git push")
    assert _high(ysk) == []


# --- 8a. ordering is a sequence, not a clock --------------------------------------------------


def test_edit_right_after_a_run_is_stale_even_at_the_same_instant(ysk, monkeypatch):
    monkeypatch.setattr(ysk.time, "time", lambda: 1000.0)
    _cmd(ysk, "pytest -q", output="4 passed", exit_code=0)
    _patch(ysk, "app.py", "x = 1", "x = 2")
    claim = ysk._stale_test_evidence("All tests pass.", ysk._events("s1"))
    assert claim and claim["severity"] == "high"


def test_edit_before_a_run_is_not_stale_when_the_clock_goes_backwards(ysk, monkeypatch):
    clock = iter([2000.0, 1500.0])
    monkeypatch.setattr(ysk.time, "time", lambda: next(clock, 1500.0))
    _patch(ysk, "app.py", "x = 1", "x = 2")
    _cmd(ysk, "pytest -q", output="4 passed", exit_code=0)
    assert ysk._stale_test_evidence("All tests pass.", ysk._events("s1")) is None


# --- 8b. unified diffs and file_path -----------------------------------------------------------


def test_unified_diff_removing_a_skip_does_not_count_as_adding_one(ysk):
    diff = (
        "--- a/tests/test_x.py\n"
        "+++ b/tests/test_x.py\n"
        "@@ -1,3 +1,2 @@\n"
        "-@pytest.mark.skip\n"
        " def test_x():\n"
        "     assert True\n"
    )
    ysk._on_post_tool_call(
        tool_name="patch",
        args={"path": "tests/test_x.py", "patch": diff},
        result="{}",
        status="ok",
        session_id="s1",
    )
    assert [e for e in _high(ysk) if e["category"] == "test_weakened"] == []


def test_unified_diff_removing_an_assertion_is_flagged(ysk):
    diff = (
        "--- a/tests/test_x.py\n"
        "+++ b/tests/test_x.py\n"
        "@@ -1,3 +1,2 @@\n"
        " def test_x():\n"
        "-    assert payload == 2\n"
        "     return True\n"
    )
    ysk._on_post_tool_call(
        tool_name="patch",
        args={"path": "tests/test_x.py", "patch": diff},
        result="{}",
        status="ok",
        session_id="s1",
    )
    assert any(e["category"] == "test_weakened" for e in _high(ysk))


def test_patch_edit_that_uses_file_path_is_scanned(ysk):
    _patch(ysk, "tests/test_x.py", "    assert f() == 1\n", "", key="file_path")
    assert any(e["category"] == "test_weakened" for e in _high(ysk))


# --- 8c. nothing is marked reported before it is shown ----------------------------------------


def test_every_finding_reaches_the_kanban_comment(ysk, monkeypatch):
    captured = {}
    fake_db = types.ModuleType("hermes_cli.kanban_db")
    fake_db.add_comment = lambda conn, task_id, author, body: captured.update(body=body)
    fake_conn = types.ModuleType("hermes_cli.kanban_db_connect")
    fake_conn.connect_closing = lambda: contextlib.nullcontext(object())
    monkeypatch.setitem(sys.modules, "hermes_cli.kanban_db", fake_db)
    monkeypatch.setitem(sys.modules, "hermes_cli.kanban_db_connect", fake_conn)
    findings = [
        {
            "category": "destructive_cmd",
            "severity": "high",
            "claim": f"claim {i}",
            "evidence": f"evidence-{i}",
        }
        for i in range(14)
    ]
    ysk._post_kanban_comment("t_many", findings, 3)
    assert captured
    assert all(f"evidence-{i}" in captured["body"] for i in range(14))


def test_a_busy_profile_does_not_republish_a_reported_finding(ysk, monkeypatch):
    posted = []
    monkeypatch.setattr(ysk, "_post_kanban_comment", lambda t, f, r: posted.append(t))

    def complete(task):
        ysk._on_post_tool_call(
            tool_name="terminal",
            args={"command": f"rm -rf ~/repos/example-{task}"},
            result="{}",
            status="ok",
            session_id=f"s-{task}",
            task_id=task,
        )
        ysk._on_kanban_task_completed(task_id=task, summary="done", run_id=1)

    complete("t_first")
    for i in range(60):
        complete(f"t_noise{i}")
    complete("t_first")
    assert posted.count("t_first") == 1


# --- 8d. the model is a second opinion, not an authority --------------------------------------


def test_aux_finding_with_evidence_not_in_the_ledger_is_dropped(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_AUX", "1")
    _cmd(ysk, "rm -rf ~/repos/example")
    _fake_aux(
        monkeypatch,
        {
            "findings": [
                {
                    "category": "silent_decision",
                    "severity": "high",
                    "claim": "invented problem",
                    "evidence": "a line that appears nowhere in the ledger",
                }
            ],
            "cleared": [],
        },
    )
    out = ysk._on_pre_verify(session_id="s1", final_response="cleaned", changed_paths=["x"])
    assert out and "invented problem" not in out["message"]


def test_aux_finding_with_real_evidence_is_kept(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_AUX", "1")
    _cmd(ysk, "rm -rf ~/repos/example")
    evidence = _high(ysk)[0]["evidence"]
    _fake_aux(
        monkeypatch,
        {
            "findings": [
                {
                    "category": "silent_decision",
                    "severity": "high",
                    "claim": "deleted a repository without saying so",
                    "evidence": evidence,
                }
            ],
            "cleared": [],
        },
    )
    out = ysk._on_pre_verify(session_id="s1", final_response="cleaned", changed_paths=["x"])
    assert out and "deleted a repository without saying so" in out["message"]


def test_model_cannot_clear_an_unverified_claim(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_AUX", "1")
    _cmd(ysk, "rm -rf ~/repos/example")
    evidence = _high(ysk)[0]["evidence"]
    _fake_aux(
        monkeypatch,
        {
            "findings": [],
            "cleared": [
                {"category": "destructive_cmd", "evidence": evidence, "why": "intended"},
                {"category": "unverified_claim", "evidence": "0 test runs", "why": "fine"},
            ],
        },
    )
    out = ysk._on_pre_verify(
        session_id="s1", final_response="All tests pass.", changed_paths=["app.py"]
    )
    assert out and "unverified_claim" in out["message"]


# --- 8e. bounded files -----------------------------------------------------------------------


def test_checks_log_rotates_once_it_is_large(ysk, monkeypatch):
    log_dir = ysk._home() / "logs" / "ysk-watch"
    log_dir.mkdir(parents=True, exist_ok=True)
    checks = log_dir / "checks.jsonl"
    checks.write_text("x" * 200, encoding="utf-8")
    monkeypatch.setattr(ysk, "_MAX_CHECKS_BYTES", 100)
    ysk._log_check("tripwire", {"session_id": "s1"})
    assert (log_dir / "checks.jsonl.1").exists()
    assert checks.stat().st_size < 200


def test_session_ledger_file_is_trimmed_when_it_grows(ysk, monkeypatch):
    monkeypatch.setattr(ysk, "_MAX_LEDGER_BYTES", 10)
    for i in range(12):
        _cmd(ysk, f"rm -rf ~/repos/example-{i}", session="s1")
    path = ysk._home() / "logs" / "ysk-watch" / "ledger" / "s1.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines and len(lines) <= ysk._MAX_EVENTS


# --- 8f. a lease push is normal rebase workflow -----------------------------------------------


def test_force_with_lease_on_a_feature_branch_is_not_high(ysk):
    _cmd(ysk, "git push --force-with-lease origin fix/capture-integrity")
    assert [e for e in _high(ysk) if e["category"] == "destructive_cmd"] == []
    assert any(e["category"] == "destructive_cmd" for e in ysk._events("s1"))


def test_a_plain_force_push_is_still_high(ysk):
    _cmd(ysk, "git push --force origin fix/capture-integrity")
    assert any(e["category"] == "destructive_cmd" for e in _high(ysk))
