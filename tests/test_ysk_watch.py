"""Behaviour contracts for ysk-watch.

Cases come from outside this implementation: the reported failure of a subagent "loosening the
tests" to pass, unverified "tests pass" claims, destructive commands, and Hermes' own rules
(fail open, never re-nudge, isolate profiles). Each asserts an outcome, not internals.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _git_repo(path: Path, origin_url: str) -> Path:
    """A git repo whose ``origin`` is ``origin_url``. No commit is needed to read a remote."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "remote", "add", "origin", origin_url],
        check=True,
        capture_output=True,
    )
    return path


def _load():
    spec = importlib.util.spec_from_file_location(
        "ysk_watch_under_test",
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
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
    monkeypatch.setattr(mod, "_post_kanban_comment", lambda *a: None)
    return mod


def _patch(ysk, path, old, new, session="s1"):
    ysk._on_post_tool_call(
        tool_name="patch",
        args={"path": path, "old_string": old, "new_string": new},
        result="{}",
        status="ok",
        session_id=session,
    )


def _run(ysk, command, exit_code, session="s1"):
    ysk._on_post_tool_call(
        tool_name="terminal",
        args={"command": command},
        result=json.dumps({"output": "", "exit_code": exit_code}),
        status="ok" if exit_code == 0 else "error",
        session_id=session,
    )


def _high(ysk, session="s1"):
    return [e for e in ysk._events(session) if e.get("severity") == "high"]


def test_removing_assertions_from_a_test_is_flagged_high(ysk):
    _patch(
        ysk,
        "tests/test_parser.py",
        "    assert parse('a') == 1\n    assert parse('b') == 2\n",
        "    assert parse('a') == 1\n",
    )
    assert [e["category"] for e in _high(ysk)] == ["test_weakened"]


def test_adding_a_skip_marker_to_a_test_is_flagged_high(ysk):
    _patch(
        ysk,
        "src/app/__tests__/login.test.ts",
        "it('logs in', () => {",
        "it.skip('logs in', () => {",
    )
    assert any(e["category"] == "test_weakened" for e in _high(ysk))


def test_strengthening_a_test_is_not_flagged(ysk):
    _patch(
        ysk,
        "tests/test_parser.py",
        "    assert parse('a') == 1\n",
        "    assert parse('a') == 1\n    assert parse('') is None\n",
    )
    assert _high(ysk) == []


def test_skip_wording_outside_tests_is_not_flagged(ysk):
    _patch(ysk, "docs/guide.md", "Run every step.", "Use it.skip( only for flaky network tests.")
    assert _high(ysk) == []


def test_destructive_command_is_flagged_high(ysk):
    _run(ysk, "git push --force origin main", 0)
    assert any(e["category"] == "destructive_cmd" for e in _high(ysk))


def test_claim_without_any_test_run_nudges_before_finishing(ysk):
    _patch(ysk, "app.py", "x = 1", "x = 2")
    out = ysk._on_pre_verify(
        session_id="s1", final_response="Done. All tests pass.", changed_paths=["app.py"]
    )
    assert out and out["action"] == "continue" and "no test run" in out["message"]


def test_claim_after_failing_run_nudges_and_says_it_failed(ysk):
    _run(ysk, "pytest -q", 1)
    out = ysk._on_pre_verify(
        session_id="s1", final_response="Fixed; 12 passed.", changed_paths=["a.py"]
    )
    assert out and "FAILED" in out["message"]


def test_claim_backed_by_passing_run_does_not_nudge(ysk):
    _run(ysk, "scripts/run_tests.sh tests/x", 0)
    assert (
        ysk._on_pre_verify(
            session_id="s1", final_response="All tests pass.", changed_paths=["a.py"]
        )
        is None
    )


def test_general_verification_wording_is_not_a_test_claim(ysk):
    assert (
        ysk._on_pre_verify(
            session_id="s1",
            final_response="I verified the config path exists.",
            changed_paths=["a.yaml"],
        )
        is None
    )


def test_tripwire_is_kept_when_model_audit_is_off(ysk):
    _patch(ysk, "tests/test_a.py", "    assert f() == 3\n", "")
    out = ysk._on_pre_verify(
        session_id="s1", final_response="Refactored.", changed_paths=["tests/test_a.py"]
    )
    assert out and "test_weakened" in out["message"]


def test_open_finding_holds_across_attempts_until_addressed(ysk):
    """A reply alone does not clear a finding: it stays open, then stops after max_nudges.

    The earlier contract ("same finding is not nudged twice") let any reply clear a block,
    which is the loophole the audit named. The finding now survives an answer that does not
    name it, and the nudge count (3 by default) still bounds the argument.
    """
    _patch(ysk, "tests/test_a.py", "    assert f() == 3\n", "")
    first = ysk._on_pre_verify(
        session_id="s1", final_response="ok", changed_paths=["tests/test_a.py"]
    )
    second = ysk._on_pre_verify(
        session_id="s1",
        final_response="this is intended",
        changed_paths=["tests/test_a.py"],
        attempt=1,
    )
    assert first and second
    assert "test_weakened" in second["message"]
    # max_nudges is 3: the fourth attempt records the finding but stops holding the turn.
    for attempt in (2, 3):
        ysk._on_pre_verify(
            session_id="s1",
            final_response="this is intended",
            changed_paths=["tests/test_a.py"],
            attempt=attempt,
        )
    assert (
        ysk._on_pre_verify(
            session_id="s1",
            final_response="this is intended",
            changed_paths=["tests/test_a.py"],
            attempt=4,
        )
        is None
    )


def test_open_finding_is_cleared_when_the_answer_names_its_file(ysk):
    _patch(ysk, "tests/test_a.py", "    assert f() == 3\n", "")
    assert ysk._on_pre_verify(
        session_id="s1", final_response="ok", changed_paths=["tests/test_a.py"]
    )
    cleared = ysk._on_pre_verify(
        session_id="s1",
        final_response="tests/test_a.py: the assertion moved into test_b with a tighter bound.",
        changed_paths=["tests/test_a.py"],
        attempt=1,
    )
    assert cleared is None


def test_naming_the_rule_alone_does_not_clear_a_finding(ysk):
    """A reply that lists rule names addresses nothing in particular."""
    _patch(ysk, "tests/test_a.py", "    assert f() == 3\n", "")
    assert ysk._on_pre_verify(session_id="s1", final_response="ok")
    held = ysk._on_pre_verify(
        session_id="s1",
        final_response="Notes: test weakened, forge push guard, stale test evidence.",
        attempt=1,
    )
    assert held and "test_weakened" in held["message"]


def test_model_can_clear_a_benign_tripwire(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_AUX", "1")
    _patch(
        ysk,
        "tests/test_a.py",
        "def test_mac():\n",
        "@pytest.mark.skip(reason='linux only')\ndef test_mac():\n",
    )
    ev = _high(ysk)[0]["evidence"]
    reply = json.dumps(
        {
            "findings": [],
            "cleared": [{"category": "test_weakened", "evidence": ev, "why": "platform"}],
        }
    )
    fake = SimpleNamespace(
        call_llm=lambda **_: SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=reply))]
        )
    )
    monkeypatch.setitem(sys.modules, "agent.auxiliary_client", fake)
    assert (
        ysk._on_pre_verify(session_id="s1", final_response="ok", changed_paths=["tests/test_a.py"])
        is None
    )


def test_model_failure_fails_open_and_keeps_the_tripwire(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_AUX", "1")

    def boom(**_):
        raise RuntimeError("provider down")

    monkeypatch.setitem(sys.modules, "agent.auxiliary_client", SimpleNamespace(call_llm=boom))
    _run(ysk, "rm -rf ~/repos/vault", 0)
    out = ysk._on_pre_verify(session_id="s1", final_response="cleaned", changed_paths=["x"])
    assert out and "destructive_cmd" in out["message"]


def test_completion_audit_posts_a_kanban_comment(ysk, monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_abc")
    posted = []
    monkeypatch.setattr(
        ysk,
        "_post_kanban_comment",
        lambda task_id, findings, run_id: posted.append((task_id, findings)),
    )
    _patch(ysk, "tests/test_a.py", "    assert g()\n", "", session="worker-session")
    ysk._on_kanban_task_completed(task_id="t_abc", summary="Implemented; all tests pass.", run_id=7)
    assert posted and posted[0][0] == "t_abc"
    cats = {f["category"] for f in posted[0][1]}
    assert {"test_weakened", "unverified_claim"} <= cats


def test_clean_completion_posts_nothing(ysk, monkeypatch):
    posted = []
    monkeypatch.setattr(ysk, "_post_kanban_comment", lambda *a: posted.append(a))
    ysk._on_kanban_task_completed(task_id="t_clean", summary="Docs updated.", run_id=1)
    assert posted == []


def test_subagent_test_edit_is_reported_to_parent(ysk):
    history = [
        {
            "tool_name": "patch",
            "status": "ok",
            "tool_input": {"argument_keys": ["path"], "targets": {"path": "tests/test_api.py"}},
        }
    ]
    ysk._on_subagent_stop(parent_session_id="parent", child_role="coder", tool_call_history=history)
    assert any(e["category"] == "test_edited_by_subagent" for e in ysk._events("parent"))


def test_profiles_do_not_share_ledgers(ysk, monkeypatch, tmp_path):
    _patch(ysk, "tests/test_a.py", "    assert h()\n", "", session="same-id")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(other))
    assert ysk._events("same-id") == []


def test_kill_switch_disables_everything(ysk, monkeypatch):
    monkeypatch.setenv("YSK_WATCH_DISABLE", "1")
    _patch(ysk, "tests/test_a.py", "    assert h()\n", "")
    assert ysk._events("s1") == []
    assert (
        ysk._on_pre_verify(session_id="s1", final_response="All tests pass.", changed_paths=["x"])
        is None
    )


def _cmd(ysk, command, output="", exit_code=0, session="s1"):
    ysk._on_post_tool_call(
        tool_name="terminal",
        args={"command": command},
        result=json.dumps({"output": output, "exit_code": exit_code}),
        status="ok" if exit_code == 0 else "error",
        session_id=session,
    )


def _cats(ysk, session="s1"):
    return [e["category"] for e in ysk._events(session)]


def test_polling_the_same_command_is_reported_once(ysk):
    for _ in range(6):
        _cmd(ysk, "hermes kanban show t_x")
    assert _cats(ysk).count("repeated_command") == 1


def test_repeated_approval_refusals_are_reported(ysk):
    for i in range(3):
        _cmd(
            ysk,
            f"python3 -c 'print({i})'",
            output="BLOCKED: User denied this command.",
            exit_code=1,
        )
    assert "approval_loop" in _cats(ysk)


def test_help_fishing_is_reported(ysk):
    for cmd in ("vault-crawler --help", "python -m crawler -h", "crawler capture --help"):
        _cmd(ysk, cmd)
    assert "help_fishing" in _cats(ysk)


def test_push_to_main_is_a_forge_push_guard_violation(ysk):
    _cmd(ysk, "git push origin main")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_push_to_a_local_bare_mirror_is_exempt(ysk, tmp_path):
    repo = _git_repo(tmp_path / "repo", str(tmp_path / "bare.git"))
    _cmd(ysk, f"cd {repo} && git push origin main")
    assert [e for e in _high(ysk) if e["category"] == "forge_push_guard"] == []


def test_push_to_a_forge_remote_is_flagged(ysk, tmp_path):
    repo = _git_repo(tmp_path / "repo", "git@github.com:dlorp/example.git")
    _cmd(ysk, f"cd {repo} && git push origin main")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_git_dash_c_push_to_a_local_mirror_is_exempt(ysk, tmp_path):
    repo = _git_repo(tmp_path / "repo", str(tmp_path / "bare.git"))
    _cmd(ysk, f"git -C {repo} push origin master")
    assert [e for e in _high(ysk) if e["category"] == "forge_push_guard"] == []


def test_push_naming_a_forge_url_is_flagged(ysk):
    _cmd(ysk, "git push git@github.com:dlorp/example.git main")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_push_with_an_unresolvable_target_is_flagged(ysk, tmp_path):
    _cmd(ysk, f"cd {tmp_path / 'absent-repo'} && git push origin main")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_push_to_a_feature_branch_is_fine(ysk):
    _cmd(ysk, "git push -u origin fix/capture-integrity")
    assert _high(ysk) == []


def test_ai_attribution_in_commit_is_flagged(ysk):
    _cmd(ysk, 'git commit -m "fix: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>"')
    assert any(e["category"] == "ai_attribution" for e in _high(ysk))


def test_exit_zero_with_traceback_is_a_silent_failure(ysk):
    _cmd(
        ysk,
        "python3 build_index.py",
        output="Traceback (most recent call last):\n  boom",
        exit_code=0,
    )
    assert "silent_failure" in _cats(ysk)


def test_retried_task_is_not_commented_twice(ysk, monkeypatch):
    posted = []
    monkeypatch.setattr(ysk, "_post_kanban_comment", lambda t, f, r: posted.append(f))
    for run in (1, 2):
        ysk._on_post_tool_call(
            tool_name="terminal",
            args={"command": "git reset --hard HEAD~3"},
            result="{}",
            status="ok",
            session_id=f"run{run}",
            task_id="t_retry",
        )
        ysk._on_kanban_task_completed(task_id="t_retry", summary="done", run_id=run)
    assert len(posted) == 1


# --- precision: the push guard resolves the target at the push -------------------------------


def test_push_text_inside_a_quoted_string_is_not_a_push(ysk):
    _cmd(ysk, 'echo "git push origin main"')
    assert _high(ysk) == []


def test_shell_c_payload_is_still_a_push(ysk):
    _cmd(ysk, 'bash -c "git push origin main"')
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


def test_variable_indirected_git_dash_c_to_a_local_mirror_is_exempt(ysk, tmp_path):
    repo = _git_repo(tmp_path / "repo", str(tmp_path / "bare.git"))
    _cmd(ysk, f"REPO={repo}; git -C $REPO push origin main")
    assert [e for e in _high(ysk) if e["category"] == "forge_push_guard"] == []


def test_compound_command_resolves_the_directory_at_the_push(ysk, tmp_path):
    bare = _git_repo(tmp_path / "mirror", str(tmp_path / "bare.git"))
    forge = _git_repo(tmp_path / "public", "git@github.com:dlorp/example.git")
    _cmd(ysk, f"cd {forge} && cd {bare} && git push origin main")
    assert [e for e in _high(ysk) if e["category"] == "forge_push_guard"] == []
    _cmd(ysk, f"cd {bare} && cd {forge} && git push origin main")
    assert any(e["category"] == "forge_push_guard" for e in _high(ysk))


# --- precision: destructive severity follows the target --------------------------------------


def test_recursive_delete_of_a_cache_path_is_info(ysk):
    _cmd(ysk, "rm -rf ~/.cache/pip")
    assert [e for e in _high(ysk) if e["category"] == "destructive_cmd"] == []
    assert "destructive_cmd" in _cats(ysk)


def test_recursive_delete_of_a_repository_is_high(ysk):
    _cmd(ysk, "rm -rf ~/repos/example-project")
    assert any(e["category"] == "destructive_cmd" for e in _high(ysk))


def test_recursive_delete_of_an_unexpanded_variable_is_high(ysk):
    _cmd(ysk, "rm -rf $TARGET")
    assert any(e["category"] == "destructive_cmd" for e in _high(ysk))


# --- evidence quality: the matched span, not the first 300 characters ------------------------


def test_evidence_windows_around_a_match_past_the_prefix(ysk):
    padding = "echo " + "x" * 400 + " && "
    _cmd(ysk, padding + "rm -rf ~/repos/vault")
    finding = next(e for e in _high(ysk) if e["category"] == "destructive_cmd")
    assert "rm -rf" in finding["evidence"]
    assert finding["evidence"].startswith("[")


# --- evidence-aware claims -------------------------------------------------------------------


def test_execute_code_payload_counts_as_test_evidence(ysk):
    ysk._on_post_tool_call(
        tool_name="execute_code",
        args={"code": "import subprocess\nsubprocess.run(['pytest', '-q'], check=True)"},
        result=json.dumps({"output": "31 passed", "exit_code": 0}),
        status="ok",
        session_id="s1",
    )
    assert (
        ysk._on_pre_verify(
            session_id="s1", final_response="All tests pass.", changed_paths=["a.py"]
        )
        is None
    )


def test_ledger_survives_a_process_restart(ysk):
    _run(ysk, "pytest -q", 0)
    ysk._ledgers.clear()
    restored = [e for e in ysk._events("s1") if e.get("category") == "test_run"]
    assert restored and restored[-1]["passed"] is True


def test_delegated_work_downgrades_an_unverified_claim(ysk):
    ysk._on_subagent_stop(
        parent_session_id="s1",
        child_role="coder",
        tool_call_history=[{"tool_name": "terminal", "status": "ok", "tool_input": {}}],
    )
    claim = ysk._unverified_claim("All tests pass.", ysk._events("s1"))
    assert claim and claim["severity"] == "warn"


# --- D2: a truncated result cannot support a completeness claim ------------------------------


def test_truncated_result_is_recorded_with_its_saved_path(ysk):
    saved = "/tmp/out.log"
    _cmd(
        ysk,
        "cat big.log",
        output=f"line\nOUTPUT TRUNCATED\nfull output (9000 chars) saved to {saved}",
    )
    events = [e for e in ysk._events("s1") if e["category"] == "truncated_result"]
    assert events and events[0]["saved_path"] == saved


def test_completeness_claim_after_an_unread_truncation_is_flagged(ysk):
    _cmd(ysk, "cat big.log", output="OUTPUT TRUNCATED\nfull output (900) saved to /tmp/x.log")
    claim = ysk._truncated_claim("Reviewed all 400 entries.", ysk._events("s1"))
    assert claim and claim["category"] == "truncated_result_unremarked"


def test_completeness_claim_is_fine_when_the_saved_output_was_read(ysk):
    path = "/tmp/x.log"
    _cmd(ysk, "cat big.log", output=f"OUTPUT TRUNCATED\nfull output (900) saved to {path}")
    _cmd(ysk, f"tail -n 400 {path}")
    assert ysk._truncated_claim("Reviewed all 400 entries.", ysk._events("s1")) is None


def test_a_partial_disclosure_is_not_a_completeness_claim(ysk):
    _cmd(ysk, "cat big.log", output="OUTPUT TRUNCATED\nfull output (900) saved to /tmp/x.log")
    assert ysk._truncated_claim("Reviewed a sample of the entries.", ysk._events("s1")) is None


# --- D3: a passing run that predates the newest edit is stale evidence -----------------------


def test_editing_source_after_a_passing_run_is_stale_evidence(ysk):
    _run(ysk, "pytest -q", 0)
    _patch(ysk, "app.py", "x = 1", "x = 2")
    claim = ysk._stale_test_evidence("All tests pass.", ysk._events("s1"))
    assert claim and claim["severity"] == "high"


def test_doc_only_edit_after_a_passing_run_is_not_stale(ysk):
    _run(ysk, "pytest -q", 0)
    _patch(ysk, "README.md", "old", "new")
    assert ysk._stale_test_evidence("All tests pass.", ysk._events("s1")) is None


# --- a blind hook must not look like a clean run ---------------------------------------------


def test_a_tripwire_crash_is_recorded_as_guard_degraded(ysk, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("tripwire exploded")

    monkeypatch.setattr(ysk.tripwires, "scan_tool_call", boom)
    _run(ysk, "ls", 0)
    log = (ysk._home() / "logs" / "ysk-watch" / "checks.jsonl").read_text(encoding="utf-8")
    assert "guard_degraded" in log
