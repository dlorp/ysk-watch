# ysk-watch

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Tests](https://github.com/dlorp/ysk-watch/actions/workflows/tests.yml/badge.svg)](https://github.com/dlorp/ysk-watch/actions/workflows/tests.yml)
[![Hermes](https://img.shields.io/badge/hermes-0.21.5%2B-informational)]()

An integrity watcher for autonomous agents. It catches the shortcuts an agent takes to make a run
look finished: assertions dropped from a test file, a skip marker slipped in, "all tests pass" with
no passing run behind it, a destructive command, a secret-bearing path read or edited.

Deterministic checks run on every tool call and cost nothing. A model is called only to confirm or
clear a high-severity hit, so the judgement that needs context stays rare and the facts that need
none are always available.

## Why

The idea comes from [`cc-plugin-you-should-know`](https://code.claude.com/docs/en/plugins/mods/overview),
the official Claude Code plugin for interactive mode. It runs an advisor side-agent over the
session and shows a note above the prompt when it finds something you may have missed. The design
is deliberately quiet: interesting is not important, so it says nothing unless something costs you
money, time, wasted work or a wrong result.

ysk-watch is our interpretation of that idea for a different job. The instinct is the same, a
watcher with a high bar that speaks only when it matters. The target is not a human reading a
prompt, it is an unattended run whose only report is the one it writes at the end. Theirs advises
the human in the loop. Ours checks the agent when the loop is unattended, where "the suite is
green" can be a claim rather than a record.

What that changes in practice:

- **Deterministic first.** Tripwires over tool calls are cheap, reproducible and never hallucinate.
  The model is a second opinion on a flagged item, not a scanner.
- **Evidence or nothing.** Every finding carries the ledger entry that produced it. A finding with
  no citation is dropped before it reaches the user.
- **Fail open.** A crashed plugin must never break the agent it watches.

Principles we adopted from that lineage:

- a high bar: report only what costs money, time, wasted work or a wrong result;
- a `silent_decision` finding for a consequential choice the agent made without saying so;
- never reproduce a secret, credential or token, even when it looks useful;
- keep the last 50 reported findings so a retried run is not commented twice.

## What it catches

Tripwires, one class per finding. `high` means the turn cannot finish cleanly until the agent
justifies or undoes it; `warn` is recorded and reported.

| Category | Severity | Fires when |
|---|---|---|
| `test_weakened` | high | assertions removed from a test file, a skip or xfail marker added, or a test file deleted |
| `test_rewritten` | warn | a test file is written whole, so prior assertions cannot be compared |
| `destructive_cmd` | high, `info` when the target is scratch | forced recursive delete, hard reset, forced clean, force push, `drop table`, disk-level formatting or raw device writes. A recursive delete whose every target is a cache, temp, build or workspace path is recorded as `info`: removing `~/.cache/pip` is housekeeping, removing a repository is not. |
| `secret_touched` | high when a secret file is edited, warn when one is referenced | `.env`, `auth.json`, `credentials.json`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `.netrc`, `.pgpass`, `secrets/` |
| `error_swallowed` | warn | `except: pass`, `|| true`, an empty `catch {}` added |
| `unverified_claim` | high | the final text says tests pass, and the ledger holds no passing test run |
| `stale_test_evidence` | high | the final text says tests pass, and a non-doc source file was edited after the newest passing run. The run exists; it no longer describes the tree. |
| `truncated_result` | info | the host cut a tool result; the saved output path is recorded so it can be read |
| `truncated_result_unremarked` | warn | the final text claims completeness while a truncated result's saved output was never read |
| `silent_failure` | warn | the command exited 0 and its output contains a traceback |
| `test_edited_by_subagent` | warn | a delegated child edited a test file (subagent history carries paths, not contents) |
| `forge_push_guard` | high | `git push` to main or master, or to a forge target that cannot be resolved to a local filesystem remote |
| `ai_attribution` | high | a commit message carries `Co-Authored-By:`, `Generated with`, `AI-generated` or a robot marker |

Every finding stores the span that matched, not the first 300 characters of the command, so a
finding can be checked against its own evidence even when the match sits late in a long command.

The push guard resolves the target where the push happens: it walks the compound command,
follows `cd`, expands `VAR=value` assignments, parses with `shlex`, ignores quoted text (an
`echo "git push origin main"` is not a push), and treats a payload handed to `bash -c` as a real
command. A repo whose remote resolves to a local filesystem path is exempt, because publishing to
a bare mirror on the LAN is not a public push.

Session patterns are counted per session and reported once when they cross a threshold:

| Pattern | Threshold | What it means |
|---|---|---|
| `approval_loop` | 3 | commands refused by approvals; stop retrying variants |
| `silent_failure` | 1 per command | exit 0 with a traceback in the output |
| `repeated_command` | 4 | the same command again and again: polling or thrash |
| `missing_path_loop` | 3 | missing script, binary or path: an invented tool |
| `help_fishing` | 3 | `--help` or `-h` repeated: tool usage being rediscovered |

## Hooks

| Hook | What it does | Cost |
|---|---|---|
| `post_tool_call` | Runs the tripwires for the call and appends findings to a bounded per-profile, per-session ledger. | Free, no model call |
| `pre_verify` | Runs when an edited turn is about to finish. Flags a "tests pass" claim with no passing run behind it, and runs **one** audit by the auxiliary model only if a high-severity tripwire fired. A confirmed finding returns `continue`, so the agent must justify or undo it. | At most 4 auxiliary calls per session |
| `kanban_task_completed` | Optional. Audits a task worker's completion summary against its ledger and posts the findings as a comment on the task, author `ysk-watch`. Quietly does nothing when the Hermes kanban store is absent. | Auxiliary call only when a high tripwire fired |
| `subagent_stop` | Runs path-level tripwires over a delegated child's tool history and folds the findings into the parent session's ledger. | Free |

The plugin never touches the conversation, so prompt caching is preserved. The audit is a separate
`call_llm(task="ysk_watch")` over the ledger.

Every check is appended to `$HERMES_HOME/logs/ysk-watch/checks.jsonl`, one JSON object per line.
That file is the whole record: it holds the finding, its evidence, and the session or task it
belongs to. Point whatever you already use for log review at it.

## Install

```bash
git clone https://github.com/dlorp/ysk-watch.git ~/.hermes/plugins/ysk-watch
hermes plugins validate ~/.hermes/plugins/ysk-watch
hermes plugins enable ysk-watch
```

Gateway-hosted sessions and cron runs load plugins at startup, so they pick it up after the next
gateway restart. CLI sessions and kanban workers pick it up immediately.

Minimal config, in the profile's `config.yaml`. Without it the plugin uses the main runtime model:

```yaml
auxiliary:
  ysk_watch:
    provider: openai
    model: gpt-4.1-mini
```

Kill switches:

```bash
YSK_WATCH_AUX=0     # keep the tripwires, skip every model call
YSK_WATCH_DISABLE=1 # disable the plugin entirely
```

## What the output looks like

Two findings, captured from a live session and with the paths sanitized.

An agent added a skip marker to a test file to get a suite green. The tripwire wrote this to
`checks.jsonl`:

```json
{"ts": 1792073422.766, "kind": "tripwire", "session_id": "local-1f2e3d4c5b6a",
 "category": "test_weakened", "severity": "high",
 "claim": "1 skip/xfail marker(s) added to a test file",
 "evidence": "/home/dev/project/tests/test_parser.py", "tool": "patch"}
```

Before the turn could finish, the agent got this back instead of stopping:

```
[ysk-watch integrity check] Before finishing, address each item below: either undo it, or state plainly in your answer why it is correct and intended. Do not hide or reword it.
- test_weakened: 1 skip/xfail marker(s) added to a test file (evidence: /home/dev/project/tests/test_parser.py)
```

A different session reported the work as verified without ever running a test. No tripwire had
fired, the claim itself was the finding:

```json
{"ts": 1792295649.91, "kind": "pre_verify_block", "session_id": "local-9a8b7c6d", "attempt": 0,
 "findings": [{"category": "unverified_claim", "severity": "high",
  "claim": "final answer claims tests pass/verified, but no test run was recorded in this session",
  "evidence": "0 test run(s) in ledger"}]}
```

Both cases end the same way: the run does not finish quietly. The agent either fixes the thing or
says out loud why it is correct.

## Tuning

Thresholds live at the top of `__init__.py` (`_REPEAT_CMD_MIN`, `_HELP_MIN`, `_BLOCKED_MIN`,
`_NOT_FOUND_MIN`, `_MAX_AUX_CALLS`, `_REPORTED_HISTORY`). They were set by mining a production
friction log rather than guessed: [paperclips](https://github.com/dlorp/paperclips) collects what
agents file about the work that went sideways, and the failure classes that recur there are the
ones worth a name here. Approval workarounds, polling, invented paths and repeated `--help` were
the patterns that showed up often enough to warrant a counter; the empty-result and truncated-read
classes were frequent enough in the same log to become tripwires. Mining the log, naming a class,
turning it into a check, and watching the new false positives is the loop. Raise the thresholds if
your work is chattier than that.

## What a finding is worth

A finding is a lead, not a verdict. The deterministic tier is precise by construction, but the
session patterns are heuristics, and a watcher that only spoke when it was certain would stay
silent through most of an unattended run. Precision is measured, not promised: per rule, count
findings, count the ones a human confirmed, and keep the ratio beside the rule. Two rules
dominated this watcher's first six days of output, both mostly on benign commands, and both were
repaired rather than defended. If your fleet's benign shapes differ, expect the same exercise on
a different pair of rules.

## Limits

- Tripwires are heuristics. The audit, or the agent's own explanation, clears benign hits.
- A whole-file write to a test file cannot be compared against the previous version, so it is a
  `warn` and not a `high`.
- Findings are kept per process and per session, bounded at 64 sessions and 300 events each. The
  ledger is also written to `$HERMES_HOME/logs/ysk-watch/ledger/` so a restart does not erase
  test evidence; it is restored only within a day of its last write.
- The claim check understands English wording for tests and a green suite. It does not read your
  language.
- A delegated child's command text never reaches the parent, so a "tests pass" claim that rests on
  a child's work is reported as a warning with that gap stated, not as a confirmed failure.
- The optional task-comment audit and the auxiliary model call use Hermes interfaces that can
  change between releases. Both are imported lazily, and the plugin fails open if they move.
- If a tripwire raises, the failure is written to `checks.jsonl` as `guard_degraded`. A quiet run
  and a blind run should not look the same.

## Development

```bash
# The plugin imports hermes_constants, so the Hermes runtime interpreter is the one that works.
~/.hermes/hermes-agent/venv/bin/python -m pytest tests
ruff check . && ruff format --check .
```

The tests are behaviour contracts: each one asserts an outcome (a finding exists, a nudge is not
repeated, a profile's ledger stays isolated), not an internal implementation detail. The push-guard
and destructive-command cases build throwaway git repos, so they need `git` on `PATH` but no
network.

## Sibling tool

[paperclips](https://github.com/dlorp/paperclips) is the two-directional friction log this
watcher's thresholds came from. ysk-watch catches the shortcut in the act; paperclips gives the
agent a place to file what it survived.

## License

MIT. See [LICENSE](LICENSE).
