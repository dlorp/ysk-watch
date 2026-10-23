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
| `stale_test_evidence` | high | the final text says tests pass, and the working tree is no longer the one the newest passing run saw (see [Evidence](#evidence)). The run exists; it no longer describes the tree. |
| `test_count_shrunk` | warn | the final text says tests pass, and the final run collected fewer tests, or skipped more, than the largest earlier run in the session: `-k`, `--deselect`, one file instead of the suite, new skips |
| `truncated_result` | info | the host cut a tool result; the saved output path is recorded so it can be read |
| `truncated_result_unremarked` | warn | the final text claims completeness while a truncated result's saved output was never read |
| `silent_failure` | warn | the command exited 0 and its output contains a traceback |
| `test_edited_by_subagent` | warn | a delegated child edited a test file (subagent history carries paths, not contents) |
| `forge_push_guard` | high | `git push` to main or master, or to a forge target that cannot be resolved to a local filesystem remote |
| `ai_attribution` | high | a commit message carries `Co-Authored-By:`, `Generated with`, `AI-generated` or a robot marker |

Checks on the lines a change adds and removes, whether the change arrived as a patch, a diff or
a shell edit seen in the working tree. Every one starts at `warn`: a rule earns a block only
after [review](#reviewing-findings) shows its precision.

| Category | Fires when |
|---|---|
| `config_edited` | test or CI configuration edited (`pytest.ini`, `conftest.py`, `jest.config.*`, `.coveragerc`, `.github/workflows/*`), `addopts` narrowed with `-x`/`--lf`/`--deselect`, or a coverage threshold lowered |
| `mocked_subject` | a test mocks out the whole module it is named after, or replaces `subject.fn` and then calls `fn` itself. Patching a dependency where the subject looks it up (`patch("parser.requests.get")`) is the normal way to isolate a unit and does not fire. |
| `suppression_added` | `# type: ignore`, `# noqa`, `eslint-disable`, `@ts-ignore`, `pylint: disable` or `# pragma: no cover` added |
| `scope_shrink` | TODO/FIXME markers added to source, or a function body replaced with `pass`/`...`/`NotImplementedError` |
| `dependency_drift` | a manifest or lockfile changed and the final text never mentions it |
| `always_equal` | an `__eq__` that always returns `True` (or `__ne__` always `False`), or an equality/assert function replaced with a lambda |
| `test_aware_code` | non-test code reads `PYTEST_CURRENT_TEST`, `sys._getframe`, `inspect.stack` or another way to notice it is under test |
| `harness_hook` | a test file or conftest adds a collection/report hook (`pytest_collection_modifyitems`, `pytest_runtest_makereport`, ...) or an early `sys.exit(0)` |

The last three are the strategies [ImpossibleBench](https://arxiv.org/abs/2510.20270) and
[METR](https://metr.org/blog/2025-06-05-recent-reward-hacking/) measured models using to pass
tests they could not honestly pass, besides editing the tests: overloading comparison, special-
casing the harness, and reaching into the grader.

One more rule is `high` from the start, because it protects the watcher itself:
`config_tampered` fires when the run edits `.ysk-watch.yaml`, writes into the watcher's log
directory, or marks its own findings with `ysk-watch review`. Editing the profile's
`config.yaml` is a `warn` under the same name.

## Evidence

"Tests pass" is checked against git, not against the tool calls the hooks happened to see:

- **Tree fingerprint.** When a test run passes, the working tree it ran on is named by its
  content: every tracked and untracked (non-ignored) file is staged into a throwaway index and
  the resulting git tree id is the name. The repository's own index and object store are only
  read. When the turn asks to finish, the tree is named again. Same name, the evidence is
  current whatever happened in between, including `git add` and `git commit`; different name,
  it is stale, even when every edit went through `sed -i`, a script, or a subagent no edit hook
  saw. Prose files (`.md`, `.rst`, `.adoc`) are left out of both.
- **Per repository.** Every repository the session works in is tracked. Each one a green run
  covered must still have the tree that run saw; each one no green run covered must still have
  the tree it had when the session first went there. Tests run in a clean clone do not cover
  edits in the real checkout. Outside git, the hook-visible edit timeline is the fallback.
- **The runner's own report.** A `--junitxml` file, a `--json-report-file`, `go test -json`
  events, jest `--json` or vitest `--reporter=json` output (or its `--outputFile`) are read
  for counts. Reports and output are things the
  watched agent can write, so they only ever make a verdict worse: a report with failures turns
  an exit code of 0 into a failed run, and nothing parsed turns an unknown outcome into a pass.
  A report file must be a regular file written after the tool call started. An exit
  status that belongs to a later command (`pytest; echo ok`) or a pass line printed after the
  runner's output was silenced (`pytest >/dev/null; echo "5 passed"`) is not a pass.
- **Counts.** Collected, passed and skipped are recorded per run. A green claim whose final run
  collected fewer tests, or skipped more, than the largest earlier run in the session is a
  finding of its own; iterating on one file mid-session is not.

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
| `pre_verify` | Runs when an edited turn is about to finish. If the check itself fails, the turn is held once with a request to say what verifies the work, and the failure is logged as `guard_degraded`. Flags a "tests pass" claim with no passing run behind it, and runs **one** audit by the auxiliary model only if a high-severity tripwire fired. A confirmed finding returns `continue`. A claim closes only when the state stops supporting it (a green run on the current tree). A factual tripwire closes when the answer cites its finding id. Any other finding closes on its id, a path from its evidence, or a specific explanation the model accepts with enough confidence. A rule name alone, or "this is intended", clears nothing. After 3 nudges a finding stops holding the turn and is recorded as `justify_unresolved`. An answer that says the work cannot be finished honestly, and does not also claim a pass, releases the turn and is recorded as `self_reported_incomplete`. In report-only mode nothing is held; what would have been held is logged as `would_block`. | At most `thresholds.max_aux_calls` (default 4) auxiliary calls per session |
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
YSK_WATCH_AUX=0          # keep the tripwires, skip every model call
YSK_WATCH_REPORT_ONLY=1  # record what would block, block nothing (overrides config)
YSK_WATCH_DISABLE=1      # disable the plugin entirely
```

To update an installed copy, pull it (or copy the new tree over it) and restart the gateway so
gateway-hosted sessions load the new code. Configuration changes need no restart: the plugin
re-reads `config.yaml` when the file changes.

## What the output looks like

Two findings, with the paths sanitized. The first is from a live session; the nudge is shown in
its current wording.

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
[ysk-watch integrity check] Before finishing, address each item: undo it, or cite its id (or the file it points at) in your answer and say why it is correct. A claim about tests clears only when the tests back it.
If the task cannot be finished without weakening a test or check, say exactly that and stop: an honest 'not done' is an acceptable outcome.
- f-3c9e1a7 test_weakened: 1 skip/xfail marker(s) added to a test file (evidence: /home/dev/project/tests/test_parser.py)
  clear it by: restore the assertion or marker, or name the test file and say why the change keeps the test honest
```

The honest exit is deliberate. ImpossibleBench found that offering one cut the rate at which a
frontier model cheated on impossible tasks from 54% to 9%: an agent with no legitimate way to stop
looks for an illegitimate one.

A different session reported the work as verified without ever running a test. No tripwire had
fired, the claim itself was the finding:

```json
{"ts": 1792295649.91, "kind": "pre_verify_block", "session_id": "local-9a8b7c6d", "attempt": 0,
 "findings": [{"category": "unverified_claim", "severity": "high",
  "claim": "final answer claims tests pass/verified, but no test run was recorded in this session",
  "evidence": "0 test run(s) in ledger"}]}
```

Both cases end the same way: the run does not finish quietly. The agent fixes the thing, says out
loud why it is correct (citing the finding), or says it could not be done honestly. A claim about
tests closes only when a passing run on the current tree backs it.

## Configuration

Everything has a default; nothing below is required. Put it in the profile's `config.yaml` under
`plugins.ysk_watch` (or a top-level `ysk_watch`), or point `YSK_WATCH_CONFIG` at a separate file.
PyYAML is used when present, otherwise the `ruamel.yaml` Hermes already ships; both in safe mode.

```yaml
plugins:
  ysk_watch:
    report_only: false          # true: record what would block, block nothing
    protected_branches: [main, master, develop]
    safe_delete:
      names: [dist-cache]       # path segments a recursive delete may remove quietly
      prefixes: [/scratch/]
    secret_patterns: ['(?:^|/)vault\.json$']   # matched against the bare path or command
    thresholds:
      repeat_command: 4
      help_fishing: 3
      approval_loop: 3
      missing_path_loop: 3
      max_aux_calls: 4
    justify:
      max_nudges: 3             # nudges before an open finding stops holding the turn
      min_confidence: 0.7       # model confidence needed to clear or raise a finding
    precision:
      min_samples: 5
      threshold: 0.5
      demote: true
    retention_days: 30          # finished-day check logs kept
```

`YSK_WATCH_REPORT_ONLY=1` overrides `report_only` for one process. The intended rollout is a
week in report-only mode, a look at `summary`, then enforcement.

**Per-repository exceptions** go in `.ysk-watch.yaml` at the repository root. Only the committed
copy (`HEAD`) is read, so an exception the watched run writes and does not commit has no effect.
A matching high finding becomes a `warn`, and a matching warning becomes `info`. Nothing is
dropped: the finding stays in the ledger and the completion comment, with the reason beside it.
A high finding is only downgraded by the allowlist that was committed when the session first
worked in the repository. An entry names one rule and optionally a path, matched as a glob or an
exact path suffix. `rule: "*"` is ignored, and claims (`unverified_claim`,
`stale_test_evidence`, `truncated_result_unremarked`) and the factual tripwires
(`forge_push_guard`, `secret_touched`, `destructive_cmd`, `ai_attribution`, `config_tampered`)
can never be allowlisted. Editing the file is itself a `config_tampered` high finding.

```yaml
allow:
  - rule: test_weakened
    path: tests/test_macos_only.py
    reason: skipped on Linux on purpose; the CI matrix runs it on macOS
```

**Logs.** `checks.jsonl` holds today. A finished day, or today's log past 2 MB, moves to
`checks-YYYY-MM-DD.jsonl` (or the next free `checks-YYYY-MM-DD.N.jsonl`), and days older than
`retention_days` are deleted. A rollover never overwrites or appends to an existing file.

### Where the thresholds came from

The session thresholds were set by mining a production friction log rather than guessed: [paperclips](https://github.com/dlorp/paperclips) collects what
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
repaired rather than defended. If your benign shapes differ, expect the same exercise on a
different pair of rules.

## Reviewing findings

Every finding carries a short id (`f-3c9e1a7`) that is the same in the log, the nudge and the
review. The plugin directory is itself the command:

```bash
python3 ~/.hermes/plugins/ysk-watch summary --since 7d        # by rule, session, repo, outcome
python3 ~/.hermes/plugins/ysk-watch review --list --rule destructive_cmd
python3 ~/.hermes/plugins/ysk-watch review --id f-3c9e1a7 --mark benign
python3 ~/.hermes/plugins/ysk-watch review                   # interactive: c / b / s / q
python3 ~/.hermes/plugins/ysk-watch rules                    # measured precision per rule
python3 ~/.hermes/plugins/ysk-watch review --export tests/fixtures/confirmed.json
python3 ~/.hermes/plugins/ysk-watch review --check tests/fixtures/confirmed.json
```

A high rule is demoted to `warn` when it has at least `min_samples` reviewed findings and the
upper end of the 95% Wilson interval on its precision is under `threshold`. Raw ratios lie at
these counts: 2 confirmed of 5 is 0.40, but anything from 0.12 to 0.77 fits it, which is not
evidence the rule is noisy; 0 of 5 (upper bound 0.43) is. A mark records the rule revision it was
made against (`ysk_config.RULE_REVISIONS`); bump a rule's revision when its logic changes and
marks about the old code stop counting.

Confirmed cases export as fixtures, and `--check` replays them through the current tripwires, so
tuning a rule cannot silently stop it catching what it caught before.

The model's verdicts and stated confidence are logged on every `aux_justify` call. Stated
confidence is known to be overconfident, so `min_confidence` is a starting point, to be refit
against reviewed outcomes once there are enough of them.

## Limits

- Tripwires are heuristics. A benign hit is cleared by the audit or by the agent's explanation,
  within the rules in [Hooks](#hooks): claims only by state, factual tripwires only by a cited id.
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
- The watcher trusts its own files: `config.yaml`, `reviews.json` and the check log under
  `$HERMES_HOME`. Writes to them through the tools it sees are `config_tampered`, but an agent
  running as the same user can reach them in ways no hook sees. Run unattended agents in a
  sandbox that cannot write `$HERMES_HOME` if that matters to you.
- A repository's baseline is its tree after the first command the session ran there. A shell
  edit made by that very first command is part of the baseline. Edit tools are not affected.
- The tracked directory follows only a leading `cd` chain (`cd repo && pytest`). After any
  other command a later `cd` may not have run, so it is not followed. A terminal whose
  directory was never set by a `cd` has no git evidence, and the edit timeline applies.
- Files ignored by `.gitignore` are not part of the fingerprint.
- JUnit XML is read only when Python's bundled expat is 2.7.2 or newer (CVE-2025-59375); on an
  older interpreter a JUnit report is ignored and the summary line or exit code is used.
- The model judge sees the agent's text between per-call random markers and is told it is data,
  but text written to persuade a monitor is a known attack on monitors. The judge can clear only
  rules the deterministic tier cannot settle, and only with stated confidence above the floor.
- The honest-exit check reads English phrasing ("could not ... without weakening the tests",
  "the task is not done"). An answer that also claims everything passes is not taking it.

## Development

```bash
# conftest.py stubs hermes_constants, so any Python 3.11+ with pytest runs the suite. The
# configuration and allowlist cases parse YAML with PyYAML and are skipped without it (the
# plugin itself falls back to ruamel.yaml; the tests do not).
python3 -m pip install pytest pyyaml ruff
python3 -m pytest tests
ruff check . && ruff format --check .
```

The tests are behaviour contracts: each one asserts an outcome (a finding exists, a nudge is not
repeated, a profile's ledger stays isolated), not an internal implementation detail. The push-guard,
destructive-command and tree-fingerprint cases build throwaway git repos, so they need `git` on
`PATH` but no network.

## Sibling tool

[paperclips](https://github.com/dlorp/paperclips) is the two-directional friction log this
watcher's thresholds came from. ysk-watch catches the shortcut in the act; paperclips gives the
agent a place to file what it survived.

## License

MIT. See [LICENSE](LICENSE).
