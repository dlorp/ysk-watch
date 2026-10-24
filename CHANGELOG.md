# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-10-22

### Added

- Evidence from git instead of tool calls: a passing test run records a fingerprint of the
  working tree it ran on, and a "tests pass" claim is stale when the tree has changed since,
  including edits made through the shell, scripts or subagents
  ([evidence.py](./evidence.py)).
- Structured test results read from JUnit XML, pytest `--json-report`, `go test -json`, jest
  `--json` and vitest `--reporter=json` (stdout or `--outputFile`); a report with failures
  overrides an exit code of 0. Reports never turn an unknown outcome into a pass.
- `test_count_shrunk`: a run that collected fewer tests or skipped more than the previous one.
- Findings stay open until they are addressed. Claims close only when the ledger and the tree
  stop supporting them. Factual tripwires close when the answer cites their id. Other findings
  close on their id, a path from their evidence, or a specific explanation the model accepts.
  A rule name alone clears nothing. After `justify.max_nudges` (default 3) a finding stops
  holding the turn and is recorded as `justify_unresolved`.
- An explicit honest exit in the nudge: an answer that says the work cannot be finished without
  weakening a check, and does not also claim a pass, releases the turn and is recorded as
  `self_reported_incomplete`.
- Stable short finding ids (`f-xxxxxxx`) shared by the log, the nudge and the review, plus a
  one-line "clear it by" hint per category.
- `ysk-watch review`, `summary` and `rules` commands ([cli.py](./cli.py)): mark findings
  confirmed or benign, see per-rule precision with a 95% Wilson interval, export confirmed cases
  as fixtures and replay them with `--check`.
- Precision-based demotion: a high rule with at least `min_samples` reviews whose Wilson upper
  bound is under `threshold` is demoted to `warn`. Review marks carry the rule revision and stop
  counting once that rule's entry in `RULE_REVISIONS` is bumped.
- Configuration from the profile's `config.yaml` or `YSK_WATCH_CONFIG`: thresholds, protected
  branches, safe-delete paths, extra secret patterns, justify and precision settings, log
  retention, and `completion_comment` (`all`, the default; `high`, which leaves warnings in the
  log; or `off`) ([ysk_config.py](./ysk_config.py)).
- Outside a git repository, or without git installed, a green run records a fingerprint of the
  directory's source-like files (size and modification time), so a shell edit after it is still
  stale evidence. Directories too large to walk within a second fall back to the edit timeline.
- Per-repository allowlist in the committed `.ysk-watch.yaml`. Matching findings are downgraded
  one level and logged as `allowlisted`, never dropped. Claims and factual tripwires cannot be
  allowlisted.
- `config_tampered` (high): the run disabled ysk-watch (`hermes plugins disable`,
  `hermes config set|unset` on its settings or the enabled-plugins list, a persisted
  `YSK_WATCH_*` switch), wrote the plugin's code, logs or review marks, edited the allowlist,
  or edited a profile `config.yaml`/`.env` in a way that touches the watcher.
- `monitoring_weakened`: alert recipients emptied, suppression flags set, monitoring switches
  turned off, or tests rewritten to assert monitoring is absent (high), and monitoring code
  removed (warn). Checked on edits and on the working tree at finish, and added to the audit
  prompt together with denial of such a change. It covers the failure in OpenAI's October 2026
  report on agents suppressing and disabling misalignment monitoring.
- Report-only mode (`report_only: true` or `YSK_WATCH_REPORT_ONLY=1`): records `would_block`
  instead of holding the turn.
- Daily check-log files (`checks-YYYY-MM-DD.jsonl`) with retention; size rollovers take the next
  free numbered name instead of overwriting a backup.
- If `pre_verify` itself fails, the turn is held once with a request to state what verifies
  the work, and the failure is logged as `guard_degraded`.
- `transform_llm_output` hook: findings still unresolved when an answer is delivered are
  appended to it (`final_notice`, on by default; off in report-only mode). This covers turns
  Hermes does not run `pre_verify` for (no file-tool edits, such as an orchestrator that only
  delegated, or shell-only work), and turns whose host-side nudge budget ran out.
- `subagent_unresolved`: a delegated child's unresolved high findings are handed to the parent
  on `subagent_stop`, where they hold the parent's turn or reach its answer.
- Warn-level tripwires: `config_edited`, `mocked_subject`, `suppression_added`, `scope_shrink`,
  `dependency_drift`, and, from the cheat strategies measured by ImpossibleBench and METR,
  `always_equal`, `test_aware_code` and `harness_hook`.
- The auxiliary model returns a confidence per finding; findings under `min_confidence` are not
  acted on, and every justify verdict is logged for later calibration.

### Changed

- LICENSE names dlorp as the copyright holder; the file had been copied from another project
  with that project's holder.
- Agent text sent to the auxiliary model is wrapped in per-call random markers, and both system
  prompts treat everything inside them as untrusted data. The model can no longer clear claims
  or factual tripwires (`forge_push_guard`, `secret_touched`, `destructive_cmd`,
  `ai_attribution`, `config_tampered`).
- An answer naming a rule no longer clears a finding of that rule.
- Configuration values are type-checked per key; an invalid value falls back to its default
  instead of raising inside a hook. Extra secret patterns are compiled one by one; an empty,
  over-long, invalid or match-everything pattern is ignored.
- Prose files are recognised by extension only (`.md`, `.rst`, `.adoc`); `.txt` files and
  `docs/` directories are code as far as staleness is concerned.
- The tracked directory follows only a leading `cd` chain.
- Session thresholds and the per-session model-call cap are read from configuration; the
  constants in `__init__.py` are gone.
- `checks.jsonl` records the repository a finding belongs to, only when it is known.

### Fixed

- A relative `cd` in a command is resolved against the terminal's known directory.
- The working-tree fingerprint and test-report paths use the directory the command `cd`s into,
  not the one the terminal was in before it.
- Fingerprints are taken from the repository root, so the same tree has the same name from any
  subdirectory, and edits inside new untracked directories change it.
- Deselected tests are no longer counted in a run's total, so `-k` narrowing is visible.
- Malformed YAML in a config or allowlist file no longer raises inside a hook.
- A malformed runner report no longer aborts the other tripwires for the same command.
- Test-report files must be regular files no older than the previous tool call; `/dev/zero`
  or a FIFO named as a report is not read.
- Command samples are redacted before they are truncated, and credentials in URLs,
  `curl -u` and `mysql -p` are redacted.
- Writing the check log never raises out of a hook.
- The copied index keeps the real index's mtime, so git's racy-clean check still rehashes a
  same-size edit made in the same second as the last index write.
- Every git call runs with `GIT_OPTIONAL_LOCKS=0`, so a watcher read never refreshes the real
  index or holds `index.lock` while the agent commits. Fingerprinting skips git-lfs clean
  filters, which would otherwise write into `.git/lfs`.
- Report freshness is bounded by the tool call's own `duration_ms` from Hermes, falling back to
  the end of the previous call.
- JUnit XML is not parsed on interpreters whose expat is older than 2.7.2 (CVE-2025-59375), and
  is capped at 1 MiB.
- pytest summary lines with colour codes, `xfailed` and `xpassed` are read.
- Configured secret patterns are matched against the bare path or command, so `^` and `$`
  anchors work as written.
- CI actions moved to checkout v7.0.1 and setup-python v7.1.0, pinned by commit SHA, with a
  read-only `contents` permission. The suite runs on Ubuntu (Python 3.11-3.14) and macOS (3.11,
  3.14), again with only `ruamel.yaml` installed, with pinned dev requirements, superseded runs
  cancelled, and Dependabot for actions and dev requirements. A manifest test checks hooks,
  version and license against the code, CHANGELOG and LICENSE.
- The git fingerprint ignores untracked caches (`__pycache__`, `.pyc`, tool caches,
  virtualenvs, `node_modules`), so a Python run after a green run does not make it stale in a
  repository that does not ignore them.

[0.6.0]: https://github.com/dlorp/ysk-watch/compare/81e83ab...v0.6.0
