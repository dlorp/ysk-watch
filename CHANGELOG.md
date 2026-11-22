# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.3] - 2026-11-21

### Fixed

- `cd "$HOME/..."` no longer turns into a nested path that does not exist. Only variables
  assigned in the same command were expanded, so the literal `$HOME/x` was joined onto the
  last known directory, each later `cd "$HOME/x"` nested it again, and the test-weakening scan
  reported it could not read the diff: a high `guard_degraded` hold on a clean tree. The
  directory for later commands now comes from the `cwd` Hermes reports with a `terminal`
  result (where it will run the next command); a `terminal` result without one means the
  directory did not change, and a call with a per-call `workdir` never moves it, since Hermes
  does not keep that directory for the next command. `cd -P`, `-L` and `--` take the path
  after the option ([tripwires.py](./tripwires.py), [__init__.py](./__init__.py)).

### Security

- A `cd` whose target only the shell can resolve leaves the directory unknown instead of
  guessing: an unassigned variable (including `$HOME`, which an earlier call can export, and
  whose quoting is lost after tokenizing), a command substitution, `~`, `~user` and a bare `cd`
  unless the command itself assigns HOME, `~-`, `~+`, `cd -`, and a relative `cd` from an
  unknown start. A test run after such a `cd` is not credited; the old fallback to the previous
  directory would have credited `cd "$CLONE" && pytest` to the repository the terminal left.
  Without a Hermes report, later commands resolve nothing until an absolute `cd`, and
  pre-verify holds with a `guard_degraded` finding that names the argument. That hold is added
  after the allowlist, which would otherwise be read from the repository this process sits in.
- A directory change after the leading `cd` chain (`true && cd /decoy && pytest`,
  `builtin cd`, `command cd`, `pushd`, `(cd x && pytest)`) makes the directory unknown; it was
  ignored, so the run was credited to where the terminal started. `export NAME=value` is
  followed like an assignment, so `export HOME=/x; cd "$HOME/y"` lands in `/x/y`.
- Only the `terminal` tool's report of its directory is trusted; `shell`, `bash` and
  `execute_code` results are read from the command alone.

### Changed

- `cd ~/x && pytest` in one call is no longer credited, since the shell's HOME is not visible
  here. `cd ~/x` in one call and `pytest` in the next still is: Hermes reports the directory
  between calls.
- `false && cd /tmp/clean; pytest` is credited to neither directory (it was credited to the
  start), since whether the `cd` ran depends on the command before it.

## [0.8.2] - 2026-11-20

### Security

- Staleness compares full tree ids. The name was cut to 48 bits (44 for a folded name), and
  the agent writes both the code a green run sees and the code it swaps in, so a birthday
  search for two versions with one name took 34 s in plain Python. `hash` is now the full git
  tree id, or a full SHA-256 when something is folded in; `short` is for display. A run
  recorded by an earlier version reads as stale once ([evidence.py](./evidence.py)).
- An edit behind a symlink changes the fingerprint wherever the link points. With
  `src/impl.py -> /elsewhere/impl.py`, `-> ../build/impl.py` (ignored), `-> ../.git/impl.py`,
  `-> __pycache__/impl.py` or an absolute link to prose in the tree, the target could change
  after a green run unseen. A target is skipped only when it is a file the reading hashed from
  disk; otherwise its bytes, a directory's files (links inside followed the same way, each
  target read once), `absent` for a dangling link, or the file type of a FIFO or device (never
  opened) go into the name. A link named like a cache (`.venv`, `venv`, `node_modules`) is a
  cache, as the directory would be. Walks leave out the tree itself, its git directory and the
  stat cache. Past 20,000 files and directories, 512 MiB read, or the deadline, the tree gets no
  fingerprint, never a partial one. Links inside nested repositories are followed too.
- git's output is read as bytes and decoded as the filesystem encodes paths (filesystem
  encoding, surrogateescape), not by the locale and without newline translation. Under a
  Latin-1 locale on a UTF-8 filesystem every non-ASCII path read back as a file that did not
  exist, and a name holding a carriage return (`helper\r.py`) read back as `helper\n.py`; either
  could change unseen. A name the filesystem encoding cannot decode is read as the file it
  names, and is written as `\udcXX` wherever text leaves the plugin: the ledger, the checks
  log, kanban comments, the auxiliary audit, the pre-verify message and the notice appended to
  an answer. Finding ids keep such names apart ([tripwires.py](./tripwires.py),
  [__init__.py](./__init__.py)).
- A directory that can be searched but not listed (mode `0311`) is no fingerprint. `os.walk`
  skipped it and `git ls-files --others` only warned and exited 0, while Python still imports
  a file in it by name.
- Readings cannot hold a hook past its budget or stop it with an exception. The reading at
  first sight of a repository and the check-time readings run on a bounded thread like the
  pre-run reading, link resolution has its own bound (an automount can block in the kernel),
  walks check the deadline per directory (a tree of empty directories has no file to check
  at), and any failure, including the `RecursionError` Python 3.11's `realpath` raises on a
  long symlink chain, is an unread tree. Before, that exception aborted `post_tool_call` before
  the repository was registered and left `pre_verify` failing open.

- The stop hooks (`pre_verify`, `transform_llm_output`, `post_tool_call`) share one 25 s
  budget that every git call takes its timeout from, and none starts once it is spent. The diff
  scans made several 5 s calls each on the hook thread: against a repository whose config
  blocks git, `pre_verify` took 90 s, past Hermes's 30 s abandon, which lets the answer through
  and skips the hook for the next 60 s. Check-time readings get only what is left, with no
  grace per repository.
- A prose-named symlink (`lib.md -> /elsewhere`) is followed; a prose file it points at keeps
  the prose rule. A git directory moved out of the tree and met inside a followed directory
  means no fingerprint. A link target that cannot be looked at (a locked parent) is unknown,
  not `absent`.
- A pre-run reading its owner stopped waiting for is abandoned: it finished after the owner's
  command ran, so a later test call no longer shares it.
- Finding ids and pre-run keys encode with `surrogatepass`, which takes any string.

### Changed

- Fingerprint names are full length, and a repository with a symlink that leaves the tree (an
  untracked virtualenv's `bin/python`, for one) gets a different name once.

## [0.8.1] - 2026-11-20

### Security

- Files git would quietly drop now count. The tree went through `git update-index
  --index-info`, which skips a path it refuses (`.git.`, `.git `, `git~1`, `.g\u200cit`,
  `.git :x`) with only an `Ignoring path` warning, and keeps one side of a name that is both a
  file and a directory, both with exit status 0. Code under such a directory, or a `calc.py`
  put where HEAD had a `calc.py/` of prose, could change after a green run with the
  fingerprint unchanged. The tree is now built in memory with every entry in it; a file where
  a directory is goes into the name beside the tree. Tree ids are unchanged for every
  repository without such names ([evidence.py](./evidence.py)).
- A nested repository or submodule whose config blocks git (an include of a FIFO) no longer
  holds the fingerprint past its deadline. Each of its git calls got a fixed 5 s, so four of
  them took a 2 s reading to 20 s and returned a name; the reading now stops at the deadline.
- A process that cannot start a thread hashes on the calling thread instead of failing.

### Fixed

- The fingerprint is as fast as 0.6.1's again. 0.8.0 took 3.8 s to name an unchanged
  44,000-path repository whose files were all in the stat cache, against 1.5 s before; it now
  takes 1.55 s, and a first fingerprint takes 7.3 s instead of 16 s:
  - The tree id is computed in memory, as `git write-tree` computes it, instead of by
    `update-index` and `write-tree` into a throwaway object directory, which wrote and then
    deleted one object for every new directory.
  - The symlinked-directory check looks at each directory once, not every component of every
    path.
  - Files the stat cache does not vouch for are hashed on four threads after the walk, and
    stop being claimed at the deadline. The walk checks the deadline every 256 paths and
    before each nested repository, and hashing keeps what it finished.
  - The independent git reads (HEAD's tree, the index, the HEAD index, the two untracked
    listings) run side by side.

## [0.8.0] - 2026-11-04

### Security

- The fingerprint takes nothing from the repository's index but names. It reads every path in
  HEAD, the index and the untracked listing from disk, hashes the raw bytes itself, and builds
  the tree in a throwaway index. An index rewritten to call an edited file clean, or a
  directory a submodule, no longer hides anything. Unchanged files are recognized by a stat
  cache of the watcher's own under `$HERMES_HOME/cache/ysk-watch/stat/`, keyed on size,
  mtime, ctime, inode and mode. A cache file that is not a plain, valid file is ignored
  ([evidence.py](./evidence.py)).
- No content conversion applies when hashing: eol, `ident` and `working-tree-encoding`
  attributes could make different code hash like HEAD.
- The untracked listing honours only `.gitignore` files. The global excludes file is now ignored
  too: the agent can write it. A `.gitignore` that ignores itself counts as content, unless a
  tool wrote it into a dot-directory or `build`/`dist` that holds nothing tracked or importable.
- Submodules and repositories created inside the checkout are hashed file by file and folded
  in; their own `.gitignore` and index hide nothing.
- A green run is credited with the tree read just before its command, from a new `pre_tool_call`
  hook (8 s budget, never blocks; parallel test calls share one reading). Reports the run
  writes about itself do not count as a change. A command that can write the tree or steer the
  run around its test step (redirections, scripts, `env`, substitution, `git -c`,
  `PYTHONPATH`, `-p plugin`, background jobs), or whose earlier read failed, earns no tree
  ([__init__.py](./__init__.py), [tripwires.py](./tripwires.py)).
- The committed allowlist is read through the hardened git, so `git replace` cannot swap its
  blob ([ysk_config.py](./ysk_config.py)).
- The diff scans compare against the commit the session started from, read before its first
  command, and read every changed path. A git failure, a vanished base commit or more than 400
  changed paths is a high finding, not an empty diff.
- The push guard resolves a bare push as git does: `pushRemote`, `pushDefault`, the remote's
  `push` refspecs and `mirror`, and `push.default`. It also flags `--all`, `--mirror`, `:` and
  glob refspecs, takes `--repo=`, follows `insteadOf` on a path, and treats `git -c` and
  `GIT_CONFIG_*` on the push as a forge push.
- git is run from a root-owned path when the one on `PATH` is writable by the watched user
  (the Command Line Tools binary on macOS rather than the `/usr/bin` shim).
- A code file that is a symlink to a prose file makes that file code.
- A `.pyc` outside `__pycache__` is content: Python imports it with no source beside it.
- The push guard no longer reads the value of `-o`/`--push-option`/`--receive-pack`/`--exec`
  as the remote.

### Fixed

- Every fingerprint and diff scan in `pre_verify` and the final notice shares a 20 s budget.
  Hermes abandons those hooks at 30 s and lets the answer through; a tree not read in time is
  now "evidence unavailable".
- A file missing from disk counts as deleted whatever the index marks say;
  `core.sparseCheckout` is the agent's to set and excuses nothing.
- Shell parsing: `2>&1`, `>&2` and `&>log` are redirections, not a background `&`.

### Changed

- Files checked out with converted line endings read as changed from HEAD (consistently, so
  evidence is not affected). Tree ids are otherwise identical to 0.7.0.
- A repository that relied on the global excludes file for generated files gets a different tree
  id once. Move such rules to `.gitignore`.

## [0.7.0] - 2026-11-03

### Security

- Repository config no longer steers or runs anything while the watcher reads the tree. Every
  git call carries command-line overrides (`GIT_CONFIG_COUNT`, which outranks config files) for
  `core.fsmonitor`, `core.untrackedCache`, `core.ignoreStat`, `core.checkStat`,
  `core.trustctime`, `core.fileMode`, `core.hooksPath`, `core.splitIndex` and `protocol.allow`,
  plus `GIT_NO_LAZY_FETCH`, an empty `GIT_ALLOW_PROTOCOL` (which a repository's
  `protocol.<name>.allow` cannot override) and `GIT_NO_REPLACE_OBJECTS`. An inherited `-c`
  (`GIT_CONFIG_PARAMETERS`) and pathspec switches are removed. Every configured filter driver
  is turned off, not only git-lfs, including in `write-tree`, which re-hashes racily clean
  files, and so is every config-defined hook (git 2.54+), which `core.hooksPath` does not
  reach ([evidence.py](./evidence.py)).
- Submodules are compared by commit (`--ignore-submodules=dirty`, `--submodule=short`), so git
  starts no process inside a submodule, where the submodule's own config would apply. The
  fingerprint recorded a submodule by its commit before too.
- Edits hidden behind assume-unchanged or skip-worktree marks change the fingerprint. The marks
  are cleared only in the throwaway index; the repository's own index keeps them.
- `.git/info/exclude` and a repository-level `core.excludesFile` no longer hide untracked files
  from the fingerprint. `.gitignore` files and the user's global excludes file still apply, and
  an untracked nested repository (a tool's worktree) stays out.
- The diff scans run without external diff or textconv programs, with fixed `a/`/`b/` prefixes,
  `--text`, `--no-relative` and literal pathspecs, from the top of the working tree, so diff
  config and `-diff` attributes cannot empty them ([tripwires.py](./tripwires.py)).
- The push guard checks every push URL (`remote get-url --push --all`), so a `pushurl` or
  `pushInsteadOf` cannot send a push to a forge while the fetch URL looks local.

### Fixed

- An unreadable tree is reported as "evidence unavailable" instead of passing silently. A
  repository readable at first sight but not at the claim used to be skipped, and a failed
  `git status` used to read as a clean tree. A green run whose tree could not be read is
  recorded as such ([__init__.py](./__init__.py)).
- A repository git refuses to read (unknown format version or extension) no longer falls back
  to the size-and-mtime directory fingerprint; the directory fingerprint also records ctime
  and inode.
- The fingerprint works from a working directory whose case differs from git's toplevel.
- The test-diff scan works when the terminal sits in a subdirectory: root-relative names were
  passed back as cwd-relative pathspecs.
- The tree snapshot is logged even when the tree cannot be read.

### Changed

- A repository that used `.git/info/exclude` for files in its working tree gets a different
  tree id once, and a file a test run writes that is excluded only there now makes evidence
  stale. Move such rules to `.gitignore`.

## [0.6.1] - 2026-11-03

### Fixed

- The working-tree fingerprint no longer copies file contents to disk. It staged every changed
  and untracked file with `git add -A` into a throwaway object directory under the system temp
  directory, so a repository with many uncommitted files cost its full size per fingerprint,
  and a run killed before its cleanup left that copy behind. On one host 43 such directories
  (about 2 GB each, 61 GB in total) filled the disk. Changed paths are now hashed with
  `git update-index --info-only` and the tree is written with `write-tree --missing-ok`: the
  tree id is identical to before (verified against the previous method), only the index and
  tree objects are written (264 MB to 8.6 MB on a 12,000-file working tree), and existing
  evidence stays valid ([evidence.py](./evidence.py)).
- Fingerprint temp directories left by killed runs are removed: directories with the
  fingerprint prefix untouched for an hour are swept, at most once every ten minutes per
  process, so a fingerprint running in another process is never disturbed.

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

[0.6.1]: https://github.com/dlorp/ysk-watch/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/dlorp/ysk-watch/compare/81e83ab...v0.6.0
