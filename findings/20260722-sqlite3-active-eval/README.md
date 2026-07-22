# SQLite 3.53.3 Active EnvGraph Evaluation - 2026-07-22

## Scope

This evaluation switches the real-app target from `nano` to the official
SQLite shell and measures four configurations over 10 seeds:

1. `nograph`
2. `filtered_active_graph`
3. `tty_action_only_state_graph`
4. `tty_action_state_graph`

Official latest SQLite release checked on 2026-07-22: `3.53.3`, released on
`2026-06-26`.

## Built Target

Source and install paths:

```text
third_party/sqlite-autoconf-3530300
third_party/sqlite-3.53.3-install/bin/sqlite3
```

Version:

```text
3.53.3 2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62 (64-bit)
```

Build logs:

```text
logs/sqlite-3.53.3-configure.log
logs/sqlite-3.53.3-make.log
logs/sqlite-3.53.3-install.log
```

## Active Recordings

Recording was driven through:

```text
sqlite3-active-manifest.json
sqlite3_record_driver.expect
logs/sqlite3-record-manifest.log
```

Valid recordings:

```text
recordings/base-exit/RECORD.pcap.gz
recordings/create-select/RECORD.pcap.gz
recordings/multiline-select/RECORD.pcap.gz
recordings/read-script/RECORD.pcap.gz
recordings/import-csv/RECORD.pcap.gz
recordings/reopen-db/RECORD.pcap.gz
recordings/attach-extra/RECORD.pcap.gz
```

Recorded sqlite workflows:

```text
base_exit        .databases ; .quit
create_select    CREATE TABLE ; INSERT ; SELECT
multiline_select SELECT <continuation prompt> 1+1;
read_script      .read script.sql
import_csv       .mode csv ; .import import.csv
reopen_db        .open reopen.db ; CREATE ; INSERT ; SELECT
attach_extra     ATTACH extra.db ; CREATE ; INSERT ; SELECT ; .databases
```

All seven recordings replay successfully with `./env-fuzz replay --out <dir>`.

## Runtime Note

The sqlite prompt-aware action path required a runtime rebuild after the new
sqlite prompt states were added to `env_graph.cpp`.  The rebuild log is:

```text
logs/rebuild-runtime.log
```

Without rebuilding `rr_main`, the offline graph could contain
`prompt:sqlite` / `prompt:sqlite-continuation` states but the runtime would
still classify them as generic `edit` / `unknown`, which makes the action
graph appear inert.

## Graphs

Generated graph artifacts:

```text
tmp/sqlite3-filtered-active.graph.json
tmp/sqlite3-tty-action-state.graph.json
tmp/sqlite3-tty-action-substring.graph.json
tmp/sqlite3-tty-action-only-state.graph.json
```

Key graph summaries:

| Graph | Payload groups | Payloads | Schedules | TTY actions |
| --- | ---: | ---: | ---: | ---: |
| `filtered_active_graph` | 8 | 74 | 26 | 0 |
| `tty_action_state_graph` | 8 | 74 | 26 | 61 |
| `tty_action_only_state_graph` | 7 | 12 | 26 | 61 |

The sqlite-specific TTY action graph uses:

```text
--tty-action-context-mode state
--tty-action-boundary-only
--tty-action-start-boundary-only
--no-tty-action-start-control
--no-tty-action-require-control
```

That keeps the learned actions aligned with line-oriented REPL commands rather
than control-key-driven editor traffic.

## 10-Seed Comparison

Base recording:

```text
recordings/base-exit/RECORD.pcap.gz
```

Runner and raw outputs:

```text
sqlite3_eval_runner.py
sqlite3-results.jsonl
sqlite3-results.csv
sqlite3-summary.json
logs/sqlite3-eval-console.log
```

Seeds:

```text
7301..7310
```

Summary:

| Config | Mean outs | Min..Max outs | Mean queue patches | Mean seconds | Mean graph | Mean frontier | Crash/Hang/Abort |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `nograph` | 11.5/14 | 10..13 | 237.2 | 13.27 | 0 | 0 | 0/0/0 |
| `filtered_active_graph` | 12.5/14 | 11..14 | 236.1 | 12.30 | 58,993 | 9,698 | 0/0/0 |
| `tty_action_only_state_graph` | 11.9/14 | 9..14 | 233.4 | 14.81 | 291,326 | 291,326 | 0/0/0 |
| `tty_action_state_graph` | 11.6/14 | 9..14 | 232.0 | 12.51 | 242,482 | 192,276 | 0/0/0 |

## Interpretation

### 1. The strongest stable gain is still the filtered active graph

Against the no-graph baseline:

- mean outs improved from `11.5` to `12.5`
- the best seed reached `14/14`
- runtime was slightly faster on average (`12.30s` vs `13.27s`)
- no crash, hang, or abort artifacts appeared

For this sqlite workload, the current payload-plus-schedule graph is the best
measured configuration.

### 2. Prompt-aware TTY actions now work in the runtime

After rebuilding `rr_main`, the action graphs stopped being inert:

- `tty_action_only_state_graph` drove about `291k` graph/frontier events per
  seed
- `tty_action_state_graph` drove about `242k` graph events and `192k`
  frontier events per seed

That proves the sqlite prompt/state-aware action path is live, not just an
offline artifact.

### 3. Action-only is mechanistically strong, but still too noisy

`tty_action_only_state_graph` can reach `14/14`, so the mechanism is capable
of real exploration.  But it is unstable:

- mean outs only `11.9`
- variance is high (`9..14`)
- runtime cost is the worst (`14.81s` mean)
- graph/frontier injection volume is extremely high

This is evidence that prompt-aware actions are useful, but the current action
scheduler is over-firing.

### 4. Action + payload is not yet better than filtered active

`tty_action_state_graph` is more balanced than action-only, but it still does
not beat `filtered_active_graph` on mean outs:

- `filtered_active_graph`: `12.5`
- `tty_action_state_graph`: `11.6`

So the current combined graph is active, but not yet better-targeted than the
payload/schedule-only graph.

## Findings

No true sqlite vulnerability, crash, hang, or abort finding was produced in
this run.

The useful result here is methodological:

- `filtered_active_graph` gives a real, stable advantage on sqlite over the
  no-graph baseline
- prompt-aware TTY actions are now actually exercised at runtime
- but the current action policy is too broad to translate heavy action use
  into a consistent real-app advantage

## Next Steps

The next sqlite-oriented improvements should focus on action quality, not just
action volume:

1. weight actions by success history instead of uniform random choice
2. cap action length or bias toward single-command actions before multi-command
   sequences
3. cluster prompt contexts more narrowly than just `prompt:sqlite`
4. reset or budget action usage per prompt transition rather than letting one
   broad prompt class dominate the run

Those are the changes most likely to turn the current mechanism advantage into
better real-app coverage or actual findings.
