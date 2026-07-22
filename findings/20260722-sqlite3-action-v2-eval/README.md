# SQLite 3.53.3 TTY Action V2 Evaluation

This run evaluated the prompt/state-aware TTY action graph after limiting each
learned REPL action to one submitted command with `--max-tty-action-enters 1`.

## Inputs

- Target: `third_party/sqlite-3.53.3-install/bin/sqlite3`
- Source recordings: `findings/20260722-sqlite3-active-eval/recordings/`
- Eval seed corpus: `recordings/base-exit/RECORD.pcap.gz`
- Seeds: `7401..7410`
- Per-run budget: `--max-execs 10000 --max-time 120`

## Graphs

```text
filtered_active_graph:
  graph: findings/20260722-sqlite3-active-eval/tmp/sqlite3-filtered-active.graph.json
  groups=8 payloads=74 schedules=26 actions=0

tty_action_single_state_graph:
  graph: findings/20260722-sqlite3-action-v2-eval/tmp/sqlite3-tty-action-single-state.graph.json
  groups=8 payloads=74 schedules=26 actions=27

tty_action_only_single_state_graph:
  graph: findings/20260722-sqlite3-action-v2-eval/tmp/sqlite3-tty-action-only-single-state.graph.json
  groups=7 payloads=12 schedules=26 actions=27
```

The action cap reduced the previous SQLite TTY action set from 61 candidates to
27 candidates.  The remaining actions are one-line sqlite commands such as
`.read ...`, `.import ...`, `.open ...`, `ATTACH ...`, `CREATE TABLE ...`,
`INSERT ...`, and `SELECT ...`; they also still include low-value commands such
as `.quit` and `.databases`.

## Results

```text
nograph:
  mean outs=12.7/14, min/max=9..14, mean patches=240.5, mean seconds=13.6563
  mean graph=0, mean frontier=0

filtered_active_graph:
  mean outs=11.7/14, min/max=10..13, mean patches=235.5, mean seconds=12.517
  mean graph=59027.2, mean frontier=9701.9

tty_action_single_state_graph:
  mean outs=11.9/14, min/max=8..14, mean patches=234.9, mean seconds=14.548
  mean graph=194527.9, mean frontier=144444.8

tty_action_only_single_state_graph:
  mean outs=12.2/14, min/max=9..14, mean patches=230.3, mean seconds=13.8318
  mean graph=200421.3, mean frontier=200421.3
```

No crash, hang, or abort artifacts were produced.

## Decision

The single-command cap is directionally useful: it reduces action/frontier event
volume and improves the action-only graph over the first SQLite action run
(`11.9 -> 12.2` mean outs, with lower graph/frontier volume and runtime).
However, it still does not beat the no-graph baseline on this target.  The next
step is to make the action graph more selective, starting with decoded
payload-level filtering to remove commands that terminate the REPL or only print
metadata.
