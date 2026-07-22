# SQLite 3.53.3 Focused TTY Action Evaluation

This run evaluated decoded payload filtering for sqlite TTY actions.  The graph
kept one-line REPL actions that can change or query sqlite state and removed
low-value commands such as `.quit`, `.databases`, and a bare incomplete
`SELECT`.

## Inputs

- Target: `third_party/sqlite-3.53.3-install/bin/sqlite3`
- Source recordings: `findings/20260722-sqlite3-active-eval/recordings/`
- Eval seed corpus: `recordings/base-exit/RECORD.pcap.gz`
- Seeds: `7401..7410`
- Per-run budget: `--max-execs 10000 --max-time 120`

## Graphs

```text
focused action+payload graph:
  graph: tmp/sqlite3-tty-action-focused-state.graph.json
  groups=8 payloads=74 schedules=26 actions=17

focused action-only graph:
  graph: tmp/sqlite3-tty-action-only-focused-state.graph.json
  groups=7 payloads=12 schedules=26 actions=17
```

The action filter reduced the candidate set from 27 one-command actions to 17.

## Results

```text
nograph:
  mean outs=12.7/14, min/max=9..14, mean patches=240.5, mean seconds=12.8944
  mean graph=0, mean frontier=0

filtered_active_graph:
  mean outs=11.7/14, min/max=10..13, mean patches=235.5, mean seconds=11.586
  mean graph=59027.2, mean frontier=9701.9

tty_action_focused_state_graph:
  mean outs=11.7/14, min/max=9..14, mean patches=238.0, mean seconds=12.4032
  mean graph=251756.4, mean frontier=201614.8

tty_action_only_focused_state_graph:
  mean outs=11.6/14, min/max=9..14, mean patches=232.2, mean seconds=13.7912
  mean graph=300677.5, mean frontier=300677.5
```

No crash, hang, or abort artifacts were produced.

## Decision

Payload filtering alone is not sufficient.  Removing `.quit` keeps sqlite alive
longer, but that also makes action frontiers fire more often.  The focused graph
therefore increases action/frontier volume without improving output coverage.
The next required control is runtime action sampling/budgeting.
