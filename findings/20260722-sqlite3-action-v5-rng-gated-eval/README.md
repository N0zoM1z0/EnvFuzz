# SQLite 3.53.3 RNG-Gated TTY Action Evaluation

This run evaluated runtime TTY action sampling.  The graph uses the focused
SQLite action set from v3 and varies `--tty-action-runtime-period` so new action
starts are sampled with probability `1/period`.

## Inputs

- Target: `third_party/sqlite-3.53.3-install/bin/sqlite3`
- Source recordings: `findings/20260722-sqlite3-active-eval/recordings/`
- Eval seed corpus: `recordings/base-exit/RECORD.pcap.gz`
- Seeds: `7401..7410`
- Per-run budget: `--max-execs 10000 --max-time 120`

## Graphs

All four graphs keep the same candidate content:

```text
groups=8 payloads=74 schedules=26 focused_actions=17 runtime_budget=1
```

The only variable is runtime period:

```text
tmp/sqlite3-tty-action-focused-p2.graph.json   period=2
tmp/sqlite3-tty-action-focused-p4.graph.json   period=4
tmp/sqlite3-tty-action-focused-p8.graph.json   period=8
tmp/sqlite3-tty-action-focused-p16.graph.json  period=16
```

## Baseline Context

From the same seed range in the v3 run:

```text
nograph:
  mean outs=12.7/14, mean patches=240.5, mean graph=0, mean frontier=0

filtered_active_graph:
  mean outs=11.7/14, mean patches=235.5
  mean graph=59027.2, mean frontier=9701.9

ungated focused action+payload:
  mean outs=11.7/14, mean patches=238.0
  mean graph=251756.4, mean frontier=201614.8
```

## Results

```text
tty_action_focused_p2_graph:
  mean outs=12.0/14, min/max=9..14, mean patches=233.7, mean seconds=12.6597
  mean graph=154699.1, mean frontier=105133.1

tty_action_focused_p4_graph:
  mean outs=12.2/14, min/max=10..14, mean patches=234.2, mean seconds=11.9596
  mean graph=104746.7, mean frontier=55843.4

tty_action_focused_p8_graph:
  mean outs=11.8/14, min/max=7..13, mean patches=235.6, mean seconds=12.4
  mean graph=81621.5, mean frontier=32570.6

tty_action_focused_p16_graph:
  mean outs=11.7/14, min/max=9..13, mean patches=233.6, mean seconds=12.0946
  mean graph=70121.2, mean frontier=20835.6
```

No crash, hang, or abort artifacts were produced.

## Decision

Runtime RNG sampling fixes the main cost problem: compared with the ungated
focused action graph, period 4 reduces mean graph events from `251756.4` to
`104746.7` and mean frontier events from `201614.8` to `55843.4`, while raising
mean outputs from `11.7` to `12.2`.

This is a real mechanism improvement over the previous action scheduler, but it
is not proof of superiority over sqlite's no-graph baseline.  In this workload,
the best action configuration still trails no-graph output coverage
(`12.2/14` vs `12.7/14`) and patch count (`234.2` vs `240.5`).  The next useful
SQLite step would be better action selection, not more action frequency: weight
resource-opening and schema-changing commands above plain selects, and only
inject actions after the target has reached a stable `sqlite>` prompt.
