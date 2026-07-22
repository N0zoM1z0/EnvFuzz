# Nano 9.1 Prompt/State-Aware TTY Action Evaluation

Date: 2026-07-22

Objective: continue after byte-window sequence modeling and test whether
prompt/state-aware TTY actions produce a real advantage on GNU nano 9.1.

## Artifacts

- `tmp/nano91-tty-action-state.graph.json`: filtered active graph plus 14
  output-state-matched TTY action candidates.
- `nano91_tty_action_eval_runner.py`: reproducible comparison runner.
- `nano91-tty-action-results.jsonl`: per-run raw metrics.
- `nano91-tty-action-results.csv`: per-run metrics table.
- `nano91-tty-action-summary.json`: aggregate metrics.
- `logs/loader-smoke-state.log`: graph loader replay smoke.
- `logs/action-smoke-1.log`: short fuzz smoke showing action frontier use.

The graph was built from the same seven valid nano 9.1 active recordings used
for the sequence eval.

## Implementation

The runtime now keeps both the original output window used for hashing and a
separate 256-byte output tail.  Frontier logs use the tail as the preview and
include both `len` and `tail_len`.

`tools/envgraph.py build --include-tty-actions` creates
`tty_action_candidates`.  Each action candidate includes:

- `action_hex`: a stdin action starting at a non-newline control byte
- `state_key`: normalized output state such as `edit` or `prompt:search`
- `context_hex`: diagnostic normalized output context before the action
- `context_mode`: `state`, `substring`, or `both`

Runtime action scheduling is conservative:

- action frontiers are tried before generic sequences and payload frontiers
- state-mode actions require the current stdout/stderr tail to classify to the
  same `state_key`
- once an action is selected, its bytes are emitted across byte-at-a-time reads
- after the action is exhausted, the normal queue EOF behavior applies

The action graph learned 14 high-level nano actions, for example:

```text
edit           Ctrl-W "middle" Enter Ctrl-K Ctrl-U Ctrl-X
edit           Ctrl-V Enter "ACTIVE_PAGE_INSERT target" Enter Ctrl-X
edit           Ctrl-W "target" Enter " [found-by-active]" Ctrl-X
prompt:search  Ctrl-K Ctrl-U Ctrl-X
edit           Ctrl-O Enter Ctrl-X
```

Patch sampling confirmed concrete action patches.  One smoke patch contained:

```text
Ctrl-V Enter ACTIVE_PAGE_INSERT target Enter Ctrl-X
```

## Results

Each configuration ran 10 seeds, 10000 execs per seed, from the same
`base-exit` recording.

| config | mean outs | full 15/15 seeds | mean patches | graph sum | frontier sum | frontier log sum | crashes/hangs/aborts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `nograph` | 13.4/15 | 0/10 | 27.3 | 0 | 0 | 309262 | 0/0/0 |
| `filtered_active_graph` | 13.8/15 | 3/10 | 26.8 | 140485 | 90061 | 271168 | 0/0/0 |
| `tty_action_state_graph` | 13.2/15 | 2/10 | 26.6 | 1057231 | 1006891 | 302248 | 0/0/0 |
| `tty_action_budget1_graph` | 13.2/15 | 2/10 | 26.6 | 1057231 | 1006891 | 302248 | 0/0/0 |

`tty_action_budget1_graph` is identical because the existing empty-queue EOF
transition already limited each leaf to one completed action sequence.

The unresolved frontier classes remained stdin-only:

```text
nograph:
  187162 queue_empty queue_emulate_read stdio://stdin
  122100 queue_empty queue_emulate_poll stdio://stdin
filtered_active_graph:
  163212 queue_empty queue_emulate_read stdio://stdin
  107956 queue_empty queue_emulate_poll stdio://stdin
tty_action_state_graph:
  201574 queue_empty queue_emulate_poll stdio://stdin
  100674 queue_empty queue_emulate_read stdio://stdin
```

## Decision

The mechanism works: EnvFuzz can now learn high-level TTY actions from active
recordings and gate them on normalized output state.

The nano advantage is still not proven.  The state-aware action graph did not
find crashes, hangs, aborts, or better output coverage.  It was also worse than
the filtered active graph on mean output coverage.

The likely reason is state granularity.  `edit` is too broad: many different
editor situations collapse into the same state, so high-level actions are still
often valid-looking but poorly timed.  The next step should not be more input
volume.  It should be screen/prompt clustering or learned action weighting, so
actions are selected for a narrower visual/editor state rather than the coarse
`edit` bucket.
