# Nano 9.1 Sequence-Aware EnvGraph Evaluation

Date: 2026-07-22

Objective: test whether sequence-aware stdin/TTY frontier modeling turns the
EnvGraph mechanism into a measurable advantage on a real interactive app
(GNU nano 9.1).

## Artifacts

- `tmp/nano91-sequence-active.graph.json`: generic stdin sequence graph,
  max sequence length 32, 256 sequence candidates.
- `tmp/nano91-tty-control-sequence.graph.json`: control-key focused stdin
  sequence graph, max sequence length 12, 120 sequence candidates.
- `nano91_sequence_eval_runner.py`: reproducible comparison runner.
- `nano91-sequence-results.jsonl`: per-run raw metrics.
- `nano91-sequence-results.csv`: per-run metrics table.
- `nano91-sequence-summary.json`: aggregate metrics.
- `logs/loader-smoke-2.log`: graph loader replay smoke.
- `logs/sequence-smoke-1.log`: short fuzz smoke proving repeated sequence
  frontier injection.

The graphs were built from the seven valid nano active recordings under
`findings/20260722-nano-active-eval/tmp/`.

## Implementation Notes

`tools/envgraph.py build --include-sequences` now creates a separate
`sequence_candidates` graph section.  Sequence payloads use `sequence_hex`, not
`payload_hex`, so the legacy single-payload loader does not misparse them.

The runtime loads sequence candidates and prefers them for empty-queue
frontiers.  For byte-at-a-time TTY reads, it keeps the queue open until the
chosen sequence is exhausted; each emitted byte/chunk is still saved as a
normal concrete patch entry.

An important bug was fixed during this work: the old frontier path incremented
`E->eof` after one graph frontier, which prevented multi-read sequences from
being emitted.  Sequence frontiers now suppress that EOF transition until the
active sequence is fully consumed.

## Verification

Build and syntax checks passed:

```text
python3 -m py_compile tools/envgraph.py
python3 -m py_compile findings/20260722-nano-sequence-eval/nano91_sequence_eval_runner.py
./build.sh
```

Replay loader smoke passed:

```text
ENVGRAPH .../nano91-sequence-active.graph.json candidates=49 sequences=256 schedules=9
EXIT 0
```

Patch sampling confirmed concrete repeated stdin frontier entries.  One saved
sequence patch contains 33 messages, including 32 consecutive stdin bytes:

```text
stdin preview: "_ active nano file\rwith several "
```

## Results

Each configuration ran 10 seeds, 10000 execs per seed, from the same
`base-exit` recording.

| config | mean outs | full 15/15 seeds | mean patches | graph sum | frontier sum | frontier log sum | crashes/hangs/aborts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `nograph` | 14.1/15 | 4/10 | 27.9 | 0 | 0 | 292079 | 0/0/0 |
| `filtered_active_graph` | 14.3/15 | 4/10 | 28.7 | 133179 | 89583 | 269781 | 0/0/0 |
| `sequence_active_graph` | 13.1/15 | 1/10 | 27.2 | 2800175 | 2754490 | 271639 | 0/0/0 |
| `tty_control_sequence_graph` | 13.3/15 | 4/10 | 27.0 | 644408 | 599321 | 272536 | 0/0/0 |

Aggregated unresolved frontier classes stayed the same in all configurations:

```text
nograph:
  207059 queue_empty queue_emulate_read stdio://stdin
   85020 queue_empty queue_emulate_poll stdio://stdin
filtered_active_graph:
  162522 queue_empty queue_emulate_read stdio://stdin
  107259 queue_empty queue_emulate_poll stdio://stdin
sequence_active_graph:
  160958 queue_empty queue_emulate_read stdio://stdin
  110681 queue_empty queue_emulate_poll stdio://stdin
tty_control_sequence_graph:
  159510 queue_empty queue_emulate_read stdio://stdin
  113026 queue_empty queue_emulate_poll stdio://stdin
```

## Decision

The mechanism is proven: EnvFuzz can now build, load, emit, and save
sequence-aware stdin frontiers.  It also fixes the one-frontier-per-resource
limit that made true sequences impossible before.

The real nano advantage is not proven.  On this corpus, sequence graphs greatly
increase graph/frontier activity, but they do not produce crashes, hangs,
aborts, or better output coverage.  The best output-coverage result remains
the previous filtered active graph without sequence frontiers.

The likely reason is that byte-window sequences are still not semantic TTY
actions.  They feed more valid-looking bytes, but they do not know whether nano
is at a search prompt, save prompt, edit buffer, or exit confirmation.  The next
step should be prompt/state-aware TTY action scheduling and resource weighting,
not simply longer or more numerous stdin sequences.
