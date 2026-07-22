# EnvGraph Evaluation - 2026-07-22

## Setup

Compared builds:

- Original EnvFuzz: `upstream/master` at `f354cd3`, worktree `/tmp/envfuzz-eval-worktrees/original-upstream`
- Improved EnvFuzz: `feature/multi-trace-envgraph` at `8d549fc`, worktree `/tmp/envfuzz-eval-worktrees/improved-head`

Both worktrees were built with `./build.sh`. Valid fuzz data is from `run2`;
`run1` was an initial runner-path smoke failure and is not used in the results.

Artifacts:

- Raw rows: `results.jsonl`
- CSV: `results.csv`
- Aggregates: `summary.json`
- Console log: `logs/eval-run2.console.log`
- Frontier summaries: `tmp/*frontier-summary.json`

## Benchmarks

| Benchmark | Type | Seeds | Execs/run | Compared configs |
| --- | --- | ---: | ---: | --- |
| `m2_frontier_branch` | synthetic queue frontier | 5 | 3000 | original, improved no graph, improved graph |
| `m3_open` | synthetic `openat` schedule frontier | 5 | 2500 | original, payload-only graph, full graph |
| `bc_real_cli` | real CLI app | 5 | 3000 | original, improved no graph, improved graph |
| `nano_real_ttyfile` | real app recording | 3 | 3000 | original, improved no graph, improved graph |

Success for synthetic benchmarks means a saved patch contains the required
`GO` and `OK` concrete environment data.  For real apps there is no single
semantic success token, so the useful metrics are output diversity, saved
patches, crash/hang/abort files, and frontier logs.

## Results Summary

### M2 Queue Frontier

| Config | Mean outs | Mean queue patches | Success runs | Mean graph events | Mean frontier events |
| --- | ---: | ---: | ---: | ---: | ---: |
| original | 1.0 | 0.0 | 0/5 | n/a | n/a |
| improved no graph | 1.0 | 1.0 | 0/5 | 0 | 0 |
| improved graph | 3.0 | 3.0 | 5/5 | 2449.6 | 800.0 |

EnvGraph changed reachability here.  Against the no-graph improved baseline,
output diversity went from 1 to 3 (`+200%`) and success rate went from `0/5` to
`5/5`.  A sampled patch replayed without `--graph` and reached
`FRONTIER_OK`, so M2 produces concrete replayable patches.

### M3 Open Schedule Frontier

| Config | Mean outs | Mean queue patches | Success runs | Mean graph events | Mean frontier/logged miss events |
| --- | ---: | ---: | ---: | ---: | ---: |
| original | 1.0 | 0.0 | 0/5 | n/a | n/a |
| payload-only graph | 2.0 | 2.0 | 0/5 | 1145.2 | 1145.2 logged `openat` misses |
| full graph | 2.0 | 2.0 | 5/5 | 2290.4 | 1145.2 |

Payload-only graph reaches the branch but cannot satisfy the new `openat`.
Full graph imports the schedule candidate and succeeds in every seed.  A
sampled full-graph patch replayed to `SCHED_GRAFT_OK`; the same patch without
`--graph` stopped at `OPEN_MISS`.

### bc Real CLI

| Config | Mean outs | Mean queue patches | Crashes/Hangs/Aborts | Mean graph events |
| --- | ---: | ---: | ---: | ---: |
| original | 14.8 | 0.0 | 0/0/0 | n/a |
| improved no graph | 13.8 | 13.8 | 0/0/0 | 0 |
| improved graph | 13.4 | 13.4 | 0/0/0 | 2194.0 |

`bc` is a shallow real CLI workload.  The graph is heavily used, but it did not
improve output diversity in this run.  This is a neutral result for EnvGraph:
candidate replacement works, but this target does not expose a deeper
environment frontier in the tested recording set.

### nano Real App

| Config | Mean outs | Mean queue patches | Crash/Hang/Abort files | Mean frontier log lines | Mean graph events |
| --- | ---: | ---: | ---: | ---: | ---: |
| original | 9.33 | 0.0 | 0/0/0 | 0 | n/a |
| improved no graph | 11.33 | 465.0 | 0/0/0 | 12447.0 | 0 |
| improved graph | 10.33 | 477.33 | 0/0.33/0 | 10655.67 | 27354.33 |

Two separate effects show up:

- The earlier custom `--out` queue path fix is a real practical improvement:
  the improved build saves hundreds of nano queue patches under the requested
  campaign directory, while original EnvFuzz saved none in this custom-output
  setup.
- EnvGraph itself did not improve nano output diversity in this 3-seed run.
  It reduced frontier log volume from `37341` to `31967` total lines
  (`-14.4%`) and generated many graph/frontier events, but that did not become
  a stable coverage/output win.

The graph nano run produced one hang-class file:

```text
runs/run2/nano_real_ttyfile/improved_graph/4001/hang/HANG_libc.so.6+2131894_m00126.patch
```

Replay did not hang; it aborted with:

```text
Fatal glibc error: gconv_builtin.c:69 (__gconv_get_builtin_trans): assertion failed: cnt < sizeof (map) / sizeof (map[0])
```

This is a potential finding around mutated `gconv`/locale data, but it needs
native validation before claiming a target-side bug.  It is also close to the
previous nano environment-file finding class, so it may be duplicate/noisy.

## Interpretation

What improved clearly:

1. **Deep environment reachability.**  On controlled M2/M3 frontiers, original
   and no-graph runs have `0/5` success; graph-assisted runs have `5/5`
   success.
2. **Concrete reproducibility.**  M2 success patches replay without graph; M3
   success patches replay with the full graph and fail in the expected
   `OPEN_MISS` way without it.
3. **Campaign observability.**  Frontier logs expose exactly where real apps run
   out of environment model.  For nano, the dominant misses are `stdio://stdin`
   readiness/read frontiers and locale-path `openat` misses.
4. **Artifact hygiene and persistence.**  The improved branch stores generated
   runs under `runs/` and fixes custom output queue paths, which materially
   improves real campaign usability.

What did not improve yet:

1. **Raw speed.**  Speed stayed broadly similar; this work improves reachable
   states, not exec/sec.
2. **Real-app coverage for nano.**  The current nano graph is mostly one-byte
   stdin and system locale/gconv payload diversity.  It produces many graph
   events, but the tested graph did not beat improved no-graph output diversity.
3. **Noise control.**  Real app graphs need better weighting/filtering.  System
   locale/gconv resources can dominate and lead to noisy environment-file
   mutations; target-owned files, stdin transcripts, and active-recorded
   frontier traces should get priority.

## Next Evaluation Steps

The next useful experiment is not "more random nano time" with the same graph.
It should be:

1. Use the nano frontier summaries to create active recordings for the top
   unresolved stdin/readiness states.
2. Build a nano graph from those active recordings, not only from the old three
   recordings.
3. Downweight or temporarily ignore high-volume system locale/gconv resources
   when measuring nano target behavior, then separately fuzz those resources for
   libc/environment findings.
4. Re-run nano with at least 10 seeds and compare improved no-graph vs
   improved active graph.
