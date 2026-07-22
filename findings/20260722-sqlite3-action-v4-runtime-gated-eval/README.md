# SQLite Runtime-Gated Action V4 Attempt

This was an aborted intermediate experiment.  The first runtime gate sampled TTY
actions with `FUZZ->id % period == 0`.  After seven period-4 seeds, results were
effectively identical to `filtered_active_graph`, which showed that the fixed id
gate was too coarse for sqlite's frontier id distribution and mostly disabled
actions.

The run was intentionally interrupted before producing a summary.  The retained
console log is `logs/sqlite3-v4-eval-console.log`.  The replacement experiment
is `findings/20260722-sqlite3-action-v5-rng-gated-eval/`, which uses runtime RNG
sampling instead.
