# Nano 9.1 Active EnvGraph Evaluation - 2026-07-22

## Scope

This run follows the previous EnvGraph evaluation with the requested changes:

1. Build and fuzz a freshly downloaded nano instead of the system nano.
2. Add an offline graph resource filter to avoid locale/gconv/system-resource
   graph pollution.
3. Record active nano workloads and compare `improved_nograph` against
   `improved_filtered_active_graph` over 10 seeds.

Official nano latest version checked on 2026-07-22: `9.1`.

## Built Nano

Source and install paths:

```text
third_party/nano-9.1
third_party/nano-9.1-install/bin/nano
```

Version:

```text
GNU nano, version 9.1
```

Build logs:

```text
logs/nano-9.1-configure.log
logs/nano-9.1-make.log
logs/nano-9.1-install.log
```

## Active Recordings

Active recording was driven through `tools/frontier_runner.py run-manifest`
using an expect driver:

```text
nano91-active-manifest.json
nano91_record_driver.expect
```

Valid recordings:

```text
recordings/base-exit/RECORD.pcap.gz
recordings/insert-save/RECORD.pcap.gz
recordings/base-variant/RECORD.pcap.gz
recordings/search-append/RECORD.pcap.gz
recordings/cut-uncut/RECORD.pcap.gz
recordings/page-insert/RECORD.pcap.gz
recordings/new-file/RECORD.pcap.gz
```

`replace-once` was excluded because its recording file was zero bytes.

The base recording replays successfully:

```text
timeout 30s ./env-fuzz replay --out findings/20260722-nano-active-eval/recordings/base-exit
status=0
EXIT 0
```

## Offline Graph Filter

New `tools/envgraph.py build` options:

```text
--include-resource-regex REGEX
--exclude-resource-regex REGEX
```

For this run the filtered active graph was built with:

```bash
tools/envgraph.py build --min-variants 1 \
  --include-resource-regex '^(stdio://stdin|/home/pentester/Project/EnvFuzz/findings/20260722-nano-active-eval/workloads/)' \
  ... > tmp/nano91-filtered-active.graph.json
```

Graph summary:

```json
{
  "candidate_group_count": 6,
  "candidate_payload_count": 49,
  "filtered_message_count": 112,
  "filtered_resource_count": 133,
  "filtered_schedule_count": 154,
  "resource_key_count": 6,
  "schedule_candidate_count": 13,
  "trace_count": 7
}
```

Resources kept in the graph:

```text
stdio://stdin
findings/20260722-nano-active-eval/workloads/base.txt
findings/20260722-nano-active-eval/workloads/cut.txt
findings/20260722-nano-active-eval/workloads/long.txt
findings/20260722-nano-active-eval/workloads/new-file.txt
findings/20260722-nano-active-eval/workloads/search.txt
```

No filtered-graph queue patch contains `/usr/lib`, `/usr/share`, `gconv`, or
`locale` resource strings.

## 10-Seed Fuzz Comparison

Base recording:

```text
recordings/base-exit/RECORD.pcap.gz
```

Run shape:

```bash
./env-fuzz fuzz --out <out> --max-execs 10000 --max-time 120 --seed <seed>
./env-fuzz fuzz --out <out> --max-execs 10000 --max-time 120 --seed <seed> \
  --graph tmp/nano91-filtered-active.graph.json
```

Seeds:

```text
5101..5110
```

Raw data:

```text
nano91-results.jsonl
nano91-results.csv
nano91-summary.json
logs/nano91-eval-console.log
```

Summary:

| Config | Runs | Mean outs | Mean queue patches | Crash/Hang/Abort | Mean seconds | Mean graph events | Mean frontier events |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `improved_nograph` | 10 | 14.0 | 26.6 | 0/0/0 | 11.62 | 0 | 0 |
| `improved_filtered_active_graph` | 10 | 13.9 | 27.5 | 0/0/0 | 10.58 | 14105.0 | 8968.6 |

Interpretation:

- The filtered active graph is being used heavily: about `14.1k` graph events
  and `9.0k` frontier events per seed.
- It did not improve output diversity in this run: `14.0` vs `13.9` mean outs.
- It slightly increased saved queue patches: `26.6` vs `27.5`.
- It did not introduce crash/hang/abort noise.
- Runtime stayed comparable; the graph run was slightly faster here, but this
  should be treated as run-to-run noise, not a claimed speed improvement.

## Frontier Findings

Filtered active graph frontier summary:

```text
queue_emulate_read  stdio://stdin  159228
queue_emulate_poll  stdio://stdin  111985
```

No-graph frontier summary:

```text
queue_emulate_read  stdio://stdin  184873
queue_emulate_poll  stdio://stdin   81062
```

After filtering, the dominant remaining unknown environment frontier is no
longer locale/gconv; it is terminal stdin/readiness state.  The active graph
fills some one-byte stdin reads, but it still lacks a model for longer
stateful terminal interaction sequences.

## Conclusion

The requested cleanup worked:

- We are fuzzing freshly built nano 9.1, not system nano.
- The graph filter prevents locale/gconv/system-resource pollution.
- Active recordings are integrated through the existing frontier runner path.
- The 10-seed comparison completed with no crash/hang/abort artifacts.

The measured improvement is narrower than hoped:

- **Positive:** graph candidates are used heavily and produce slightly more
  saved queue patches without system-resource noise.
- **Neutral:** output diversity is effectively flat.
- **Remaining gap:** nano needs a stronger stdin/TTY sequence model, not just
  more independent one-byte stdin variants.

The next code-level improvement should be a sequence-aware stdin candidate
mode, such as grouping multi-byte terminal transcripts or replaying short
active-recorded stdin subsequences when `queue_emulate_read` repeatedly asks
for one byte.
