# EnvGraph Offline Tooling

`envgraph.py` is the M0 implementation for the Multi-Trace EnvGraph work.
It parses existing EnvFuzz `RECORD.pcap.gz` files without changing replay
behavior.

## Dump A Recording

```bash
tools/envgraph.py dump --summary --include-payload \
  --trace-id nano-ttyfile \
  out-nano-ttyfile/RECORD.pcap.gz > tmp-envgraph/nano-ttyfile.jsonl
```

The dump is JSONL and contains:

- one optional `summary` row
- `resource` rows reconstructed from EnvFuzz port/name AUX data
- `message` rows for per-resource inbound/outbound payloads

## Build A Graph

```bash
tools/envgraph.py build \
  tmp-envgraph/nano-ttyfile.jsonl \
  tmp-envgraph/nano-self.jsonl \
  tmp-envgraph/nano-input.jsonl > tmp-envgraph/nano.graph.json
```

The graph groups inbound payload candidates by:

- resource class
- canonical resource key
- payload length

By default, only groups with at least two unique payloads are kept. That keeps
the M1 runtime focused on real cross-trace diversity instead of replaying
identical system-file payloads from multiple recordings.

## M0 Evaluation Snapshot

Using the three existing nano recordings:

```text
trace_count: 3
resource_key_count: 21
candidate_group_count: 1
candidate_payload_count: 17
```

The only multi-variant group was:

```text
stdio stdio://stdin payload_len=1 variant_count=17
```

That is expected for the current nano traces: locale, gconv, terminfo, and the
seed text file are mostly identical across workloads, while the terminal input
stream contains real workload variation.

