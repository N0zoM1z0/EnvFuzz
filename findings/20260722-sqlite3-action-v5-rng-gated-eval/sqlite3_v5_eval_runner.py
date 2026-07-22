#!/usr/bin/env python3

import csv
import importlib.util
import json
import sys
from pathlib import Path


def load_helper(repo):
    helper = repo / "findings/20260722-sqlite3-action-v3-focused-eval/sqlite3_v3_eval_runner.py"
    spec = importlib.util.spec_from_file_location("sqlite3_v3_eval_runner", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    repo = Path.cwd().resolve()
    root = repo / "findings/20260722-sqlite3-action-v5-rng-gated-eval"
    source_root = repo / "findings/20260722-sqlite3-active-eval"
    helper = load_helper(repo)
    configs = [
        {
            "name": "tty_action_focused_p2_graph",
            "graph": root / "tmp/sqlite3-tty-action-focused-p2.graph.json",
        },
        {
            "name": "tty_action_focused_p4_graph",
            "graph": root / "tmp/sqlite3-tty-action-focused-p4.graph.json",
        },
        {
            "name": "tty_action_focused_p8_graph",
            "graph": root / "tmp/sqlite3-tty-action-focused-p8.graph.json",
        },
        {
            "name": "tty_action_focused_p16_graph",
            "graph": root / "tmp/sqlite3-tty-action-focused-p16.graph.json",
        },
    ]
    seeds = list(range(7401, 7411))

    rows = []
    for config in configs:
        for seed in seeds:
            row = helper.run_one(repo, root, source_root, config, seed)
            rows.append(row)
            print(
                "%-32s seed=%s rc=%s outs=%s/%s patches=%s graph=%s "
                "frontier=%s crashes=%s hangs=%s aborts=%s seconds=%s"
                % (
                    config["name"],
                    seed,
                    row.get("returncode"),
                    row.get("outs_seen", ""),
                    row.get("outs_total", ""),
                    row.get("patch_count"),
                    row.get("graph", 0),
                    row.get("frontier", 0),
                    row.get("crash_file_count"),
                    row.get("hang_file_count"),
                    row.get("abort_file_count"),
                    row.get("seconds"),
                ),
                flush=True,
            )

    jsonl_path = root / "sqlite3-v5-results.jsonl"
    csv_path = root / "sqlite3-v5-results.csv"
    summary_path = root / "sqlite3-v5-summary.json"
    with jsonl_path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    fields = sorted({key for row in rows for key in row})
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    summary_path.write_text(
        json.dumps(helper.summarize(rows), indent=2, sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    sys.exit(main())
