#!/usr/bin/env python3

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def clean(text):
    return ANSI_RE.sub("", text)


def parse_status(text):
    result = {}
    for line in clean(text).splitlines():
        if "EXIT" not in line:
            continue
        for key, pattern in (
            ("outs", r"outs=(\d+)/(\d+)"),
            ("path", r"path=([0-9a-fA-F]+)"),
            ("crash", r"crash=(\d+)"),
            ("abort", r"abort=(\d+)"),
            ("hang", r"hang=(\d+)"),
            ("graph", r"graph=(\d+)"),
            ("frontier", r"frontier=(\d+)"),
        ):
            match = re.search(pattern, line)
            if not match:
                continue
            if key == "outs":
                result["outs_seen"] = int(match.group(1))
                result["outs_total"] = int(match.group(2))
            elif key == "path":
                result[key] = match.group(1)
            else:
                result[key] = int(match.group(1))
        match = re.search(r"#(\d+):", line)
        if match:
            result["last_msg_id"] = int(match.group(1))
    return result


def count_files(path):
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file())


def patch_stats(out_dir, tokens):
    patch_files = list(out_dir.rglob("*.patch"))
    if not tokens:
        return len(patch_files), 0
    success = 0
    for patch in patch_files:
        data = patch.read_bytes()
        if all(token in data for token in tokens):
            success += 1
    return len(patch_files), success


def frontier_lines(out_dir):
    path = out_dir / "frontiers" / "frontiers.jsonl"
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        return sum(1 for line in stream if line.strip())


def run_one(root, run_id, bench, config, seed):
    out_dir = root / "runs" / run_id / bench["name"] / config["name"] / str(seed)
    out_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(bench["recording"], out_dir / "RECORD.pcap.gz")

    cmd = [
        str(Path(config["worktree"]) / "env-fuzz"),
        "fuzz",
        "--out",
        str(out_dir),
        "--max-execs",
        str(bench["max_execs"]),
        "--max-time",
        str(bench["max_time"]),
        "--seed",
        str(seed),
    ]
    if config.get("graph"):
        cmd.extend(["--graph", str(config["graph"])])

    log_path = out_dir / "fuzz.log"
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=config["worktree"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=bench["timeout"],
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        timed_out = False
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", errors="replace")
        output += "\nEVAL_TIMEOUT\n"
        timed_out = True
        returncode = 124
    log_path.write_text(output, encoding="utf-8")

    row = {
        "benchmark": bench["name"],
        "config": config["name"],
        "seed": seed,
        "returncode": returncode,
        "timed_out": timed_out,
        "seconds": round(time.time() - started, 3),
        "out_dir": str(out_dir),
        "log": str(log_path),
    }
    row.update(parse_status(output))
    patch_count, success_count = patch_stats(out_dir, bench.get("success_tokens", []))
    row.update(
        {
            "patch_count": patch_count,
            "success_patch_count": success_count,
            "queue_patch_count": count_files(out_dir / "queue"),
            "crash_file_count": count_files(out_dir / "crash"),
            "abort_file_count": count_files(out_dir / "abort"),
            "hang_file_count": count_files(out_dir / "hang"),
            "frontier_log_lines": frontier_lines(out_dir),
        }
    )
    return row


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--original", required=True)
    parser.add_argument("--improved", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)

    repo = Path.cwd().resolve()
    root = Path(args.root).resolve()
    original = Path(args.original).resolve()
    improved = Path(args.improved).resolve()

    benchmarks = [
        {
            "name": "m2_frontier_branch",
            "recording": repo / "runs/frontier-branch-base/RECORD.pcap.gz",
            "max_execs": 3000,
            "max_time": 60,
            "timeout": 90,
            "success_tokens": [b"GO", b"OK"],
            "seeds": [1001, 1002, 1003, 1004, 1005],
            "configs": [
                {"name": "original", "worktree": original},
                {"name": "improved_nograph", "worktree": improved},
                {
                    "name": "improved_graph",
                    "worktree": improved,
                    "graph": repo / "runs/tmp/frontier-branch.graph.json",
                },
            ],
        },
        {
            "name": "m3_open",
            "recording": repo / "runs/m3-open-base/RECORD.pcap.gz",
            "max_execs": 2500,
            "max_time": 60,
            "timeout": 90,
            "success_tokens": [b"GO", b"OK"],
            "seeds": [2001, 2002, 2003, 2004, 2005],
            "configs": [
                {"name": "original", "worktree": original},
                {
                    "name": "improved_payload_only",
                    "worktree": improved,
                    "graph": repo / "runs/tmp/m3-open.payload-only.graph.json",
                },
                {
                    "name": "improved_fullgraph",
                    "worktree": improved,
                    "graph": repo / "runs/tmp/m4-open-active.graph.json",
                },
            ],
        },
        {
            "name": "bc_real_cli",
            "recording": repo / "runs/bc-base/RECORD.pcap.gz",
            "max_execs": 3000,
            "max_time": 60,
            "timeout": 90,
            "success_tokens": [],
            "seeds": [3001, 3002, 3003, 3004, 3005],
            "configs": [
                {"name": "original", "worktree": original},
                {"name": "improved_nograph", "worktree": improved},
                {
                    "name": "improved_graph",
                    "worktree": improved,
                    "graph": repo / "runs/tmp/bc.graph.json",
                },
            ],
        },
        {
            "name": "nano_real_ttyfile",
            "recording": repo / "runs/legacy/out-nano-ttyfile/RECORD.pcap.gz",
            "max_execs": 3000,
            "max_time": 120,
            "timeout": 150,
            "success_tokens": [],
            "seeds": [4001, 4002, 4003],
            "configs": [
                {"name": "original", "worktree": original},
                {"name": "improved_nograph", "worktree": improved},
                {
                    "name": "improved_graph",
                    "worktree": improved,
                    "graph": repo / "runs/legacy/tmp-envgraph-m0/nano.graph.json",
                },
            ],
        },
    ]

    rows = []
    jsonl_path = root / "results.jsonl"
    csv_path = root / "results.csv"
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as jsonl:
        for bench in benchmarks:
            for config in bench["configs"]:
                for seed in bench["seeds"]:
                    row = run_one(root, args.run_id, bench, config, seed)
                    rows.append(row)
                    jsonl.write(json.dumps(row, sort_keys=True) + "\n")
                    jsonl.flush()
                    print(
                        "%s %-22s seed=%s rc=%s patches=%s success=%s "
                        "outs=%s/%s graph=%s frontier=%s seconds=%s"
                        % (
                            bench["name"],
                            config["name"],
                            seed,
                            row.get("returncode"),
                            row.get("patch_count"),
                            row.get("success_patch_count"),
                            row.get("outs_seen", ""),
                            row.get("outs_total", ""),
                            row.get("graph", 0),
                            row.get("frontier", 0),
                            row.get("seconds"),
                        ),
                        flush=True,
                    )

    fields = sorted({key for row in rows for key in row})
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
