#!/usr/bin/env python3

import csv
import json
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


def frontier_lines(out_dir):
    path = out_dir / "frontiers" / "frontiers.jsonl"
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        return sum(1 for line in stream if line.strip())


def run_one(repo, root, source_root, config, seed):
    out_dir = root / "runs" / config["name"] / str(seed)
    out_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(source_root / "recordings/base-exit/RECORD.pcap.gz", out_dir / "RECORD.pcap.gz")

    cmd = [
        str(repo / "env-fuzz"),
        "fuzz",
        "--out",
        str(out_dir),
        "--max-execs",
        "10000",
        "--max-time",
        "120",
        "--seed",
        str(seed),
    ]
    if config.get("graph"):
        cmd.extend(["--graph", str(config["graph"])])

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=150,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        returncode = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", errors="replace")
        output += "\nEVAL_TIMEOUT\n"
        returncode = 124
        timed_out = True

    log_path = out_dir / "fuzz.log"
    log_path.write_text(output, encoding="utf-8")
    row = {
        "config": config["name"],
        "seed": seed,
        "returncode": returncode,
        "timed_out": timed_out,
        "seconds": round(time.time() - started, 3),
        "out_dir": str(out_dir),
        "log": str(log_path),
        "patch_count": count_files(out_dir / "queue"),
        "crash_file_count": count_files(out_dir / "crash"),
        "abort_file_count": count_files(out_dir / "abort"),
        "hang_file_count": count_files(out_dir / "hang"),
        "frontier_log_lines": frontier_lines(out_dir),
    }
    row.update(parse_status(output))
    return row


def summarize(rows):
    import collections
    import statistics

    groups = collections.defaultdict(list)
    for row in rows:
        groups[row["config"]].append(row)
    result = {}
    for config, items in sorted(groups.items()):
        entry = {"n": len(items), "returncodes": sorted({r["returncode"] for r in items})}
        for field in (
            "outs_seen",
            "patch_count",
            "crash_file_count",
            "abort_file_count",
            "hang_file_count",
            "frontier_log_lines",
            "graph",
            "frontier",
            "seconds",
        ):
            values = [r.get(field) for r in items if r.get(field) is not None]
            if values:
                entry[field] = {
                    "mean": statistics.mean(values),
                    "min": min(values),
                    "max": max(values),
                    "sum": sum(values),
                }
        result[config] = entry
    return result


def main():
    repo = Path.cwd().resolve()
    root = repo / "findings/20260722-sqlite3-action-v3-focused-eval"
    source_root = repo / "findings/20260722-sqlite3-active-eval"
    configs = [
        {"name": "nograph"},
        {
            "name": "filtered_active_graph",
            "graph": source_root / "tmp/sqlite3-filtered-active.graph.json",
        },
        {
            "name": "tty_action_focused_state_graph",
            "graph": root / "tmp/sqlite3-tty-action-focused-state.graph.json",
        },
        {
            "name": "tty_action_only_focused_state_graph",
            "graph": root / "tmp/sqlite3-tty-action-only-focused-state.graph.json",
        },
    ]
    seeds = list(range(7401, 7411))

    rows = []
    for config in configs:
        for seed in seeds:
            row = run_one(repo, root, source_root, config, seed)
            rows.append(row)
            print(
                "%-40s seed=%s rc=%s outs=%s/%s patches=%s graph=%s "
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

    jsonl_path = root / "sqlite3-v3-results.jsonl"
    csv_path = root / "sqlite3-v3-results.csv"
    summary_path = root / "sqlite3-v3-summary.json"
    with jsonl_path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    fields = sorted({key for row in rows for key in row})
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    summary_path.write_text(
        json.dumps(summarize(rows), indent=2, sort_keys=True), encoding="utf-8"
    )


if __name__ == "__main__":
    sys.exit(main())
