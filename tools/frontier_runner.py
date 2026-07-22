#!/usr/bin/env python3
#
# Harness-driven active recording helper for EnvGraph frontiers.

import argparse
import collections
import json
import os
import subprocess
import sys
from pathlib import Path


def read_frontiers(paths):
    for path in paths:
        with open(path, "r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                item["_source"] = str(path)
                item["_line"] = line_no
                yield item


def frontier_key(item):
    return (
        item.get("kind", ""),
        item.get("reason", item.get("source", "")),
        item.get("syscall_name", ""),
        item.get("resource_key", ""),
    )


def summarize(args):
    groups = collections.Counter()
    examples = {}
    for item in read_frontiers(args.frontiers):
        key = frontier_key(item)
        groups[key] += 1
        examples.setdefault(key, item)

    rows = []
    for key, count in groups.most_common():
        kind, reason, syscall_name, resource_key = key
        example = examples[key]
        rows.append(
            {
                "count": count,
                "kind": kind,
                "reason": reason,
                "syscall_name": syscall_name,
                "resource_key": resource_key,
                "example": {
                    "source": example.get("_source"),
                    "line": example.get("_line"),
                    "request_shape": example.get("request_shape", {}),
                    "trace_prefix": example.get("trace_prefix", {}),
                    "recent_output": example.get("recent_output", {}),
                },
            }
        )
    print(json.dumps({"frontier_group_count": len(rows), "groups": rows}, indent=2))


def stdin_bytes(spec):
    if "stdin_hex" in spec:
        return bytes.fromhex(spec["stdin_hex"])
    if "stdin_text" in spec:
        return spec["stdin_text"].encode(spec.get("stdin_encoding", "utf-8"))
    if "stdin_file" in spec:
        return Path(spec["stdin_file"]).read_bytes()
    return None


def run_manifest(args):
    with open(args.manifest, "r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    env_fuzz = manifest.get("env_fuzz", args.env_fuzz)
    default_env = os.environ.copy()
    default_env.update(manifest.get("env", {}))

    results = []
    for idx, run in enumerate(manifest.get("runs", []), 1):
        out = run["out"]
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        env = default_env.copy()
        env.update(run.get("env", {}))
        env["ENV_FUZZ"] = env_fuzz
        env["OUT"] = out
        if "driver_command" in run:
            cmd = run["driver_command"]
            if isinstance(cmd, str):
                raise ValueError(
                    "run #%d driver_command must be a JSON array" % idx
                )
        else:
            command = run["command"]
            if isinstance(command, str):
                raise ValueError("run #%d command must be a JSON array" % idx)
            env["TARGET_COMMAND_JSON"] = json.dumps(command)
            cmd = [env_fuzz, "record", "--out", out, "--"] + command
        input_data = stdin_bytes(run)
        if args.dry_run:
            result = {
                "index": idx,
                "out": out,
                "command": cmd,
                "stdin_len": 0 if input_data is None else len(input_data),
                "dry_run": True,
            }
        else:
            proc = subprocess.run(
                cmd,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
            result = {
                "index": idx,
                "out": out,
                "command": cmd,
                "stdin_len": 0 if input_data is None else len(input_data),
                "returncode": proc.returncode,
                "stdout": proc.stdout.decode("utf-8", errors="replace"),
                "stderr_tail": proc.stderr.decode(
                    "utf-8", errors="replace"
                ).splitlines()[-20:],
            }
            if proc.returncode != 0 and not args.keep_going:
                results.append(result)
                print(json.dumps({"results": results}, indent=2))
                return proc.returncode
        results.append(result)

    print(json.dumps({"results": results}, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Summarize EnvGraph frontiers and run recording manifests"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary = subparsers.add_parser("summarize", help="summarize frontier JSONL")
    summary.add_argument("frontiers", nargs="+", help="frontiers.jsonl files")
    summary.set_defaults(func=summarize)

    run = subparsers.add_parser("run-manifest", help="run recording manifest")
    run.add_argument("manifest", help="JSON recording manifest")
    run.add_argument("--env-fuzz", default="./env-fuzz", help="env-fuzz path")
    run.add_argument("--dry-run", action="store_true", help="print commands only")
    run.add_argument("--keep-going", action="store_true", help="continue after failures")
    run.set_defaults(func=run_manifest)

    args = parser.parse_args(argv)
    result = args.func(args)
    return 0 if result is None else result


if __name__ == "__main__":
    sys.exit(main())
