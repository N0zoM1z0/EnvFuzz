#!/usr/bin/env python3
#
# EnvGraph offline tooling for EnvFuzz recordings.
#
# This intentionally starts as an offline parser so graph construction can be
# validated independently of replay determinism.

import argparse
import collections
import gzip
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path


PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

ETH_P_IPV6 = 0x86DD
IPPROTO_TCP = 6

TH_FIN = 0x01
TH_SYN = 0x02
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20

SCHED_PORT = 9999

SYSCALL_SIZE = 64

AEND = 0
ANAM = 251
APTH = 252
APRT = 254
ACTX = 250

MI_____ = 0x01
M_I____ = 0x02
MR_ = 0x40
M_R = 0x80

ASTR = 5

ARG_MASKS = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20]

SYS_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    49: "bind",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    63: "uname",
    72: "fcntl",
    78: "getdents",
    79: "getcwd",
    89: "readlink",
    158: "arch_prctl",
    186: "gettid",
    202: "futex",
    217: "getdents64",
    231: "exit_group",
    257: "openat",
    262: "newfstatat",
    269: "faccessat",
    273: "set_robust_list",
    280: "utimensat",
    288: "accept4",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    302: "prlimit64",
    318: "getrandom",
    319: "memfd_create",
    332: "statx",
    334: "rseq",
    335: "rdtsc",
    336: "start",
    338: "setcontext",
    339: "signal",
    435: "clone3",
    436: "close_range",
    439: "faccessat2",
}

SCHEDULE_PATH_ARG = {
    2: 0,      # open
    4: 0,      # stat
    6: 0,      # lstat
    21: 0,     # access
    257: 1,    # openat
    262: 1,    # newfstatat
    269: 1,    # faccessat
    332: 1,    # statx
    439: 1,    # faccessat2
}


def syscall_name(no):
    return SYS_NAMES.get(no, "sys_%d" % no)


def resource_class(name):
    if not name:
        return "unknown"
    if name.startswith("stdio://"):
        return "stdio"
    if name.startswith("socket://"):
        return "socket"
    if name.startswith("pipe://"):
        return "pipe"
    if name.startswith("event://"):
        return "eventfd"
    if name.startswith("epoll://"):
        return "epoll"
    if name.startswith("memfd://"):
        return "memfd"
    if name.startswith("netlink://"):
        return "netlink"
    if name.startswith("port://"):
        return "unknown-port"
    if name.startswith("/"):
        return "file"
    return "resource"


def canonical_resource(name):
    if not name:
        return "<unknown>"
    cls = resource_class(name)
    if cls == "file":
        return os.path.normpath(name)
    return name


def payload_digest(payload):
    return hashlib.sha256(payload).hexdigest()


def open_recording(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def read_exact(stream, size, context):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("unexpected EOF while reading %s" % context)
    return data


def parse_pcap_messages(path):
    messages = []
    packets = 0
    msg_id = 0
    current = None

    with open_recording(path) as stream:
        header = read_exact(stream, 24, "pcap header")
        magic, major, minor, _r1, _r2, snaplen, linktype_word = struct.unpack(
            "<IHHIIII", header
        )
        linktype = linktype_word & 0x0FFFFFFF
        if (
            magic != PCAP_MAGIC
            or major != 2
            or minor != 4
            or snaplen != 0x7FFFFFFF
            or linktype != LINKTYPE_ETHERNET
        ):
            raise ValueError("unsupported EnvFuzz PCAP header in %s" % path)

        while True:
            packet_header = stream.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("truncated packet header in %s" % path)
            _sec, _usec, length, captured = struct.unpack("<IIII", packet_header)
            if length != captured:
                raise ValueError("truncated packet capture in %s" % path)
            packet = read_exact(stream, length, "packet")
            packets += 1
            if length < 14 + 40 + 20 + 4:
                raise ValueError("packet %d is too small in %s" % (packets, path))

            ether = packet[:14]
            ip6 = packet[14:54]
            tcp = packet[54:74]
            payload = packet[74:-4]

            proto = struct.unpack("!H", ether[12:14])[0]
            if proto != ETH_P_IPV6:
                raise ValueError("packet %d is not IPv6 in %s" % (packets, path))
            if ip6[6] != IPPROTO_TCP:
                raise ValueError("packet %d is not TCP in %s" % (packets, path))

            src = b"SSSSSSSSSSSSSSSS"
            dst = b"DDDDDDDDDDDDDDDD"
            eth_src = ether[6:12]
            eth_dst = ether[0:6]
            outbound = None
            if eth_src == src[:6] and eth_dst == dst[:6]:
                outbound = True
            elif eth_src == dst[:6] and eth_dst == src[:6]:
                outbound = False
            else:
                raise ValueError("packet %d has unknown direction in %s" % (packets, path))

            sport, dport = struct.unpack("!HH", tcp[:4])
            flags = tcp[13]
            port = dport if outbound else sport

            if not (flags & TH_URG):
                continue

            if current is None:
                msg_id += 1
                current = {
                    "id": msg_id,
                    "port": port,
                    "outbound": outbound,
                    "payload": bytearray(),
                }
            elif current["port"] != port or current["outbound"] != outbound:
                raise ValueError("packet sequence changed before PUSH in %s" % path)

            current["payload"].extend(payload)
            if flags & TH_PUSH:
                msg = dict(current)
                msg["payload"] = bytes(current["payload"])
                messages.append(msg)
                current = None

    if current is not None:
        raise ValueError("unterminated EnvFuzz message in %s" % path)
    return messages


def parse_aux(payload):
    aux = []
    offset = SYSCALL_SIZE
    while offset + 5 <= len(payload):
        word = struct.unpack_from("<I", payload, offset)[0]
        size = word & 0x00FFFFFF
        kind = (word >> 24) & 0xFF
        mask = payload[offset + 4]
        offset += 5
        if offset + size > len(payload):
            break
        data = payload[offset : offset + size]
        aux.append({"kind": kind, "mask": mask, "data": data})
        offset += size
        if kind == AEND:
            break
    return aux


def c_string(data):
    if not data:
        return ""
    end = data.find(b"\x00")
    if end < 0:
        end = len(data)
    return data[:end].decode("utf-8", errors="replace")


def aux_int(aux, mask, kind):
    for item in aux:
        if item["mask"] == mask and item["kind"] == kind and len(item["data"]) >= 4:
            return struct.unpack_from("<i", item["data"], 0)[0]
    return None


def aux_str(aux, mask, kind):
    for item in aux:
        if item["mask"] == mask and item["kind"] == kind:
            return c_string(item["data"])
    return None


def schedule_candidate_path(call):
    idx = SCHEDULE_PATH_ARG.get(call["no"])
    if idx is None:
        return None
    mask = ARG_MASKS[idx]
    path = aux_str(call["aux"], mask, APTH)
    if path:
        return os.path.normpath(path)
    path = aux_str(call["aux"], mask, ASTR)
    if path:
        return os.path.normpath(path)
    return None


def parse_syscall_message(msg):
    payload = msg["payload"]
    if len(payload) < SYSCALL_SIZE:
        return None
    no, packed_id = struct.unpack_from("<ii", payload, 0)
    args = struct.unpack_from("<qqqqqq", payload, 8)
    result = struct.unpack_from("<q", payload, 56)[0]
    thread_id = packed_id & 0x7FFFFFFF
    replay = bool(packed_id & 0x80000000)
    aux = parse_aux(payload)
    return {
        "no": no,
        "name": syscall_name(no),
        "thread_id": thread_id,
        "replay": replay,
        "args": list(args),
        "result": result,
        "aux": aux,
        "sched_hex": payload.hex(),
        "sched_len": len(payload),
    }


def build_trace(path, trace_id=None):
    recording_path = Path(path)
    trace_id = trace_id or recording_path.parent.name or recording_path.name
    messages = parse_pcap_messages(recording_path)
    port_names = {
        10000: "stdio://stdin",
        10001: "stdio://stdout",
        10002: "stdio://stderr",
    }
    calls = []
    nodes = []
    schedule_nodes = []
    resource_stats = collections.Counter()

    for msg in messages:
        if msg["port"] != SCHED_PORT:
            continue
        call = parse_syscall_message(msg)
        if call is None:
            continue
        call_index = len(calls)
        calls.append(call)

        sched_path = schedule_candidate_path(call)
        if call["result"] >= 0 and sched_path is not None:
            schedule_nodes.append(
                {
                    "type": "schedule",
                    "trace_id": trace_id,
                    "msg_id": msg["id"],
                    "call_index": call_index,
                    "thread_id": call["thread_id"],
                    "syscall_no": call["no"],
                    "syscall_name": call["name"],
                    "path": sched_path,
                    "result": call["result"],
                    "sched_len": call["sched_len"],
                    "sched_sha256": payload_digest(msg["payload"]),
                    "sched_hex": call["sched_hex"],
                }
            )

        for mask in (MR_, M_R):
            port = aux_int(call["aux"], mask, APRT)
            name = aux_str(call["aux"], mask, ANAM)
            if port is not None and name:
                port_names[port] = name

        path_name = aux_str(call["aux"], MI_____, APTH)
        if path_name:
            result = call["result"]
            if result >= 0:
                # open/openat records APTH but stores the fd->port mapping via MR_.
                port = aux_int(call["aux"], MR_, APRT)
                if port is not None:
                    port_names[port] = path_name

    message_ordinals = collections.Counter()
    for msg in messages:
        if msg["port"] == SCHED_PORT:
            continue
        name = port_names.get(msg["port"], "port://%d" % msg["port"])
        key = canonical_resource(name)
        cls = resource_class(name)
        direction = "outbound" if msg["outbound"] else "inbound"
        message_ordinals[(msg["port"], direction)] += 1
        ordinal = message_ordinals[(msg["port"], direction)]
        resource_stats[key] += 1
        nodes.append(
            {
                "type": "message",
                "trace_id": trace_id,
                "msg_id": msg["id"],
                "port": msg["port"],
                "resource_key": key,
                "resource_class": cls,
                "resource_name": name,
                "direction": direction,
                "ordinal": ordinal,
                "payload_len": len(msg["payload"]),
                "payload_sha256": payload_digest(msg["payload"]),
                "payload_hex": msg["payload"].hex(),
            }
        )

    resources = [
        {
            "resource_key": canonical_resource(name),
            "resource_class": resource_class(name),
            "resource_name": name,
            "port": port,
            "message_count": resource_stats[canonical_resource(name)],
        }
        for port, name in sorted(port_names.items())
    ]

    return {
        "type": "trace",
        "trace_id": trace_id,
        "source": str(recording_path),
        "message_count": len([m for m in messages if m["port"] != SCHED_PORT]),
        "syscall_count": len(calls),
        "resource_count": len(resources),
        "resources": resources,
        "nodes": nodes,
        "schedule_nodes": schedule_nodes,
    }


def dump_trace(args):
    trace = build_trace(args.recording, args.trace_id)
    if args.summary:
        print(
            json.dumps(
                {
                    "type": "summary",
                    "trace_id": trace["trace_id"],
                    "source": trace["source"],
                    "syscall_count": trace["syscall_count"],
                    "message_count": trace["message_count"],
                    "resource_count": trace["resource_count"],
                },
                sort_keys=True,
            )
        )
    for resource in trace["resources"]:
        print(
            json.dumps(
                {
                    "type": "resource",
                    "trace_id": trace["trace_id"],
                    **resource,
                },
                sort_keys=True,
            )
        )
    for node in trace["nodes"]:
        out = dict(node)
        if not args.include_payload:
            out.pop("payload_hex", None)
        print(json.dumps(out, sort_keys=True))
    if args.include_schedule:
        for node in trace["schedule_nodes"]:
            print(json.dumps(node, sort_keys=True))


def read_json_lines(paths):
    for path in paths:
        stream = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
        with stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def compile_resource_filters(args):
    args.include_resource_patterns = [
        re.compile(pattern) for pattern in args.include_resource_regex
    ]
    args.exclude_resource_patterns = [
        re.compile(pattern) for pattern in args.exclude_resource_regex
    ]
    args.sequence_resource_patterns = [
        re.compile(pattern) for pattern in args.sequence_resource_regex
    ]


def resource_matches(patterns, values):
    return any(pattern.search(value) for pattern in patterns for value in values)


def resource_allowed(args, *values):
    values = [str(value) for value in values if value is not None]
    if args.include_resource_patterns and not resource_matches(
        args.include_resource_patterns, values
    ):
        return False
    if args.exclude_resource_patterns and resource_matches(
        args.exclude_resource_patterns, values
    ):
        return False
    return True


def sequence_resource_allowed(args, *values):
    values = [str(value) for value in values if value is not None]
    return resource_matches(args.sequence_resource_patterns, values)


def is_tty_control(byte):
    return (byte < 32 and byte not in (9, 10, 13)) or byte == 127


def sequence_metadata(payload):
    control_count = sum(1 for byte in payload if is_tty_control(byte))
    enter_count = sum(1 for byte in payload if byte in (10, 13))
    printable_count = sum(1 for byte in payload if 32 <= byte < 127)
    return {
        "sequence_control_count": control_count,
        "sequence_enter_count": enter_count,
        "sequence_printable_count": printable_count,
        "sequence_score": control_count * 1000 + enter_count * 20 + len(payload),
    }


def build_sequence_candidates(sequence_messages, args):
    candidates = []
    seen = set()
    for (trace_id, resource_key), items in sorted(sequence_messages.items()):
        items = sorted(items, key=lambda item: item["ordinal"])
        for start in range(len(items)):
            payload = b""
            for end in range(start, len(items)):
                item = items[end]
                payload += bytes.fromhex(item["payload_hex"])
                if len(payload) > args.max_sequence_len:
                    break
                if len(payload) < args.min_sequence_len:
                    continue
                metadata = sequence_metadata(payload)
                if args.sequence_require_control and not metadata[
                    "sequence_control_count"
                ]:
                    continue
                digest = payload_digest(payload)
                key = "%s|%s" % (resource_key, digest)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "trace_id": trace_id,
                        "resource_key": resource_key,
                        "resource_class": item["resource_class"],
                        "resource_name": item["resource_name"],
                        "start_ordinal": items[start]["ordinal"],
                        "message_count": end - start + 1,
                        "sequence_len": len(payload),
                        "sequence_sha256": digest,
                        "sequence_hex": payload.hex(),
                        **metadata,
                    }
                )
    candidates.sort(
        key=lambda item: (
            item["resource_key"],
            -item["sequence_score"],
            -item["sequence_len"],
            item["trace_id"],
            item["start_ordinal"],
        )
    )
    return candidates[: args.max_sequences]


def build_graph(args):
    if args.include_sequences and args.min_sequence_len < 1:
        raise ValueError("--min-sequence-len must be >= 1")
    if args.include_sequences and args.min_sequence_len > args.max_sequence_len:
        raise ValueError("--min-sequence-len must be <= --max-sequence-len")
    if args.include_sequences and not args.sequence_resource_regex:
        args.sequence_resource_regex = ["^stdio://stdin$"]
    compile_resource_filters(args)
    traces = {}
    resources = {}
    candidates = collections.defaultdict(list)
    sequence_messages = collections.defaultdict(list)
    schedule_candidates = {}
    filtered = collections.Counter()

    for item in read_json_lines(args.dumps):
        item_type = item.get("type")
        trace_id = item.get("trace_id")
        if item_type == "summary":
            traces[trace_id] = item
            continue
        if item_type == "resource":
            if not resource_allowed(
                args, item.get("resource_key"), item.get("resource_name")
            ):
                filtered["resource"] += 1
                continue
            resources.setdefault(item["resource_key"], {}).setdefault(trace_id, item)
            continue
        if item_type == "schedule":
            if not resource_allowed(args, item.get("path")):
                filtered["schedule"] += 1
                continue
            if "sched_hex" not in item:
                raise ValueError(
                    "graph build needs schedule bytes; run dump with --include-schedule"
                )
            key = "%s|%s" % (item["syscall_name"], item["path"])
            if key not in schedule_candidates:
                schedule_candidates[key] = {
                    "key": key,
                    "trace_id": trace_id,
                    "msg_id": item["msg_id"],
                    "call_index": item["call_index"],
                    "thread_id": item["thread_id"],
                    "syscall_no": item["syscall_no"],
                    "syscall_name": item["syscall_name"],
                    "path": item["path"],
                    "result": item["result"],
                    "sched_len": item["sched_len"],
                    "sched_sha256": item["sched_sha256"],
                    "sched_hex": item["sched_hex"],
                }
            continue
        if item_type != "message" or item.get("direction") != "inbound":
            continue
        if not resource_allowed(
            args, item.get("resource_key"), item.get("resource_name")
        ):
            filtered["message"] += 1
            continue
        if item["payload_len"] == 0:
            continue
        if "payload_hex" not in item:
            raise ValueError(
                "graph build needs payloads; run dump with --include-payload"
            )
        candidate = {
            "trace_id": trace_id,
            "msg_id": item["msg_id"],
            "resource_key": item["resource_key"],
            "resource_class": item["resource_class"],
            "resource_name": item["resource_name"],
            "ordinal": item["ordinal"],
            "payload_len": item["payload_len"],
            "payload_sha256": item["payload_sha256"],
            "payload_hex": item["payload_hex"],
        }
        candidate_key = "%s|%s|%d" % (
            item["resource_class"],
            item["resource_key"],
            item["payload_len"],
        )
        candidates[candidate_key].append(candidate)
        if not args.include_sequences:
            continue
        if not sequence_resource_allowed(
            args, item.get("resource_key"), item.get("resource_name")
        ):
            filtered["sequence_message"] += 1
            continue
        sequence_messages[(trace_id, item["resource_key"])].append(candidate)

    graph_candidates = []
    for key, items in sorted(candidates.items()):
        # Keep one concrete payload for each hash per candidate class.
        seen = set()
        uniq = []
        for item in items:
            digest = item["payload_sha256"]
            if digest in seen:
                continue
            seen.add(digest)
            uniq.append(item)
        if len(uniq) < args.min_variants:
            continue
        graph_candidates.append(
            {
                "key": key,
                "resource_class": uniq[0]["resource_class"],
                "resource_key": uniq[0]["resource_key"],
                "payload_len": uniq[0]["payload_len"],
                "variant_count": len(uniq),
                "candidates": uniq[: args.max_variants],
            }
        )

    sequence_candidates = []
    if args.include_sequences:
        sequence_candidates = build_sequence_candidates(sequence_messages, args)

    graph = {
        "format": "envgraph-v0",
        "build": {
            "min_variants": args.min_variants,
            "max_variants": args.max_variants,
            "include_sequences": args.include_sequences,
            "min_sequence_len": args.min_sequence_len,
            "max_sequence_len": args.max_sequence_len,
            "max_sequences": args.max_sequences,
            "sequence_require_control": args.sequence_require_control,
            "sequence_resource_regex": args.sequence_resource_regex,
            "input_count": len(args.dumps),
            "include_resource_regex": args.include_resource_regex,
            "exclude_resource_regex": args.exclude_resource_regex,
        },
        "summary": {
            "trace_count": len(traces),
            "resource_key_count": len(resources),
            "candidate_group_count": len(graph_candidates),
            "candidate_payload_count": sum(
                len(group["candidates"]) for group in graph_candidates
            ),
            "schedule_candidate_count": len(schedule_candidates),
            "sequence_candidate_count": len(sequence_candidates),
            "filtered_resource_count": filtered["resource"],
            "filtered_message_count": filtered["message"],
            "filtered_schedule_count": filtered["schedule"],
            "filtered_sequence_message_count": filtered["sequence_message"],
        },
        "traces": traces,
        "resources": resources,
        "candidate_groups": graph_candidates,
        "sequence_candidates": sequence_candidates,
        "schedule_candidates": [
            schedule_candidates[key] for key in sorted(schedule_candidates)
        ][: args.max_schedule_candidates],
    }
    print(json.dumps(graph, indent=2, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build and inspect multi-trace EnvGraph data for EnvFuzz"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    dump = subparsers.add_parser("dump", help="dump one EnvFuzz recording as JSONL")
    dump.add_argument("recording", help="RECORD.pcap or RECORD.pcap.gz")
    dump.add_argument("--trace-id", help="stable trace identifier")
    dump.add_argument(
        "--include-payload",
        action="store_true",
        help="include payload_hex fields needed by graph build/runtime",
    )
    dump.add_argument(
        "--summary",
        action="store_true",
        help="include a summary JSONL row before resources/messages",
    )
    dump.add_argument(
        "--include-schedule",
        action="store_true",
        help="include white-listed raw syscall schedule rows for M3",
    )
    dump.set_defaults(func=dump_trace)

    build = subparsers.add_parser("build", help="merge JSONL dumps into graph JSON")
    build.add_argument("dumps", nargs="+", help="JSONL dump files or '-' for stdin")
    build.add_argument(
        "--min-variants",
        type=int,
        default=2,
        help="minimum unique payload variants per candidate group",
    )
    build.add_argument(
        "--max-variants",
        type=int,
        default=64,
        help="maximum payload variants stored per candidate group",
    )
    build.add_argument(
        "--max-schedule-candidates",
        type=int,
        default=256,
        help="maximum white-listed syscall schedule candidates stored",
    )
    build.add_argument(
        "--include-sequences",
        action="store_true",
        help="store message-aligned inbound byte sequences for queue frontiers",
    )
    build.add_argument(
        "--sequence-resource-regex",
        action="append",
        default=[],
        help=(
            "only build sequence candidates for matching resource keys or names; "
            "defaults to stdin and may be repeated"
        ),
    )
    build.add_argument(
        "--min-sequence-len",
        type=int,
        default=2,
        help="minimum byte length for sequence candidates",
    )
    build.add_argument(
        "--max-sequence-len",
        type=int,
        default=32,
        help="maximum byte length for sequence candidates",
    )
    build.add_argument(
        "--max-sequences",
        type=int,
        default=256,
        help="maximum sequence candidates stored in the graph",
    )
    build.add_argument(
        "--sequence-require-control",
        action="store_true",
        help="only store sequence candidates containing a non-newline TTY control byte",
    )
    build.add_argument(
        "--include-resource-regex",
        action="append",
        default=[],
        help=(
            "only keep resource/message/schedule candidates whose key, name, "
            "or path matches this regex; may be repeated"
        ),
    )
    build.add_argument(
        "--exclude-resource-regex",
        action="append",
        default=[],
        help=(
            "drop resource/message/schedule candidates whose key, name, or "
            "path matches this regex; may be repeated"
        ),
    )
    build.set_defaults(func=build_graph)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
