# EnvFuzz Campaign: nano tty/file focused run

Date: 2026-07-22

## Summary

This was a follow-up nano-focused campaign after the earlier
`nsswitch.conf`/glibc crash. The goal was to bias EnvFuzz away from glibc,
locale, terminfo, and nano syntax-definition files, leaving only the nano
editing transcript and the target text file as fuzzable inputs.

No crash, abort, or hang artifacts were produced in this focused run.

## Target

- Program: `nano`
- Version observed earlier in triage: `GNU nano, version 7.2`
- Command shape:

```bash
env TERM=xterm HOME=/home/pentester ./env-fuzz fuzz --out out-nano-ttyfile --max-time 300 --max-execs 300000
```

## Recording Scope

The recording used:

```bash
nano -I -x -0 -t nano-work/nano-self-seed.txt
```

The expect automation performed simple editing operations:

- insert a line
- search for `target`
- cut and uncut a line
- write the file
- exit nano

The campaign used `ignore.tab` rules to exclude noisy non-nano inputs:

- `/etc/nsswitch.conf`
- `/etc/locale.alias`
- `/usr/share/nano/*.nanorc`
- `/usr/lib/locale/*`
- `/usr/lib/x86_64-linux-gnu/gconv/*`
- `/usr/share/locale/*`
- `/usr/share/terminfo/*`

After those filters, EnvFuzz only generated queue mutations for:

- `stdio://stdin`
- `/home/pentester/Project/EnvFuzz/nano-work/nano-self-seed.txt`

## Result

Final artifact counts:

```text
crash: 0
abort: 0
hang:  0
queue: 924
```

No nano-owned finding was identified in this 5-minute / 300k-exec focused
campaign.

## Artifacts

- `artifacts/RECORD.pcap.gz`
- `artifacts/envfuzz-nano-ttyfile-fuzz-long.stdout`
- `artifacts/envfuzz-nano-ttyfile-fuzz-long.stderr`
- `artifacts/ignore.tab`
