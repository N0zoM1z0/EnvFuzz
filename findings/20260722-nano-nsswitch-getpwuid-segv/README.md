# EnvFuzz Finding: malformed nsswitch.conf triggers SIGSEGV through nano

Date: 2026-07-22

## Summary

EnvFuzz found three `hang/` patches while fuzzing `nano`. Replay triage showed
they do not reproduce as hangs. Instead, the minimized native reproducer for
`m00659` reliably crashes native `nano` with SIGSEGV when a malformed
`/etc/nsswitch.conf` is supplied in an isolated mount namespace.

The crash appears to be in glibc NSS lookup, with `nano` acting as the trigger
via `getpwuid()`.

## Environment

- OS/kernel: `Linux laptop-9d3a7045 6.6.87.2-microsoft-standard-WSL2 x86_64`
- nano: `GNU nano, version 7.2`
- glibc: `Ubuntu GLIBC 2.39-0ubuntu8.7`
- EnvFuzz output directory: `out-nano/`

## Fuzzing Commands

Initial stable recording:

```bash
expect -c '
set timeout 20
spawn env TERM=xterm ./env-fuzz record --out out-nano -- nano nano-work/envfuzz-record.txt
sleep 1
send "envfuzz nano record seed\rsecond line\r"
sleep 0.2
send "\017"
sleep 0.2
send "\r"
sleep 0.2
send "\030"
expect eof
'
```

Replay check:

```bash
script -qfec "TERM=xterm ./env-fuzz replay --out out-nano" /dev/null
```

Long fuzz run:

```bash
expect -c '
set timeout 320
spawn env TERM=xterm ./env-fuzz fuzz --out out-nano --max-time 300 --max-execs 300000
expect eof
'
```

Final EnvFuzz counts:

```text
crash=0 abort=0 hang=3 queue=2201
```

## EnvFuzz Artifacts

- `artifacts/HANG_libc.so.6+2723607_m00650.patch`
- `artifacts/HANG_libc.so.6+2723607_m00659.patch`
- `artifacts/HANG_libc.so.6+2723607_m01094.patch`
- `artifacts/nsswitch-mut-00659.conf`
- `artifacts/native-nano-mut-gdb.out`
- `artifacts/original-recording-replay.out`
- `artifacts/envfuzz-nano-fuzz-long.stdout`

## Native Reproducer

This command uses an isolated mount namespace and bind-mounts the mutated
`nsswitch.conf` over `/etc/nsswitch.conf`. It does not modify the host `/etc`.

```bash
sudo unshare -m bash -lc '
mount --make-rprivate /
mount --bind /home/pentester/Project/EnvFuzz/findings/20260722-nano-nsswitch-getpwuid-segv/artifacts/nsswitch-mut-00659.conf /etc/nsswitch.conf
timeout 10s setpriv --reuid 1000 --regid 1000 --clear-groups \
  env HOME=/home/pentester USER=pentester LOGNAME=pentester TERM=xterm \
  script -qfec "printf '\''native nano user home\\n\\017\\n\\030'\'' | nano /tmp/native-nano-mut-user-home.txt" /dev/null
'
```

Observed result:

```text
Sorry! Nano crashed!  Code: 11.  Please report a bug.
```

Repeated native runs returned `139` three times, matching SIGSEGV.

## Backtrace

The captured gdb backtrace is in `artifacts/native-nano-mut-gdb.out`.

Top frames:

```text
Program received signal SIGSEGV, Segmentation fault.
__nss_module_get_function (module=0x53c32704b7826d00, name="getpwuid_r") at ./nss/nss_module.c:328
#0  __nss_module_get_function
#1  __GI___nss_lookup_function
#2  __GI___nss_lookup
#3  __GI___nss_passwd_lookup2
#4  __getpwuid_r
#5  getpwuid
#6  nano
```

## Triage Notes

- EnvFuzz initially classified these as hangs, all at `libc.so.6+2723607`.
- Direct EnvFuzz replay of the patches produced SIGSEGV rather than timeout.
- `m00650` replay also produced many `read()` mismatch warnings, so that patch
  is noisier.
- `m00659` and `m01094` are compact mutations of `/etc/nsswitch.conf`.
- Native reproduction confirms a real SIGSEGV without EnvFuzz instrumentation.
- Root cause is likely glibc NSS handling of malformed `nsswitch.conf`; this is
  not currently a strong nano-owned bug.

## Mutated Input

The compact reproducer is `artifacts/nsswitch-mut-00659.conf`. The notable
mutation is a malformed service rule:

```text
passwd:      [  files systemd
```
