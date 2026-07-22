# WSL GUI Calculator Manual Recording

This is a manual active recording of `/usr/bin/gnome-calculator` launched from
WSL with WSLg display variables available.

## Recording

```bash
./env-fuzz record --out findings/20260723-wsl-gui-calc-record/manual-click-001 -- /usr/bin/gnome-calculator
```

Result:

```text
record exit: 0
recording: manual-click-001/RECORD.pcap.gz
size: 4768859 bytes
```

The run emitted WSL/GL warnings about cpuid interception and Mesa/Zink device
selection, but the target exited cleanly.

## Replay Smoke

```bash
./env-fuzz replay --out findings/20260723-wsl-gui-calc-record/manual-click-001
```

Result:

```text
replay exit: 0
```

## Dump Summary

```text
resources_by_class:
  stdio: 3
  file: 557
  eventfd: 18
  resource: 5
  memfd: 8
  socket: 1

messages: 6295
inbound_bytes: 5723781
outbound_bytes: 249563
```

This confirms the GUI app recording captured a substantial environment surface,
including files, eventfds, memfds, and a socket.  The next useful step is to make
several deliberately different calculator interaction recordings and build an
EnvGraph from them, then compare no-graph vs active graph fuzzing.
