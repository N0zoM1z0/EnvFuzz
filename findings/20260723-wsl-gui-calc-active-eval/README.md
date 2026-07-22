# WSL GUI Calculator Active Recording Evaluation

This run tested whether several manual WSLg `gnome-calculator` recordings could
produce a useful EnvGraph for fuzzing GUI interaction traffic.

## Recordings

Target:

```bash
/usr/bin/gnome-calculator
```

Manual active recordings:

```text
basic-arithmetic        12 + 34, 7 * 8
decimal-division        5.5 * 2, 100 / 4
parentheses-precedence  parenthesized / precedence expressions
scientific-functions    menu / scientific-function interactions
error-boundary          division by zero and clear/backspace behavior
```

All five recordings exited cleanly and replay smoke tests returned `EXIT 0`.

## Dump Summary

The GUI traces are much heavier than CLI traces.  Across recordings, the dominant
interactive resources are:

```text
unix:///run/user/1000//wayland-0
unix:///run/user/1000/bus
unix:///run/user/1000/at-spi/bus
event://*
```

Static GUI/runtime dependencies dominate the file surface: Mesa/Vulkan configs,
fontconfig/XKB data, GIO module cache, dconf, shader cache, and shared libraries.

## Graphs

Two focused graphs were built from the five dumps:

```text
calc-wayland-only.graph.json:
  resources: unix:///run/user/1000//wayland-0
  candidate groups=97, payloads=1832

calc-wayland-active.graph.json:
  resources: wayland + session bus + at-spi bus + eventfd
  candidate groups=120, payloads=2101
```

## Focused Fuzz Setup

An isolated run cwd was used:

```text
focused-cwd/
  ignore.tab
  lib -> repo lib symlink
  fcntl.tab/ioctl.tab/prctl.tab -> repo table symlinks
```

The focused `ignore.tab` ignores absolute-path file resources, eventfds, memfds,
stdio, pipes, epoll, and netlink.  This keeps the comparison focused on
`unix://...` GUI/session traffic instead of static GUI configuration files.

Source seed:

```text
recordings/basic-arithmetic/RECORD.pcap.gz
```

Eval:

```text
configs: nograph, wayland_only_graph, wayland_bus_graph
seeds: 8201..8205
budget: --max-execs 300 --max-time 30
```

## Results

```text
nograph:
  mean outs=8.0/10, min/max=5..9
  mean patches=135.8, mean hangs=23.6
  mean graph=0, mean frontier=0

wayland_only_graph:
  mean outs=7.4/10, min/max=1..9
  mean patches=137.4, mean hangs=23.6
  mean graph=10.4, mean frontier=0

wayland_bus_graph:
  mean outs=4.8/10, min/max=3..6
  mean patches=129.6, mean hangs=19.0
  mean graph=389.0, mean frontier=0
```

No crash or abort artifacts were produced.  Hangs are frequent in this GUI
socket-focused setup and should be treated as timeout-style behavior unless
triaged individually.

## Decision

Manual GUI active recording works operationally: WSLg calculator can be recorded,
replayed, dumped, and converted into a graph.  The graph also affects runtime:
Wayland-only graphs hit a few replacements per run, and Wayland+bus graphs hit
hundreds.

However, low-level GUI socket replacement did not improve fuzzing.  Wayland-only
was slightly worse than no-graph, and Wayland+bus was substantially worse on
output coverage despite more graph hits.  This suggests that the useful unit for
GUI apps is not a raw Wayland/session-bus message payload.  It is a semantic UI
action with a state precondition, such as button press sequences, mode changes,
or expression-entry operations.

The next meaningful direction is to lift manual recordings into GUI action
models rather than directly replaying/mutating low-level protocol messages.
