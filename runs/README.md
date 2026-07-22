# EnvFuzz Run Artifacts

Generated campaigns, temporary graph dumps, and fuzz outputs should live under
this directory instead of the repository root.

Suggested layout:

```text
runs/<campaign-name>/      EnvFuzz --out directory
runs/tmp/                 transient graph dumps and benchmark scratch files
runs/legacy/              artifacts moved from older root-level experiments
```

The directory is ignored by git except for this README and `.gitkeep`.

