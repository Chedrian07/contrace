# contrace

`contrace` is a tool that rehosts Docker-based Linux CTF challenges as **observable x86_64 QEMU guests**.

The project has two goals:

1. Preserve the Linux execution semantics critical to solving challenges as faithfully as possible.
2. Keep cross-architecture overhead as low as possible without compromising that preservation.

This project does not replicate Docker as-is. Instead, it extracts the runtime constructs important to single-service CTF challenges — `USER`, `WORKDIR`, `ENV`, `ENTRYPOINT/CMD`, ports, and `socat`/direct-exec style execution — and re-executes them inside the guest.

## Current Scope

- Input: directory, `zip`, `tar`-family archives
- Guest: `x86_64` only
- Rootfs: `initramfs (cpio.gz)`
- Service types: `direct`, `socat`, `xinetd`, `inetd`, `supervisord`
- Default debug/tracing:
  - `gdbserver --multi` on
  - trace preset defaults to `syscalls`
  - `tracefs` / `debugfs` mount
- Attach watchdog:
  - off by default
  - enable with `--enable-gdb-attach`

Out of scope:

- multi-container / compose
- volume / bind mount parity
- privileged / device passthrough
- Docker runtime flag parity
- systemd / full init parity
- ext4 disk image path

## Requirements

- Python 3.11+
- Docker / Docker Buildx
- `qemu-system-x86_64`
- `gdb` or `gdb-multiarch`

The kernel and guest tool bundle must be included in the repository:

- `kernel/x86_64/bzImage`
- `static/x86_64/busybox`
- `static/x86_64/gdbserver`
- `static/x86_64/trace-cmd`
- `static/x86_64/contrace-exec`

## Quick Start

Inspect:

```bash
python3 -m contrace inspect ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip --json
```

Run:

```bash
python3 -m contrace run ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip
```

Generate artifacts only:

```bash
python3 -m contrace run ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip --dry-run
```

Enable attach:

```bash
python3 -m contrace run ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip --enable-gdb-attach
```

Defaults:

- workdir: `/tmp/contrace-*`
- trace preset: `syscalls`
- `gdbserver --multi`: host port `1234`
- `gdbserver --attach`: host port `1235` (requires `--enable-gdb-attach`)

## Using GDB

`gdbserver --multi`:

```bash
gdb -q -nx ./challenge/deploy/chall
```

```gdb
set architecture i386:x86-64
target extended-remote 127.0.0.1:1234
set remote exec-file /home/chall/chall
run
```

`gdbserver --attach`:

```bash
gdb -q -nx ./challenge/deploy/chall
```

```gdb
set architecture i386:x86-64
target remote 127.0.0.1:1235
info registers
x/20i $pc
```

The `set remote exec-file` path is the **path inside the guest**.
`file ./challenge/deploy/chall` or the GDB launch argument is the **host-local ELF path**.

## Validation

Unit tests:

```bash
pytest -q
```

Full wargame zip validation:

```bash
./scripts/validate-wargame-zips.py
```

Validation results are written to `reports/wargame_zip/summary.json`.

## Architecture Overview

1. Find the `Dockerfile` from the input archive/directory.
2. Build the `linux/amd64` image with `docker buildx build`.
3. Extract metadata and rootfs via `docker inspect` and `docker export`.
4. Construct the `RuntimeSpec`.
5. Inject `/init`, `runtime.json`, and debug tools for the guest.
6. Pack the rootfs as `cpio.gz`.
7. Boot the guest with QEMU.

For more details, see the following documents:

- `ARCHITECTURE.md`
- `docs/00-mvp-scope.md`
- `docs/01-runtime-contract.md`
- `docs/02-cli-and-config.md`
- `docs/03-kernel-and-guest-profile.md`
- `docs/04-debugging-and-tracing.md`
- `docs/05-test-plan.md`
- `docs/06-risks-and-limitations.md`
- `docs/07-implementation-plan.md`
