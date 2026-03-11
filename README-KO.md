# contrace

`contrace`는 Docker 기반 Linux CTF 문제를 **관찰 가능한 x86_64 QEMU guest**로 재호스팅하는 도구다.

프로젝트 목표는 두 가지다.

1. 문제 풀이에 중요한 Linux 실행 의미론을 최대한 보존한다.
2. 그 보존 수준을 해치지 않는 범위에서 크로스 아키텍처 오버헤드를 가능한 낮게 유지한다.

이 프로젝트는 Docker를 그대로 복제하지 않는다. 대신 단일 서비스형 CTF 문제에서 중요한 `USER`, `WORKDIR`, `ENV`, `ENTRYPOINT/CMD`, 포트, `socat`/direct-exec 류 실행 구조를 추출해 guest 안에서 다시 실행한다.

## 현재 범위

- 입력: 디렉터리, `zip`, `tar` 계열 archive
- guest: `x86_64` only
- rootfs: `initramfs (cpio.gz)`
- 서비스 유형: `direct`, `socat`, `xinetd`, `inetd`, `supervisord`
- 기본 debug/tracing:
  - `gdbserver --multi` on
  - trace preset 기본값 `syscalls`
  - `tracefs` / `debugfs` mount
- attach watchdog:
  - 기본값 off
  - `--enable-gdb-attach`로 활성화

지원하지 않는 범위:

- multi-container / compose
- volume / bind mount parity
- privileged / device passthrough
- Docker runtime flag parity
- systemd/full init parity
- ext4 disk image path

## 요구 사항

- Python 3.11+
- Docker / Docker Buildx
- `qemu-system-x86_64`
- `gdb` 또는 `gdb-multiarch`

커널과 guest tool bundle은 저장소에 포함되어 있어야 한다.

- `kernel/x86_64/bzImage`
- `static/x86_64/busybox`
- `static/x86_64/gdbserver`
- `static/x86_64/trace-cmd`
- `static/x86_64/contrace-exec`

## 빠른 시작

inspect:

```bash
python3 -m contrace inspect ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip --json
```

실행:

```bash
python3 -m contrace run ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip
```

artifact만 생성:

```bash
python3 -m contrace run ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip --dry-run
```

attach 활성화:

```bash
python3 -m contrace run ./wargame_zip/ad83460e-059d-46d2-af12-2d1d1c213dda.zip --enable-gdb-attach
```

기본값:

- workdir: `/tmp/contrace-*`
- trace preset: `syscalls`
- `gdbserver --multi`: host `1234`
- `gdbserver --attach`: host `1235` (`--enable-gdb-attach` 필요)

## GDB 사용

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

`set remote exec-file` 경로는 **guest 내부 경로**다.
`file ./challenge/deploy/chall` 또는 GDB 실행 인자는 **호스트 로컬 ELF 경로**다.

## 검증

단위 테스트:

```bash
pytest -q
```

wargame zip 전체 검증:

```bash
./scripts/validate-wargame-zips.py
```

검증 결과는 `reports/wargame_zip/summary.json`에 기록된다.

## 아키텍처 요약

1. 입력 archive/디렉터리에서 `Dockerfile`을 찾는다.
2. `docker buildx build`로 `linux/amd64` 이미지를 빌드한다.
3. `docker inspect`와 `docker export`로 metadata와 rootfs를 추출한다.
4. `RuntimeSpec`을 구성한다.
5. guest용 `/init`, `runtime.json`, debug 도구를 주입한다.
6. rootfs를 `cpio.gz`로 패킹한다.
7. QEMU로 guest를 부팅한다.

더 자세한 내용은 아래 문서를 본다.

- `ARCHITECTURE.md`
- `docs/00-mvp-scope.md`
- `docs/01-runtime-contract.md`
- `docs/02-cli-and-config.md`
- `docs/03-kernel-and-guest-profile.md`
- `docs/04-debugging-and-tracing.md`
- `docs/05-test-plan.md`
- `docs/06-risks-and-limitations.md`
- `docs/07-implementation-plan.md`
