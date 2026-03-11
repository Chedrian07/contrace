#!/bin/sh
set -eu

ARCH="${1:-x86_64}"
KERNEL_VERSION="${KERNEL_VERSION:-6.6.52}"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
KERNEL_DIR="${ROOT_DIR}/kernel/${ARCH}"
CONFIG_PATH="${KERNEL_DIR}/config"
OUTPUT_PATH="${KERNEL_DIR}/bzImage"

if [ "${ARCH}" != "x86_64" ]; then
  echo "unsupported arch: ${ARCH}" >&2
  exit 2
fi

if [ ! -f "${CONFIG_PATH}" ]; then
  echo "kernel config not found: ${CONFIG_PATH}" >&2
  exit 2
fi

docker run --rm \
  -v "${ROOT_DIR}:/workspace" \
  -w /workspace \
  ubuntu:24.04 \
  /bin/sh -euxc "
    apt-get update
    apt-get install -y build-essential bc bison flex libssl-dev libelf-dev pahole wget xz-utils
    wget -O /tmp/linux.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz
    rm -rf /tmp/linux-src
    mkdir -p /tmp/linux-src
    tar -xf /tmp/linux.tar.xz -C /tmp/linux-src --strip-components=1
    cp ${CONFIG_PATH} /tmp/linux-src/.config
    make -C /tmp/linux-src olddefconfig
    make -C /tmp/linux-src -j\$(nproc) bzImage
    cp /tmp/linux-src/arch/x86/boot/bzImage ${OUTPUT_PATH}
  "

echo "kernel written to ${OUTPUT_PATH}"
