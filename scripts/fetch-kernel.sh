#!/bin/sh
set -eu

ARCH="${1:-x86_64}"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
KERNEL_DIR="${ROOT_DIR}/kernel/${ARCH}"
URL_FILE="${KERNEL_DIR}/artifact-url.txt"
OUTPUT_PATH="${KERNEL_DIR}/bzImage"

if [ ! -f "${URL_FILE}" ]; then
  echo "kernel artifact URL file not found: ${URL_FILE}" >&2
  exit 2
fi

URL="$(cat "${URL_FILE}")"
if [ -z "${URL}" ] || printf '%s' "${URL}" | grep -q 'example.invalid'; then
  echo "kernel artifact URL is not configured in ${URL_FILE}" >&2
  exit 2
fi

mkdir -p "${KERNEL_DIR}"
curl -L --fail --output "${OUTPUT_PATH}" "${URL}"
chmod 0644 "${OUTPUT_PATH}"
echo "kernel written to ${OUTPUT_PATH}"
