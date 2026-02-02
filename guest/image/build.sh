#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
GUEST_DIR="${REPO_ROOT}/guest"
IMAGE_DIR="${GUEST_DIR}/image"

ALPINE_VERSION=${ALPINE_VERSION:-3.20.3}
ALPINE_BRANCH=${ALPINE_BRANCH:-v3.20}
ARCH=${ARCH:-x86_64}

OUT_DIR=${OUT_DIR:-"${IMAGE_DIR}/out"}
ROOTFS_DIR="${OUT_DIR}/rootfs"
INITRAMFS="${OUT_DIR}/initramfs.cpio.gz"
CACHE_DIR="${IMAGE_DIR}/.cache"

SANDBOXD_BIN=${SANDBOXD_BIN:-"${GUEST_DIR}/zig-out/bin/sandboxd"}

ALPINE_TARBALL="alpine-minirootfs-${ALPINE_VERSION}-${ARCH}.tar.gz"
ALPINE_URL=${ALPINE_URL:-"https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/${ARCH}/${ALPINE_TARBALL}"}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

require_cmd tar
require_cmd cpio
require_cmd gzip
require_cmd curl

mkdir -p "${CACHE_DIR}" "${OUT_DIR}"

if [[ ! -f "${SANDBOXD_BIN}" ]]; then
    echo "sandboxd binary not found, building..." >&2
    (cd "${GUEST_DIR}" && ${ZIG:-zig} build -Doptimize=ReleaseSmall)
fi

if [[ ! -f "${CACHE_DIR}/${ALPINE_TARBALL}" ]]; then
    echo "downloading ${ALPINE_URL}" >&2
    curl -L "${ALPINE_URL}" -o "${CACHE_DIR}/${ALPINE_TARBALL}"
fi

rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"

tar -xzf "${CACHE_DIR}/${ALPINE_TARBALL}" -C "${ROOTFS_DIR}"

install -m 0755 "${SANDBOXD_BIN}" "${ROOTFS_DIR}/usr/bin/sandboxd"
install -m 0755 "${IMAGE_DIR}/init" "${ROOTFS_DIR}/init"

mkdir -p "${ROOTFS_DIR}/proc" "${ROOTFS_DIR}/sys" "${ROOTFS_DIR}/dev" "${ROOTFS_DIR}/run"

(
    cd "${ROOTFS_DIR}"
    find . -print0 | cpio --null -ov --format=newc | gzip -9 > "${INITRAMFS}"
)

echo "initramfs written to ${INITRAMFS}"
