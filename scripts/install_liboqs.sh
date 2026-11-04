#!/usr/bin/env bash
# Build and install liboqs from source (CLAUDE.md §6: "build from source with CMake").
#
# This script is the single source of truth for the liboqs version. It is used by
#   - local setup (README),
#   - docker/Dockerfile.* (build stage),
#   - .github/workflows/ci.yml.
#
# Why build from source instead of a distro package?
#   * Distro packages lag behind and may not ship the final FIPS 203/204 algorithms.
#   * We pin an exact release tag *and* its commit hash, so a moved tag is detected.
#   * We build a minimal library containing only ML-KEM-768 and ML-DSA-65
#     (smaller attack surface, faster build). See docs/decisions/ADR-001.
#
# Usage: scripts/install_liboqs.sh [PREFIX]      (default PREFIX=/usr/local)
set -euo pipefail

LIBOQS_VERSION="0.16.0"
# Commit that tag 0.16.0 points to (git ls-remote --tags, 2026-11-04).
LIBOQS_COMMIT="5a1a854b0dc9f2141bdc771c555ee60c37950183"
PREFIX="${1:-/usr/local}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

git clone --quiet --depth 1 --branch "$LIBOQS_VERSION" \
    https://github.com/open-quantum-safe/liboqs.git "$WORKDIR/liboqs"

actual_commit="$(git -C "$WORKDIR/liboqs" rev-parse HEAD)"
if [[ "$actual_commit" != "$LIBOQS_COMMIT" ]]; then
    echo "ERROR: liboqs tag $LIBOQS_VERSION resolves to $actual_commit, expected $LIBOQS_COMMIT" >&2
    exit 1
fi

cmake -S "$WORKDIR/liboqs" -B "$WORKDIR/build" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"
ninja -C "$WORKDIR/build"
ninja -C "$WORKDIR/build" install

if command -v ldconfig >/dev/null 2>&1 && [[ "$(id -u)" == "0" ]]; then
    ldconfig
fi
echo "liboqs $LIBOQS_VERSION installed to $PREFIX"
