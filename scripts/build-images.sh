#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# build-images.sh
#
# Builds every OCI image declared under images/ and saves each one as a tarball
# inside desktop/resources/images/. Those tarballs are then picked up by
# electron-builder (see desktop/electron-builder.yml) and shipped INSIDE the
# desktop installer so the user never has to pull from a registry.
#
# This is the build-machine side of the Model B (tarball bundle) distribution
# flow described in images/README.md. It is intended to run on the CI/release
# host that prepares the installer, not on the end user's workstation.
#
# Requires:
#   - docker on PATH (the build host's responsibility; see CLAUDE.md RULE 1
#     for why this is acceptable here: the user gets the resulting .tar files
#     bundled in the installer and only needs a runtime to load/run them).
#
# Usage:
#   ./scripts/build-images.sh
# -----------------------------------------------------------------------------

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_DIR="${REPO_ROOT}/images"
OUT_DIR="${REPO_ROOT}/desktop/resources/images"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: 'docker' not found on PATH." >&2
  echo "This script runs on the build/CI host; see CLAUDE.md RULE 1 for the" >&2
  echo "bundling contract (end users do not need docker installed by this script;" >&2
  echo "the build host does, because it produces the tarballs that ship inside" >&2
  echo "the installer)." >&2
  exit 1
fi

if [ ! -d "${IMAGES_DIR}" ]; then
  echo "error: images directory not found at ${IMAGES_DIR}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

shopt -s nullglob
for entry in "${IMAGES_DIR}"/*; do
  [ -d "${entry}" ] || continue
  name="$(basename "${entry}")"
  tag="forensia/${name}:latest"
  tar_path="${OUT_DIR}/${name}.tar"

  docker build -t "${tag}" "${IMAGES_DIR}/${name}/" >/dev/null
  docker save "${tag}" -o "${tar_path}"

  # Size in MB (1 MB = 1024 * 1024 bytes), portable across GNU/BSD stat.
  bytes="$(wc -c < "${tar_path}" | tr -d ' ')"
  size_mb="$(( (bytes + 1048575) / 1048576 ))"
  echo "${name}: built and saved (${size_mb} MB)"
done
shopt -u nullglob
