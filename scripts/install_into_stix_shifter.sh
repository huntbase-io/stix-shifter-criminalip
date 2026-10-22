#!/usr/bin/env bash
# Install the Criminal IP connector into a stix-shifter checkout.
#
#   scripts/install_into_stix_shifter.sh [--copy] <path-to-stix-shifter>
#
# Default: symlink <stix-shifter>/stix_shifter_modules/criminalip -> this repo's module (handy for development).
# --copy:  copy the module instead (what you want before building wheels or opening an upstream PR).
set -euo pipefail

mode=link
if [[ "${1:-}" == "--copy" ]]; then
    mode=copy
    shift
fi
if [[ $# -ne 1 ]]; then
    echo "usage: $0 [--copy] <path-to-stix-shifter>" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${repo_root}/stix_shifter_modules/criminalip"
target_root="$(cd "$1" && pwd)"
modules_dir="${target_root}/stix_shifter_modules"
dest="${modules_dir}/criminalip"

if [[ ! -f "${modules_dir}/config.json" || ! -f "${target_root}/main.py" ]]; then
    echo "error: ${target_root} does not look like a stix-shifter checkout" >&2
    exit 1
fi

if [[ -L "${dest}" ]]; then
    rm "${dest}"
elif [[ -e "${dest}" ]]; then
    echo "error: ${dest} already exists and is not a symlink; remove it first" >&2
    exit 1
fi

if [[ "${mode}" == "copy" ]]; then
    mkdir -p "${dest}"
    (cd "${src}" && tar --exclude='__pycache__' --exclude='*.pyc' -cf - .) | (cd "${dest}" && tar -xf -)
    echo "copied ${src} -> ${dest}"
else
    ln -s "${src}" "${dest}"
    echo "linked ${dest} -> ${src}"
fi
