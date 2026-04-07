#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ram_root="${VALKYRIE_AFL_RAM_DIR:-/dev/shm/valkyrie-fuzzing_ex01}"

if [[ ! -d /dev/shm ]]; then
    echo "/dev/shm is missing on this host" >&2
    exit 1
fi

fs_type="$(stat -f -c %T /dev/shm 2>/dev/null || echo unknown)"
if [[ "${fs_type}" != "tmpfs" ]]; then
    echo "warning: /dev/shm is not tmpfs (detected ${fs_type})" >&2
fi

mkdir -p "${ram_root}/queue" "${ram_root}/crashes"
find "${ram_root}/queue" -mindepth 1 -delete
find "${ram_root}/crashes" -mindepth 1 -delete

link_output() {
    local name="$1"
    local target="${ram_root}/${name}"
    local local_path="${script_dir}/${name}"

    if [[ -e "${local_path}" && ! -L "${local_path}" ]]; then
        echo "${local_path} exists and is not a symlink; remove it first" >&2
        exit 1
    fi

    ln -sfn "${target}" "${local_path}"
}

link_output "queue"
link_output "crashes"

echo "prepared LibAFL RAM workspace:"
echo "  queue:   ${ram_root}/queue"
echo "  crashes: ${ram_root}/crashes"
echo "local links:"
echo "  ${script_dir}/queue"
echo "  ${script_dir}/crashes"
