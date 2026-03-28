#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ram_root="${VALKYRIE_AFL_RAM_DIR:-/dev/shm/valkyrie-fuzzing_simple_crash_elf_x64}"

if [[ ! -d /dev/shm ]]; then
    echo "/dev/shm is missing on this host" >&2
    exit 1
fi

fs_type="$(stat -f -c %T /dev/shm 2>/dev/null || echo unknown)"
if [[ "${fs_type}" != "tmpfs" ]]; then
    echo "warning: /dev/shm is not tmpfs (detected ${fs_type})" >&2
fi

mkdir -p "${ram_root}/afl_out" "${ram_root}/afl_crashs"
find "${ram_root}/afl_out" -mindepth 1 -delete
find "${ram_root}/afl_crashs" -mindepth 1 -delete

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

link_output "afl_out"
link_output "afl_crashs"

echo "prepared LibAFL RAM workspace:"
echo "  corpus:  ${ram_root}/afl_out"
echo "  crashes: ${ram_root}/afl_crashs"
echo "local links:"
echo "  ${script_dir}/afl_out"
echo "  ${script_dir}/afl_crashs"
