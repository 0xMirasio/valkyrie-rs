# Fuzzing examples

- example01 : x64 simple crash variants under `examples/fuzzing/example01/`
- `example01-static-elf_full_load` : static ELF, full-load reusable runner
- `example01-static-elf-snapshot` : static ELF, snapshot at `main`
- `example01-dynamic-full_load` : dynamic ELF, full-load reusable runner (`x8664_linux_glibc2.39` rootfs)
- `example01-elf-snapshot` : dynamic ELF, snapshot at `main` (`x8664_linux_glibc2.39` rootfs)
- example02 : x64 dynamic elf / complex crash in png parsing / afl loop via snapshot restauration before scan_png. valkyrie monitor, `afl_out/` layout on `/dev/shm`
