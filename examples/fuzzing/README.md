# Fuzzing examples

- example01 : x64 dynamic elf / simple crash with stdin / no afl loop, elf launched every iterations, `afl_out/` layout (`queue/`, `crash/`, `config/`, `state/`), valkyrie monitor, classic IO  
- example02 : x64 dynamic elf / complex crash in png parsing / afl loop via snapshot restauration before scan_png. valkyrie monitor, `afl_out/` layout on `/dev/shm`
- example03 :  DRCOV coverage trace generation example
