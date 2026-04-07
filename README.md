# valkyrie-rs

`valkyrie-rs` is a Rust binary emulator aimed at fast program analysis and fuzzing workflows. It currently exposes:

- architectures: `x86`, `x86_64`
- guest modes: `BareMetal`, `Linux`
- loaders: raw blobs and ELF binaries (Static/Dynamic)
- LibAFL integration

Subproject usage:
- Unicorn for cpu emulation
- lief for elf parsers
- capstone for disassembly
- libafl for fuzzing

## Why

Fast binary fuzzing is hard. Qiling got advanced support for emulation but fuzzing is very slow. Qemu can become hardcore to setup with complex target. The goal of this project is to provide a Rust-native emulator+fuzzer that is easier to embed into fuzzing workflows.

## Repository Setup

The repository depends on the `rootfs/` submodule. (qiling rootfs github)  

```bash
git clone https://github.com/0xMirasio/valkyrie-rs.git --depth 1 --recursive
```

## System Dependencies

Recommended Ubuntu/Debian packages:

```bash
sudo apt install libclang-15-dev cmake gcc g++ pkg-config make
```

## Build

Raw emulator
```bash
cargo build --release
```

with LibAFL support:

```bash
cargo build --release --features libafl
```

## Quick Start

### Run a Linux ELF

```rust
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

fn main() -> valkyrie_rs::Result<()> {
    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        "rootfs/x8664_linux".to_string(),
    )?
    .argv([b"/bin/true".to_vec()])
    .feed_elf("rootfs/x8664_linux/bin/true")?;

    let mut vk = Valkyrie::new(cfg)?;
    vk.run()?;

    assert_eq!(vk.exit_status, Some(0));
    Ok(())
}
```

see examples for valkyrie usage. 