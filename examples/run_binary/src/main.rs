use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use valkyrie_rs::logger::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Result, VMemory, Valkyrie, ValkyrieConfig};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os();
    let program = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run_binary"));

    let Some(binary_path) = args.next().map(PathBuf::from) else {
        eprintln!(
            "usage: {} <binary> [rootfs]",
            program.to_string_lossy()
        );
        process::exit(2);
    };

    let rootfs_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));

    let arch = detect_elf_arch(&binary_path)?;

    Logger::info(format!(
        "running {} as {arch:?} with rootfs {}",
        binary_path.display(),
        rootfs_path.display(),
    ));

    let cfg = ValkyrieConfig::new(
        arch,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )?
    .verbose(true)
    .feed_elf(&binary_path)?;

    let mut vk = Valkyrie::new(cfg)?;
    vk.run()?;
    VMemory::dump_stacks(&mut vk);

    Logger::success("Valkyrie : done");
    Ok(())
}

fn detect_elf_arch(path: &Path) -> Result<Arch> {
    let header = fs::read(path)?;
    if header.len() < 20 {
        return Err(valkyrie_rs::error::ValkyrieError::BadConfig(
            "ELF file too small",
        ));
    }

    if &header[..4] != ELF_MAGIC {
        return Err(valkyrie_rs::error::ValkyrieError::BadConfig(
            "input is not an ELF file",
        ));
    }

    let elf_class = header[4];
    let machine = u16::from_le_bytes([header[18], header[19]]);

    match (elf_class, machine) {
        (ELF_CLASS_32, EM_386) => Ok(Arch::X86),
        (ELF_CLASS_64, EM_X86_64) => Ok(Arch::X86_64),
        _ => Err(valkyrie_rs::error::ValkyrieError::Loader(
            "only x86 and x86_64 ELF binaries are supported by this example",
        )),
    }
}
