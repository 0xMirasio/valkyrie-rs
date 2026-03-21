use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
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

#[derive(Debug, PartialEq, Eq)]
struct CliArgs {
    binary_path: PathBuf,
    rootfs_path: PathBuf,
    guest_args: Vec<OsString>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = parse_cli_args(env::args_os()).unwrap_or_else(|err| {
        eprintln!("{err}");
        process::exit(2);
    });

    let arch = detect_elf_arch(&cli.binary_path)?;
    let guest_argv = guest_argv(&cli.binary_path, &cli.guest_args);

    Logger::info(format!(
        "running {} as {arch:?} with rootfs {} and {} guest args",
        cli.binary_path.display(),
        cli.rootfs_path.display(),
        cli.guest_args.len(),
    ));

    let cfg = ValkyrieConfig::new(
        arch,
        OsType::Linux,
        cli.rootfs_path.to_string_lossy().to_string(),
    )?
    .verbose(true)
    .argv(guest_argv)
    .feed_elf(&cli.binary_path)?;

    let mut vk = Valkyrie::new(cfg)?;
    vk.run()?;
    VMemory::dump_stacks(&mut vk);

    Logger::success("Valkyrie : done");
    Ok(())
}

fn parse_cli_args<I>(args: I) -> std::result::Result<CliArgs, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let program = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("run_binary"));

    parse_cli_args_from(program, args)
}

fn parse_cli_args_from<I>(program: PathBuf, args: I) -> std::result::Result<CliArgs, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut rootfs_path = None;
    let mut binary_path = None;
    let mut guest_args = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if binary_path.is_none() && arg == "--rootfs" {
            let Some(path) = iter.next() else {
                return Err(format!(
                    "--rootfs requires a path\n{}",
                    usage(&program),
                ));
            };
            rootfs_path = Some(PathBuf::from(path));
            continue;
        }

        if binary_path.is_none() {
            binary_path = Some(PathBuf::from(arg));
            continue;
        }

        guest_args.push(arg);
    }

    let Some(binary_path) = binary_path else {
        return Err(usage(&program));
    };

    if rootfs_path.is_none() && guest_args.len() == 1 {
        let legacy_rootfs = PathBuf::from(&guest_args[0]);
        if legacy_rootfs.is_dir() {
            rootfs_path = Some(legacy_rootfs);
            guest_args.clear();
        }
    }

    Ok(CliArgs {
        binary_path,
        rootfs_path: rootfs_path.unwrap_or_else(|| PathBuf::from("/")),
        guest_args,
    })
}

fn usage(program: &Path) -> String {
    format!(
        "usage: {} [--rootfs <path>] <binary> [args...]",
        program.to_string_lossy()
    )
}

fn guest_argv(binary_path: &Path, guest_args: &[OsString]) -> Vec<Vec<u8>> {
    let mut argv = Vec::with_capacity(guest_args.len() + 1);
    argv.push(binary_path.as_os_str().as_bytes().to_vec());
    argv.extend(guest_args.iter().cloned().map(OsStringExt::into_vec));
    argv
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_guest_args_without_rootfs() {
        let parsed = parse_cli_args_from(
            PathBuf::from("run_binary"),
            vec![OsString::from("/bin/ls"), OsString::from("-la")],
        )
        .unwrap();

        assert_eq!(parsed.binary_path, PathBuf::from("/bin/ls"));
        assert_eq!(parsed.rootfs_path, PathBuf::from("/"));
        assert_eq!(parsed.guest_args, vec![OsString::from("-la")]);
    }

    #[test]
    fn parse_explicit_rootfs_flag() {
        let parsed = parse_cli_args_from(
            PathBuf::from("run_binary"),
            vec![
                OsString::from("--rootfs"),
                OsString::from("/tmp/rootfs"),
                OsString::from("/bin/ls"),
                OsString::from("-la"),
            ],
        )
        .unwrap();

        assert_eq!(parsed.binary_path, PathBuf::from("/bin/ls"));
        assert_eq!(parsed.rootfs_path, PathBuf::from("/tmp/rootfs"));
        assert_eq!(parsed.guest_args, vec![OsString::from("-la")]);
    }

    #[test]
    fn parse_legacy_positional_rootfs() {
        let parsed = parse_cli_args_from(
            PathBuf::from("run_binary"),
            vec![OsString::from("/bin/ls"), OsString::from("/")],
        )
        .unwrap();

        assert_eq!(parsed.binary_path, PathBuf::from("/bin/ls"));
        assert_eq!(parsed.rootfs_path, PathBuf::from("/"));
        assert!(parsed.guest_args.is_empty());
    }
}
