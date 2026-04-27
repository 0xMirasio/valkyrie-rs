use std::env;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process;

use valkyrie_rs::logger::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{DRCOV, Result, Valkyrie, ValkyrieConfig};

#[derive(Debug, PartialEq, Eq)]
struct CliArgs {
    binary_path: PathBuf,
    rootfs_path: PathBuf,
    output_path: PathBuf,
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

    let guest_argv = guest_argv(&cli.binary_path, &cli.guest_args);

    Logger::info(format!(
        "running {} as X86_64 with rootfs {} -> drcov {}",
        cli.binary_path.display(),
        cli.rootfs_path.display(),
        cli.output_path.display(),
    ));

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        cli.rootfs_path.to_string_lossy().to_string(),
    )?
    .verbose(3)
    .argv(guest_argv)
    .save_trace(DRCOV)
    .save_trace_path(&cli.output_path)?
    .feed_elf(&cli.binary_path)?;

    let mut vk = Valkyrie::new(cfg)?;
    vk.run()?;

    Logger::success(format!(
        "DRCOV trace written to {}",
        cli.output_path.display()
    ));
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
        .unwrap_or_else(|| PathBuf::from("drcov_trace"));

    parse_cli_args_from(program, args)
}

fn parse_cli_args_from<I>(program: PathBuf, args: I) -> std::result::Result<CliArgs, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut rootfs_path = None;
    let mut output_path = None;
    let mut binary_path = None;
    let mut guest_args = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if binary_path.is_none() && arg == "--rootfs" {
            let Some(path) = iter.next() else {
                return Err(format!("--rootfs requires a path\n{}", usage(&program)));
            };
            rootfs_path = Some(PathBuf::from(path));
            continue;
        }

        if binary_path.is_none() && arg == "--out" {
            let Some(path) = iter.next() else {
                return Err(format!("--out requires a path\n{}", usage(&program)));
            };
            output_path = Some(PathBuf::from(path));
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

    Ok(CliArgs {
        binary_path,
        rootfs_path: rootfs_path.unwrap_or_else(|| PathBuf::from("/")),
        output_path: output_path.unwrap_or_else(|| PathBuf::from("valkyrie_trace.drcov")),
        guest_args,
    })
}

fn usage(program: &Path) -> String {
    format!(
        "usage: {} [--rootfs <path>] [--out <trace.drcov>] <binary> [args...]",
        program.to_string_lossy()
    )
}

fn guest_argv(binary_path: &Path, guest_args: &[OsString]) -> Vec<Vec<u8>> {
    let mut argv = Vec::with_capacity(guest_args.len() + 1);
    argv.push(binary_path.as_os_str().as_bytes().to_vec());
    argv.extend(guest_args.iter().cloned().map(OsStringExt::into_vec));
    argv
}
