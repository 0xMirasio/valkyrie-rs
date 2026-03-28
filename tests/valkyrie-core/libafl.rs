#![cfg(feature = "libafl")]

use std::path::{Path, PathBuf};

use libafl::executors::ExitKind;
use libafl::inputs::BytesInput;
use valkyrie_rs::fuzzing::{
    DEFAULT_COVERAGE_MAP_SIZE, ReusableEmulator, emulate_input_with_coverage,
};
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

fn linux_rootfs(arch: Arch) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rootfs");
    match arch {
        Arch::X86 => root.join("x86_linux"),
        Arch::X86_64 => root.join("x8664_linux"),
    }
}

fn crash_binary(arch: Arch) -> PathBuf {
    let name = match arch {
        Arch::X86 => "loader_crash_linux_32_static",
        Arch::X86_64 => "loader_crash_linux_64_static",
    };

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join(name)
}

fn run_crash_test(arch: Arch) {
    let rootfs_path = linux_rootfs(arch);
    let elf_path = crash_binary(arch);
    let mut coverage = vec![0_u8; DEFAULT_COVERAGE_MAP_SIZE];

    let ok_exit =
        emulate_input_with_coverage(&BytesInput::new(b"NOPE".to_vec()), &mut coverage, |stdin| {
            let cfg = ValkyrieConfig::new(
                arch,
                OsType::Linux,
                rootfs_path.to_string_lossy().to_string(),
            )
            .unwrap()
            .stdin_bytes(stdin)
            .feed_elf(&elf_path)
            .unwrap();
            Valkyrie::new(cfg)
        })
        .unwrap();
    assert_eq!(ok_exit, ExitKind::Ok);
    assert!(
        coverage.iter().any(|&byte| byte != 0),
        "coverage map stayed empty for arch={arch:?}"
    );

    let crash_exit =
        emulate_input_with_coverage(&BytesInput::new(b"ABC".to_vec()), &mut coverage, |stdin| {
            let cfg = ValkyrieConfig::new(
                arch,
                OsType::Linux,
                rootfs_path.to_string_lossy().to_string(),
            )
            .unwrap()
            .stdin_bytes(stdin)
            .feed_elf(&elf_path)
            .unwrap();
            Valkyrie::new(cfg)
        })
        .unwrap();
    assert_eq!(crash_exit, ExitKind::Crash);
    assert!(
        coverage.iter().any(|&byte| byte != 0),
        "coverage map stayed empty during crash case for arch={arch:?}"
    );
}

#[test]
fn basic_libafl_x86_64_crash_feed_elf_static() {
    run_crash_test(Arch::X86_64);
}

#[test]
fn basic_libafl_x86_crash_feed_elf_static() {
    run_crash_test(Arch::X86);
}

#[test]
fn basic_libafl_x86_64_reusable_runner_resets_between_inputs() {
    let arch = Arch::X86_64;
    let rootfs_path = linux_rootfs(arch);
    let elf_path = crash_binary(arch);
    let mut coverage = vec![0_u8; DEFAULT_COVERAGE_MAP_SIZE];

    let cfg = ValkyrieConfig::new(
        arch,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .feed_elf(&elf_path)
    .unwrap();
    let vk = Valkyrie::new(cfg).unwrap();
    let mut runner = ReusableEmulator::new(vk, &mut coverage).unwrap();

    let ok_exit = runner
        .run_input(&BytesInput::new(b"NOPE".to_vec()))
        .unwrap();
    assert_eq!(ok_exit, ExitKind::Ok);
    assert!(coverage.iter().any(|&byte| byte != 0));

    let crash_exit = runner.run_input(&BytesInput::new(b"ABC".to_vec())).unwrap();
    assert_eq!(crash_exit, ExitKind::Crash);
    assert!(coverage.iter().any(|&byte| byte != 0));
}
