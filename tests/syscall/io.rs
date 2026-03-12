use std::fs;
use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

#[test]
fn basic_io_x86_64_feed_elf_static() {
    let rootfs_path = crate::linux_rootfs(Arch::X86_64);

    let output_path = rootfs_path.join("tmp").join("d");
    crate::rm_file_if_exists!(&output_path).expect("failed to remove rootfs /tmp/d before test");

    let io_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("io_linux_64_static");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    //.disassemble(true)
    .feed_elf(io_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    vk.run().unwrap();
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    VMemory::dump_stacks(&mut vk);

    let p = output_path.as_path();
    assert!(p.exists(), "expected {p:?} to exist after vk.run()");

    let content = fs::read(p).expect("failed to read /tmp/d");
    assert_eq!(
        content, b"test\n",
        "unexpected content in /tmp/d: {content:?}"
    );
}

#[test]
fn basic_io_x86_feed_elf_static() {
    let rootfs_path = crate::linux_rootfs(Arch::X86);

    let output_path = rootfs_path.join("tmp").join("d");
    crate::rm_file_if_exists!(&output_path).expect("failed to remove rootfs /tmp/d before test");

    let io_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("io_linux_32_static");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    //.disassemble(true)
    .feed_elf(io_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    vk.run().unwrap();
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    VMemory::dump_stacks(&mut vk);

    let p = output_path.as_path();
    assert!(p.exists(), "expected {p:?} to exist after vk.run()");

    let content = fs::read(p).expect("failed to read /tmp/d");
    assert_eq!(
        content, b"test\n",
        "unexpected content in /tmp/d: {content:?}"
    );
}
