use std::fs;
use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

#[test]
fn io_multiple_x86_64_oslinux_elfloader_static() {
    let rootfs_path = Path::new("/");

    crate::rm_file_if_exists!("/tmp/d").expect("failed to remove /tmp/d before test");

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
    VMemory::dump_stacks(&mut vk);

    let p = Path::new("/tmp/d");
    assert!(p.exists(), "expected {p:?} to exist after vk.run()");

    let content = fs::read(p).expect("failed to read /tmp/d");
    assert_eq!(
        content, b"test\n",
        "unexpected content in /tmp/d: {content:?}"
    );
}

// TODO : fix io_multiple_x86_oslinux_elfloader_static
/*
#[test]
fn io_multiple_x86_oslinux_elfloader_static() {
    let rootfs_path = Path::new("/");

    crate::rm_file_if_exists!("/tmp/d").expect("failed to remove /tmp/d before test");

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
    VMemory::dump_stacks(&mut vk);

    let p = Path::new("/tmp/d");
    assert!(p.exists(), "expected {p:?} to exist after vk.run()");

    let content = fs::read(p).expect("failed to read /tmp/d");
    assert_eq!(
        content, b"test\n",
        "unexpected content in /tmp/d: {content:?}"
    );
}
*/
