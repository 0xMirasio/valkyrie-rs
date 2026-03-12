use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

#[test]
fn basic_common_x64_feed_elf_static() {
    let rootfs_path = Path::new("/");
    let common_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("common_linux_64_static");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .feed_elf(common_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();
    VMemory::dump_stacks(&mut vk);
}

#[test]
fn basic_common_x86_feed_elf_static() {
    let rootfs_path = Path::new("/");
    let common_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("common_linux_32_static");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    //.disassemble(true)
    .feed_elf(common_bin_path)
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
}
