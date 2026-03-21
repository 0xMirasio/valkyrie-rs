use std::fs;
use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

fn reset_network_guest_paths(rootfs_path: &Path) {
    let tmp_dir = rootfs_path.join("tmp");
    fs::create_dir_all(&tmp_dir).expect("failed to create rootfs /tmp before test");

    let path = tmp_dir.join("valkyrie_missing.sock");
    crate::rm_file_if_exists!(&path)
        .unwrap_or_else(|e| panic!("failed to remove {path:?} before test: {e}"));
}

#[test]
fn basic_network_x86_64_feed_elf_dynamic() {
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86_64);
    reset_network_guest_paths(&rootfs_path);

    let network_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("network_linux_64");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .feed_elf(network_bin_path)
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

#[test]
fn basic_network_x86_feed_elf_dynamic() {
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86);
    reset_network_guest_paths(&rootfs_path);

    let network_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("network_linux_32");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .feed_elf(network_bin_path)
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
