use std::fs;
use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

fn reset_io_guest_paths(rootfs_path: &Path) {
    let tmp_dir = rootfs_path.join("tmp");
    fs::create_dir_all(&tmp_dir).expect("failed to create rootfs /tmp before test");

    for file_name in ["f", "m", "d", "valkyrie_missing.sock"] {
        let path = tmp_dir.join(file_name);
        crate::rm_file_if_exists!(&path)
            .unwrap_or_else(|e| panic!("failed to remove {path:?} before test: {e}"));
    }
}

#[test]
fn basic_io_x86_64_feed_elf_dynamic() {
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86_64);
    reset_io_guest_paths(&rootfs_path);
    let tmp_dir = rootfs_path.join("tmp");
    let output_path = tmp_dir.join("d");

    let io_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("io_linux_64");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(1)
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
fn basic_io_x86_feed_elf_dynamic() {
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86);
    reset_io_guest_paths(&rootfs_path);
    let tmp_dir = rootfs_path.join("tmp");
    let output_path = tmp_dir.join("d");

    let io_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("io_linux_32");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(1)
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
