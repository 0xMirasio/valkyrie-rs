use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

#[test]
fn basic_memory_x64_feed_elf_dynamic() {
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86_64);
    let memory_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("memory_linux_64");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(1)
    //.disassemble(true)
    .feed_elf(memory_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    let initial_heap_break = vk.mem.heap_addr_exit;
    vk.run().unwrap();
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    assert!(
        vk.mem.heap_addr_exit > initial_heap_break,
        "expected heap break to grow: start={initial_heap_break:#x} end={:#x}",
        vk.mem.heap_addr_exit
    );
    VMemory::dump_stacks(&mut vk);
}

#[test]
fn basic_memory_x86_feed_elf_dynamic() {
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86);
    let memory_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join("memory_linux_32");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(1)
    //.disassemble(true)
    .feed_elf(memory_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    let initial_heap_break = vk.mem.heap_addr_exit;
    vk.run().unwrap();
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    assert!(
        vk.mem.heap_addr_exit > initial_heap_break,
        "expected heap break to grow: start={initial_heap_break:#x} end={:#x}",
        vk.mem.heap_addr_exit
    );
    VMemory::dump_stacks(&mut vk);
}
