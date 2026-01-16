use std::fs;
use std::path::Path;

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

// write(1, "hello, world!\n", 14)
pub const HELLO_WRITE_X86_64: [u8; 60] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1        ; SYS_write
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1        ; fd=stdout
    0x48, 0x83, 0xEC, 0x10, // sub rsp, 0x10
    0x48, 0xBB, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, // mov rbx, 0x77202c6f6c6c6568
    0x48, 0x89, 0x1C, 0x24, // mov [rsp], rbx
    0x48, 0xBB, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x0a, 0x00,
    0x00, // mov rbx, 0x0000000a21646c726f
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
    0x48, 0x89, 0xE6, // mov rsi, rsp
    0xBA, 0x0E, 0x00, 0x00, 0x00, // mov edx, 14
    0x0F, 0x05, // syscall,
    0xB8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 1        ; Sys_exit
    0x0F, 0x05,
];

pub const HELLO_WRITE_X86: [u8; 48] = [
    0x68, 0x21, 0x0A, 0x00, 0x00, // push dword 0x00000a21
    0x68, 0x6F, 0x72, 0x6C, 0x64, // push dword 0x646c726f
    0x68, 0x6F, 0x2C, 0x20, 0x77, // push dword 0x77202c6f
    0x68, 0x68, 0x65, 0x6C, 0x6C, // push dword 0x6c6c6568
    0xB8, 0x04, 0x00, 0x00, 0x00, // mov eax, 4
    0xBB, 0x01, 0x00, 0x00, 0x00, // mov ebx, 1
    0x89, 0xE1, // mov ecx, esp
    0xBA, 0x0E, 0x00, 0x00, 0x00, // mov edx, 14
    0xCD, 0x80, // int 0x80
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x31, 0xDB, // xor ebx, ebx
    0xCD, 0x80, // int 0x80
];

#[test]
fn io_write_x86_64_oslinux_rawloader() {
    let rootfs_path = Path::new("/");
    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    //.disassemble(true)
    .entry_point(0x400000)
    .feed_baremetal(&HELLO_WRITE_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();
    VMemory::dump_stacks(&mut vk);
}

#[test]
fn io_write_x86_oslinux_rawloader() {
    let rootfs_path = Path::new("/");
    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .disassemble(true)
    .entry_point(0x400000)
    .feed_baremetal(&HELLO_WRITE_X86)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();
    VMemory::dump_stacks(&mut vk);
}

#[test]
fn io_multiple_x86_64_oslinux_fileloader() {
    let rootfs_path = Path::new("/");

    crate::rm_file_if_exists!("/tmp/d").expect("failed to remove /tmp/d before test");

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
    .verbose(true)
    .disassemble(true)
    .code_base_addr(0x400000)
    .entry_point(0x401620)
    .exit_point(0x401781)
    .feed_file(io_bin_path)
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
