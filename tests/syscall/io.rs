use std::path::Path;

use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86_64::RegX86_64;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

// write(1, "hello, world!\n", 14)
pub const HELLO_WRITE_X86_64: [u8; 53] = [
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
    0x0F, 0x05, // syscall
];

#[test]
fn integration_syscall_write() {
    let rootfs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rootfs")
        .join("x8664_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .entry_point(0x400000)
    .feed_baremetal(&HELLO_WRITE_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP))
        .unwrap();

    vk.run().unwrap();

    let rax = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RAX))
        .unwrap();

    assert_eq!(rax, 14, "write() should return 14, got {rax}");

    let trap_addr = vk.exit_trap_addr.expect("exit trap not set");
    let stack_bytes = vk.mem.read(&mut vk.uc, rsp, 8).unwrap();
    let trapped = u64::from_le_bytes(stack_bytes.try_into().unwrap());
    assert_eq!(trapped, trap_addr);
}

// TODO
// - add more syscall tests (read, open, close, etc)
