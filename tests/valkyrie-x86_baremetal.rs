use std::path::Path;
use valkyrie_rs::Valkyrie;
use valkyrie_rs::ValkyrieConfig;
use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86::RegX86;
use valkyrie_rs::vtype::{Arch, OsType};

static PROJECT_ROOT: &str = env!("CARGO_MANIFEST_DIR");

pub const HELLO_WRITE_X86_64: [u8; 38] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1        ; SYS_write
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1        ; fd=stdout
    0x48, 0x8D, 0x35, 0x10, 0x00, 0x00, 0x00, // lea rsi, [rip+0x10]; &"hello"
    0xBA, 0x05, 0x00, 0x00, 0x00, // mov edx, 5        ; len
    0x0F, 0x05, // syscall
    0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60       ; SYS_exit
    0x31, 0xFF, // xor edi, edi      ; status=0
    0x0F, 0x05, // syscall
    0x68, 0x65, 0x6C, 0x6C, 0x6F, // "hello"
];

#[test]
fn integration_new() {
    let rootfs_path = Path::new(PROJECT_ROOT).join("rootfs").join("x8664_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::BareMetal,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .feed_baremetal(&HELLO_WRITE_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    let esp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::ESP))
        .unwrap();

    assert_eq!(esp, 0x3e7000);
}
