use std::path::Path;
use valkyrie_rs::Valkyrie;
use valkyrie_rs::ValkyrieConfig;
use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86_64::RegX86_64;
use valkyrie_rs::vtype::{Arch, OsType};

static PROJECT_ROOT: &str = env!("CARGO_MANIFEST_DIR");

pub const HELLO_WRITE_X86_64: [u8; 10] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1        ; SYS_write
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1        ; fd=stdout
];

#[test]
fn integration_new() {
    let rootfs_path = Path::new(PROJECT_ROOT).join("rootfs").join("x8664_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::BareMetal,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .feed_baremetal(&HELLO_WRITE_X86_64)
    .unwrap()
    .disassemble(true)
    .verbose(true);

    let mut vk = Valkyrie::new(cfg).unwrap();
    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP))
        .unwrap();

    assert_eq!(rsp, 0x3e7000);

    vk.run().unwrap();
    let trap_addr = vk.exit_trap_addr.expect("exit trap not set");
    let stack_bytes = vk.mem.read(&mut vk.uc, rsp, 8).unwrap();
    let trapped = u64::from_le_bytes(stack_bytes.try_into().unwrap());

    assert_eq!(trapped, trap_addr);
}
