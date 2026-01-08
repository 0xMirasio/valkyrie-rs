use std::path::Path;

use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86::RegX86;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

// exit()
pub const EXIT_X86: [u8; 7] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xCD, 0x80, // int 0x80
];

#[test]
fn integration_syscall_exit_x86_linux() {
    let rootfs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("rootfs")
        .join("x86_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .entry_point(0x400000)
    .feed_baremetal(&EXIT_X86)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let esp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::ESP))
        .unwrap();

    vk.run().unwrap();

    let trap_addr = vk.exit_trap_addr.expect("exit trap not set") as u32;
    let stack_bytes = vk.mem.read(&mut vk.uc, esp, 4).unwrap();
    let trapped = u32::from_le_bytes(stack_bytes.try_into().unwrap());
    assert_eq!(trapped, trap_addr);
}
