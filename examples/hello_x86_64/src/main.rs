use std::path::Path;

use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86_64::RegX86_64;
use valkyrie_rs::util::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

// Remplace par ton tableau réel
pub const HELLO_WRITE_X86_64: [u8; 10] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
];

fn main() {
    // Rootfs repo:        .../valkyrie-rs/rootfs/x8664_linux
    let rootfs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("rootfs")
        .join("x8664_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::BareMetal,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .feed_baremetal(&HELLO_WRITE_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP))
        .unwrap();

    Logger::info(&format!("RSP = {rsp:#x}"));
    vk.run().unwrap();
    let trap_addr = vk.exit_trap_addr.expect("exit trap not set");
    let stack_bytes = vk.mem.read(&mut vk.uc, rsp, 8).unwrap();
    let trapped = u64::from_le_bytes(stack_bytes.try_into().unwrap());

    vk.mem.show_mappings();
    Logger::info(&format!(
        "rsp = {rsp:#x} | trapped = {trap_addr:#x} | exit_trap = {trapped:#x}"
    ));

    Logger::success("Valkyrie : done");
}
