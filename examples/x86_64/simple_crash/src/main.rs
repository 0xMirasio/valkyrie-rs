use std::path::Path;

use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86_64::RegX86_64;
use valkyrie_rs::logger::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

pub const SAMPLE_X86_64: [u8; 16] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
    0xC7, 0x00, 0x04, 0x00, 0x00, 0x00, // mov dword ptr [rax], 4 (maked crash here)
];

fn main() {
    let rootfs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
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
    .disassemble(true)
    .entry_point(0x400000)
    .feed_baremetal(&SAMPLE_X86_64)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86_64(RegX86_64::RSP))
        .unwrap();

    Logger::info(&format!("RSP = {rsp:#x}"));
    vk.mem.show_mappings();

    vk.run().unwrap();
    Logger::success("Valkyrie : done");
}
