use std::path::Path;

use valkyrie_rs::VMemory;
use valkyrie_rs::arch::regs::VRegister;
use valkyrie_rs::arch::x86::RegX86;
use valkyrie_rs::logger::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

pub const SYSCALL_HELLO: [u8; 12] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
    0xCD, 0x80, // int 0x80
];

fn main() {
    let rootfs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("rootfs")
        .join("x86_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .disassemble(true)
    .entry_point(0x400000)
    .feed_baremetal(&SYSCALL_HELLO)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    let rsp = vk
        .arch
        .regs
        .get_reg(&mut vk.uc, VRegister::X86(RegX86::ESP))
        .unwrap();

    Logger::info(&format!("ESP = {rsp:#x}"));
    vk.mem.show_mappings();

    vk.run().unwrap();
    VMemory::dump_stacks(&mut vk);
    Logger::success("Valkyrie : done");
}
