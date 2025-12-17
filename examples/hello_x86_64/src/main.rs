use std::path::Path;

use valkyrie_rs::util::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

// Remplace par ton tableau réel
pub const HELLO_WRITE_X86_64: [u8; 38] = [
    0xB8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
    0xBF, 0x01, 0x00, 0x00, 0x00,             // mov edi, 1
    0x48, 0x8D, 0x35, 0x10, 0x00, 0x00, 0x00, // lea rsi, [rip+0x10]
    0xBA, 0x05, 0x00, 0x00, 0x00,             // mov edx, 5
    0x0F, 0x05,                               // syscall
    0xB8, 0x3C, 0x00, 0x00, 0x00,             // mov eax, 60
    0x31, 0xFF,                               // xor edi, edi
    0x0F, 0x05,                               // syscall
    0x68, 0x65, 0x6C, 0x6C, 0x6F,             // "hello"
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

    // selon ton API actuelle: Valkyrie::run(cfg) ou Valkyrie::new(cfg)?.run(...)
    let res = Valkyrie::run(cfg);
    if let Err(e) = res {
        Logger::error(format!("Valkyrie failed: {e}"));
    }

    Logger::success("Valkyrie : done");
}
