use std::path::Path;

use valkyrie_rs::VMemory;
use valkyrie_rs::logger::Logger;
use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{Valkyrie, ValkyrieConfig};

fn main() {
    let rootfs_path = Path::new("/");
    let io_bin_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("target.bin");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    //.disassemble(true)
    .feed_elf(io_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();

    vk.run().unwrap();
    VMemory::dump_stacks(&mut vk);

    Logger::success("Valkyrie : done");
}
