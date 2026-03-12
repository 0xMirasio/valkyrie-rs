pub mod fileloader;
pub mod rawloader;
pub mod syscall;

use std::path::PathBuf;

use valkyrie_rs::vtype::Arch;

#[macro_export]
macro_rules! rm_file_if_exists {
    ($filepath:expr) => {{
        match std::fs::remove_file($filepath) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }};
}

pub fn linux_rootfs(arch: Arch) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rootfs");
    match arch {
        Arch::X86 => root.join("x86_linux"),
        Arch::X86_64 => root.join("x8664_linux"),
    }
}
