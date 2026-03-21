#[path = "valkyrie-core/mod.rs"]
pub mod valkyrie_core;
#[path = "valkyrie-loader/mod.rs"]
pub mod valkyrie_loader;
#[path = "valkyrie-unix-syscall/mod.rs"]
pub mod valkyrie_unix_syscall;

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

pub fn linux_rootfs_glibc(arch: Arch) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rootfs");
    match arch {
        Arch::X86 => root.join("x86_linux_glibc2.39"),
        Arch::X86_64 => root.join("x8664_linux_glibc2.39"),
    }
}
