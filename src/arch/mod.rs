pub mod x86;

use crate::vtype::{Arch, Endianess};
use unicorn_engine::unicorn_const::{Arch as UcArch, Mode as UcMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchDefaults {
    pub endianess: Endianess,
    pub archsize: u16,
}

pub fn defaults_for_arch(arch: Arch) -> (Endianess, u16) {
    match arch {
        Arch::X86 => (Endianess::LittleEndian, 32),
        Arch::X86_64 => (Endianess::LittleEndian, 64),
    }
}

pub fn unicorn_arch(arch: Arch) -> (UcArch, UcMode) {
    match arch {
        Arch::X86_64 => (UcArch::X86, UcMode::MODE_64),
        Arch::X86 => (UcArch::X86, UcMode::MODE_32),
    }
}
