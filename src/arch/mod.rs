pub mod x86;

use crate::vtype::{Arch, Endianess};

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
