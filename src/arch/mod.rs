pub mod regs;
pub mod x86; //TODO
pub mod x86_64;

use crate::vtype::{Arch, Endianess};
use unicorn_engine::unicorn_const::{Arch as UcArch, Mode as UcMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchDefaults {
    pub endianess: Endianess,
    pub archsize: u16,
}

#[derive(Debug, Clone)]
pub struct VArch {
    pub arch: Arch,
    pub regs: regs::VRegs,
}

impl VArch {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            regs: regs::VRegs::new(arch),
        }
    }
}

pub fn defaults_for_arch(arch: Arch) -> (Endianess, u16) {
    match arch {
        Arch::X86 => (Endianess::LittleEndian, 32),
        Arch::X86_64 => (Endianess::LittleEndian, 64),
    }
}

pub fn get_unicorn_arch(arch: Arch) -> (UcArch, UcMode) {
    match arch {
        Arch::X86_64 => (UcArch::X86, UcMode::MODE_64),
        Arch::X86 => (UcArch::X86, UcMode::MODE_32),
    }
}
