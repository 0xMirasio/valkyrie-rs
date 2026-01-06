use unicorn_engine::Unicorn;

use crate::error::{Result, ValkyrieError};
use crate::vtype::Arch;

use super::{x86, x86_64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VRegister {
    X86(x86::RegX86),
    X86_64(x86_64::RegX86_64),
}

#[derive(Debug, Clone)]
pub struct VRegs {
    arch: Arch,
    pub pc: VRegister,
    pub sp: VRegister,
}

impl VRegs {
    pub fn new(arch: Arch) -> Self {
        let (pc, sp) = match arch {
            Arch::X86_64 => (
                VRegister::X86_64(x86_64::RegX86_64::RIP),
                VRegister::X86_64(x86_64::RegX86_64::RSP),
            ),
            Arch::X86 => (
                VRegister::X86(x86::RegX86::EIP),
                VRegister::X86(x86::RegX86::ESP),
            ),
        };

        Self { arch, pc, sp }
    }

    pub fn get_pc<D>(&self, uc: &mut Unicorn<'_, D>) -> Result<u64> {
        self.get_reg(uc, self.pc)
    }

    pub fn set_pc<D>(&self, uc: &mut Unicorn<'_, D>, value: u64) -> Result<()> {
        self.set_reg(uc, self.pc, value)
    }

    pub fn get_sp<D>(&self, uc: &mut Unicorn<'_, D>) -> Result<u64> {
        self.get_reg(uc, self.sp)
    }

    pub fn set_sp<D>(&self, uc: &mut Unicorn<'_, D>, value: u64) -> Result<()> {
        self.set_reg(uc, self.sp, value)
    }

    pub fn set_reg<D>(&self, uc: &mut Unicorn<'_, D>, reg: VRegister, value: u64) -> Result<()> {
        match (self.arch, reg) {
            (Arch::X86, VRegister::X86(r)) => x86::set_reg(uc, r, value),
            (Arch::X86_64, VRegister::X86_64(r)) => x86_64::set_reg(uc, r, value),
            _ => Err(ValkyrieError::NotImplemented(
                "set_reg not implemented for this arch",
            )),
        }
    }

    pub fn get_reg<D>(&self, uc: &mut Unicorn<'_, D>, reg: VRegister) -> Result<u64> {
        match (self.arch, reg) {
            (Arch::X86, VRegister::X86(r)) => x86::get_reg(uc, r),
            (Arch::X86_64, VRegister::X86_64(r)) => x86_64::get_reg(uc, r),
            _ => Err(ValkyrieError::NotImplemented(
                "get_reg not implemented for this arch",
            )),
        }
    }
}
