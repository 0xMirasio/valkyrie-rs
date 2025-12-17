use unicorn_engine::Unicorn;

use crate::error::{Result, ValkyrieError};
use crate::vtype::Arch;

use super::x86_64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VRegister {
    X86_64(x86_64::RegX86_64),
}

#[derive(Debug, Clone)]
pub struct VRegs {
    arch: Arch,
}

impl VRegs {
    pub fn new(arch: Arch) -> Self {
        Self { arch }
    }

    pub fn set_reg<D>(&self, uc: &mut Unicorn<'_, D>, reg: VRegister, value: u64) -> Result<()> {
        match (self.arch, reg) {
            (Arch::X86_64, VRegister::X86_64(r)) => x86_64::set_reg(uc, r, value),
            _ => Err(ValkyrieError::NotImplemented(
                "set_reg not implemented for this arch",
            )),
        }
    }

    pub fn get_reg<D>(&self, uc: &mut Unicorn<'_, D>, reg: VRegister) -> Result<u64> {
        match (self.arch, reg) {
            (Arch::X86_64, VRegister::X86_64(r)) => x86_64::get_reg(uc, r),
            _ => Err(ValkyrieError::NotImplemented(
                "get_reg not implemented for this arch",
            )),
        }
    }
}
