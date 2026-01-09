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
pub struct RegUpdate {
    pub reg: VRegister,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct VRegs {
    arch: Arch,
    pub pc: VRegister,
    pub sp: VRegister,
    last_reg_update: Vec<RegUpdate>,
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

        let last_reg_update: Vec<RegUpdate> = Vec::new();

        Self {
            arch,
            pc,
            sp,
            last_reg_update,
        }
    }

    pub fn take_reg_updates(&mut self) -> Vec<RegUpdate> {
        std::mem::take(&mut self.last_reg_update)
    }

    pub fn get_pc<D>(&self, uc: &mut Unicorn<'_, D>) -> Result<u64> {
        self.get_reg(uc, self.pc)
    }

    pub fn set_pc<D>(&mut self, uc: &mut Unicorn<'_, D>, value: u64) -> Result<()> {
        self.set_reg(uc, self.pc, value)
    }

    pub fn get_sp<D>(&self, uc: &mut Unicorn<'_, D>) -> Result<u64> {
        self.get_reg(uc, self.sp)
    }

    pub fn set_sp<D>(&mut self, uc: &mut Unicorn<'_, D>, value: u64) -> Result<()> {
        self.set_reg(uc, self.sp, value)
    }

    pub fn set_reg<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
        reg: VRegister,
        value: u64,
    ) -> Result<()> {
        let _ = match (self.arch, reg) {
            (Arch::X86, VRegister::X86(r)) => x86::set_reg(uc, r, value),
            (Arch::X86_64, VRegister::X86_64(r)) => x86_64::set_reg(uc, r, value),
            _ => {
                return Err(ValkyrieError::NotImplemented(
                    "set_reg not implemented for this arch",
                ));
            }
        };

        if reg != self.pc {
            self.last_reg_update.push(RegUpdate { reg, value });
        }
        Ok(())
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
