use crate::Valkyrie;
//use crate::arch::regs::VRegister;
//use crate::arch::x86::RegX86;
//use crate::arch::x86_64::RegX86_64;
use crate::error::Result;
use crate::loader::Loader;
//use crate::logger::Logger;
//use crate::vtype::{Arch, PAGE_SIZE};

//use unicorn_engine::unicorn_const::Prot;

pub struct LoaderElf {
    pub load_address: u64,
}

impl LoaderElf {
    pub fn new() -> Self {
        Self { load_address: 0 }
    }
}

impl Loader for LoaderElf {
    fn run(&mut self, _vk: &mut Valkyrie) -> Result<()> {
        Ok(())
    }

    fn load_address(&self) -> u64 {
        self.load_address
    }
}

impl Default for LoaderElf {
    fn default() -> Self {
        Self::new()
    }
}
