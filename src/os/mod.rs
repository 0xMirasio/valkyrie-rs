pub mod blob;
pub mod linux;
pub mod register_syscall;
pub mod syscall;

use crate::error::Result;
use crate::vtype::OsType;

use crate::Valkyrie;

pub trait Os {
    fn set_loader_info(&mut self, load_address: u64, code_size: u64, skip_exit_check: bool);
    fn skip_exit_trap(&self) -> bool;
    fn run(&self, vk: &mut Valkyrie) -> Result<()>;
}

#[derive(Debug, Clone)]
pub enum VCoreOs {
    Blob(blob::OsBlob),
    Linux(linux::OsLinux),
}

impl VCoreOs {
    pub fn set_loader_info(&mut self, load_address: u64, code_size: u64, skip_exit_check: bool) {
        match self {
            VCoreOs::Blob(os) => os.set_loader_info(load_address, code_size, skip_exit_check),
            VCoreOs::Linux(os) => os.set_loader_info(load_address, code_size, skip_exit_check),
        }
    }

    pub fn skip_exit_trap(&self) -> bool {
        match self {
            VCoreOs::Blob(os) => os.skip_exit_trap(),
            VCoreOs::Linux(os) => os.skip_exit_trap(),
        }
    }

    pub fn run(&self, vk: &mut Valkyrie) -> Result<()> {
        match self {
            VCoreOs::Blob(os) => os.run(vk),
            VCoreOs::Linux(os) => os.run(vk),
        }
    }
}

pub fn select_os(ostype: OsType) -> Result<VCoreOs> {
    match ostype {
        OsType::BareMetal => Ok(VCoreOs::Blob(blob::OsBlob::new())),
        OsType::Linux => Ok(VCoreOs::Linux(linux::OsLinux::new())),
    }
}
