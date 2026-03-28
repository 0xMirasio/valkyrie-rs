pub mod blob;
pub mod elf;

use crate::Valkyrie;
use crate::error::Result;
use crate::vtype::{LoaderType, OsType};

pub trait Loader {
    fn run(&mut self, vk: &mut Valkyrie) -> Result<()>;
    fn load_address(&self) -> u64;

    fn skip_exit_check(&self, vk: &mut Valkyrie) -> bool {
        match vk.cfg.os {
            OsType::Linux => true,
            OsType::BareMetal => false,
        }
    }
}

pub fn select_loader(loader_type: LoaderType) -> Result<Box<dyn Loader>> {
    match loader_type {
        LoaderType::Raw => Ok(Box::new(blob::LoaderBlob::new())),
        LoaderType::Elf => Ok(Box::new(elf::LoaderElf::new())),
    }
}
