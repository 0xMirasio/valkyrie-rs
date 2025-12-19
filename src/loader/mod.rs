pub mod blob;
// TODO: pub mod elf; AJOUTER SUPPORT ELF

use crate::Valkyrie;
use crate::error::Result;
use crate::vtype::OsType;

pub trait Loader {
    fn run(&mut self, vk: &mut Valkyrie) -> Result<()>;
    fn load_address(&self) -> u64;

    fn skip_exit_check(&self) -> bool {
        false
    }
}

pub fn select_loader(ostype: OsType) -> Result<Box<dyn Loader>> {
    match ostype {
        OsType::BareMetal => Ok(Box::new(blob::LoaderBlob::new())),
        //OsType::Linux => Err(ValkyrieError::NotImplemented("ELF loader not implemented")),
    }
}
