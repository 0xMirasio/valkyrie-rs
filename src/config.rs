pub use crate::arch;
pub use crate::error::ValkyrieError;
pub use crate::util::Logger;
pub use crate::vstruct::VCoreStructs;
pub use crate::vtype::{Arch, Endianess, OsType};

use std::path::Path;

#[derive(Debug, Clone)]
pub struct ValkyrieConfig {
    pub arch: Arch,              // arch
    pub os: OsType,              // os
    pub rootfs: String,          // rootfspath
    pub verbose: bool,           // verbosity
    pub endianess: Endianess,    // endianess
    pub archsize: u16,           // archsize
    pub baremetal_code: Vec<u8>, // user baremetal code
    pub vstruct: VCoreStructs,   // VCoreStructs instance
}

// implement a new ValkyrieConfig.
impl ValkyrieConfig {
    pub fn new(arch: Arch, os: OsType, rootfs: String) -> Result<Self, ValkyrieError> {
        Logger::info("New Valkyrie instance");

        let path = Path::new(&rootfs);

        if !path.exists() {
            return Err(ValkyrieError::BadConfig("rootfs path does not exist"));
        }

        let (endianess, archsize) = arch::defaults_for_arch(arch);

        Logger::info(format!(
            "guessed arch defaults: arch={:?}, archsize={}bit, endianess={:?}",
            arch, archsize, endianess
        ));

        let vstruct = VCoreStructs::new(endianess, archsize).unwrap();

        Ok(Self {
            arch,
            os,
            rootfs,
            verbose: false,
            endianess,
            archsize,
            baremetal_code: Vec::new(),
            vstruct,
        })
    }

    /// Save baremetal blob in config.
    pub fn feed_baremetal(mut self, code: &[u8]) -> Result<Self, ValkyrieError> {
        if code.is_empty() {
            return Err(ValkyrieError::BadConfig("baremetal code must be non-empty"));
        }
        self.baremetal_code.clear();
        self.baremetal_code.extend_from_slice(code);
        Ok(self)
    }

    /// TODO : ELF feed
    pub fn feed_elf(self, _elf_bytes: &[u8]) -> Result<Self, ValkyrieError> {
        Err(ValkyrieError::NotImplemented("ELF loading not implemented"))
    }

    // setter ValkyrieConfig::verbose
    pub fn verbose(mut self, value: bool) -> Self {
        self.verbose = value;
        self
    }

    // setter ValkyrieConfig::endianess
    pub fn endianess(mut self, value: Endianess) -> Self {
        self.endianess = value;
        self
    }
}
