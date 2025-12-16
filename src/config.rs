pub use crate::vtype::{Arch, OsType};

use std::path::Path;

#[derive(Debug, Clone)]
pub struct ValkyrieConfig {
    pub arch: Arch,
    pub os: OsType,
    pub rootfs: String,
    pub verbose: bool,
}

impl ValkyrieConfig {
    pub fn new(arch: Arch, os: OsType, rootfs: String) -> Result<Self, std::io::Error> {
        let path = Path::new(&rootfs);

        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("rootfs path does not exist: {}", rootfs),
            ));
        }

        Ok(Self {
            arch,
            os,
            rootfs,
            verbose: false,
        })
    }


    pub fn verbose(mut self, value: bool) -> Self {
        self.verbose = value;
        self
    }
}
