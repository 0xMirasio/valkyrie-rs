pub use crate::arch;
pub use crate::error::ValkyrieError;
pub use crate::hook::VCoreHooks;
pub use crate::util::Logger;
pub use crate::vstruct::VCoreStructs;
pub use crate::vtype::{Arch, Endianess, LoaderType, OsType, PAGE_SIZE, VState};

use std::path::Path;

#[derive(Debug, Clone)]
pub struct ValkyrieConfig {
    pub arch: Arch,              // arch
    pub os: OsType,              // os
    pub loader: LoaderType,      // loader
    pub rootfs: String,          // rootfspath
    pub verbose: bool,           // verbosity
    pub endianess: Endianess,    // endianess
    pub archsize: u16,           // archsize
    pub baremetal_code: Vec<u8>, // user baremetal code
    pub entry_point: u64,        // program entrypoint
    pub exit_point: u64,         // program exit_point
    pub code_ram_size: u64,      // program ram size
    pub heap_size: u64,          // program heap size
    pub count: usize,            // program instruction max count
    pub timeout: u64,            // program execution max timeout
    pub disassemble: bool,       // disassemble execution
    pub debug: bool,             // debug mode
    pub debug_port: u16,         // debug server port
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
            "guessed arch defaults: arch={arch:?}, archsize={archsize}bit, endianess={endianess:?}"
        ));

        // todo : add profile management

        let code_ram_size: u64 = (PAGE_SIZE as u64) * 1000; // 4000Kb default ram space
        let heap_size: u64 = (PAGE_SIZE as u64) * 100; // 400kb default heap size

        Ok(Self {
            arch,
            os,
            loader: LoaderType::Raw,
            rootfs,
            verbose: false,
            endianess,
            archsize,
            baremetal_code: Vec::new(),
            entry_point: 0,
            exit_point: 0,
            code_ram_size,
            heap_size,
            count: usize::MAX, // no instructions limit
            timeout: u64::MAX, // no timeout limit
            disassemble: false,
            debug: false,
            debug_port: 1234,
        })
    }

    /// Save baremetal blob in config.
    pub fn feed_baremetal(mut self, code: &[u8]) -> Result<Self, ValkyrieError> {
        if code.is_empty() {
            return Err(ValkyrieError::BadConfig("baremetal code must be non-empty"));
        }
        self.loader = LoaderType::Raw;
        self.baremetal_code.clear();
        self.baremetal_code.extend_from_slice(code);
        Ok(self)
    }

    /// TODO : ELF feed
    pub fn feed_elf(mut self, _elf_bytes: &[u8]) -> Result<Self, ValkyrieError> {
        self.loader = LoaderType::Elf;
        Err(ValkyrieError::NotImplemented("ELF loading not implemented"))
    }

    // setter ValkyrieConfig::verbose
    pub fn verbose(mut self, value: bool) -> Self {
        self.verbose = value;
        self
    }

    //setter ValkyrieConfig::disassemble
    pub fn disassemble(mut self, value: bool) -> Self {
        self.disassemble = value;
        self
    }

    // setter ValkyrieConfig::debug
    pub fn debug(mut self, value: bool) -> Self {
        self.debug = value;
        self
    }

    // setter ValkyrieConfig::debug_port
    pub fn debug_port(mut self, value: u16) -> Self {
        self.debug_port = value;
        self
    }

    // setter ValkyrieConfig::endianess
    pub fn endianess(mut self, value: Endianess) -> Self {
        self.endianess = value;
        self
    }

    // setter ValkyrieConfig::archsize
    pub fn archsize(mut self, value: u16) -> Self {
        self.archsize = value;
        self
    }

    // setter ValkyrieConfig::entry_point
    pub fn entry_point(mut self, value: u64) -> Self {
        self.entry_point = value;
        self
    }

    // setter ValkyrieConfig::exit_point
    pub fn exit_point(mut self, value: u64) -> Self {
        self.exit_point = value;
        self
    }

    // setter ValkyrieConfig::code_ram_size
    pub fn code_ram_size(mut self, value: u64) -> Self {
        self.code_ram_size = value;
        self
    }

    // setter ValkyrieConfig::heap_size
    pub fn heap_size(mut self, value: u64) -> Self {
        self.heap_size = value;
        self
    }
}
