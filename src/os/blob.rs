use crate::Valkyrie;
use crate::error::Result;
use crate::os::Os;
use crate::vtype::VState;

#[derive(Debug, Clone)]
pub struct OsBlob {
    load_address: Option<u64>,
    code_size: Option<u64>,
    skip_exit_check: bool,
}

impl OsBlob {
    pub fn new() -> Self {
        Self {
            load_address: None,
            code_size: None,
            skip_exit_check: false,
        }
    }
}

impl Os for OsBlob {
    fn set_loader_info(&mut self, load_address: u64, code_size: u64, skip_exit_check: bool) {
        self.load_address = Some(load_address);
        self.code_size = Some(code_size);
        self.skip_exit_check = skip_exit_check;
    }

    fn skip_exit_trap(&self) -> bool {
        self.skip_exit_check
    }

    fn run(&self, vk: &mut Valkyrie) -> Result<()> {
        vk.vstate = VState::Running;
        vk.uc.emu_start(
            vk.cfg.entry_point,
            vk.cfg.exit_point,
            vk.cfg.timeout,
            vk.cfg.count,
        )?;
        vk.vstate = VState::Ended;
        Ok(())
    }
}

impl Default for OsBlob {
    fn default() -> Self {
        Self::new()
    }
}
