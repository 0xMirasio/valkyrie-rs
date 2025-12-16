#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Mode {
    Real16,
    Protected32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct X86RunOptions {
    pub begin: Option<u64>,
    pub end: Option<u64>,
    pub instruction_count: Option<u64>,
}
