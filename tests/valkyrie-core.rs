use valkyrie_rs::Valkyrie;
use valkyrie_rs::ValkyrieConfig;
use valkyrie_rs::vtype::{Arch, OsType};

use std::path::Path;

static PROJECT_ROOT: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn integration_new() {
    let rootfs_path = Path::new(PROJECT_ROOT).join("rootfs").join("x8664_linux");

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::BareMetal,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true);

    let vk = Valkyrie::new(cfg);
    assert!(vk.is_ok());
}
