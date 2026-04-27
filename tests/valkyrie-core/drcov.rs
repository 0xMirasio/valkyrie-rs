use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{DRCOV, Valkyrie, ValkyrieConfig};

fn linux_rootfs(arch: Arch) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rootfs");
    match arch {
        Arch::X86 => root.join("x86_linux"),
        Arch::X86_64 => root.join("x8664_linux"),
    }
}

fn common_binary(arch: Arch) -> PathBuf {
    let name = match arch {
        Arch::X86 => "loader_common_linux_32_static",
        Arch::X86_64 => "loader_common_linux_64_static",
    };

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join(name)
}

fn unique_trace_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("valkyrie-trace-{nanos}.drcov"))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn basic_drcov_trace_generation_x86_64_static() {
    let arch = Arch::X86_64;
    let rootfs_path = linux_rootfs(arch);
    let elf_path = common_binary(arch);
    let trace_path = unique_trace_path();
    let _ = std::fs::remove_file(&trace_path);

    let cfg = ValkyrieConfig::new(
        arch,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .save_trace(DRCOV)
    .save_trace_path(&trace_path)
    .unwrap()
    .feed_elf(&elf_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();

    let trace = std::fs::read(&trace_path).unwrap();
    assert!(trace.starts_with(b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n"));

    let bb_pos = find_subsequence(&trace, b"BB Table: ").unwrap();
    let text_prefix = std::str::from_utf8(&trace[..bb_pos]).unwrap();
    let module_count = text_prefix
        .lines()
        .find_map(|line| line.strip_prefix("Module Table: version 2, count "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(module_count > 0);
    assert!(text_prefix.contains(elf_path.to_string_lossy().as_ref()));

    let bb_line_end = trace[bb_pos..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|offset| bb_pos + offset)
        .unwrap();
    let bb_line = std::str::from_utf8(&trace[bb_pos..bb_line_end]).unwrap();
    let bb_count = bb_line
        .strip_prefix("BB Table: ")
        .and_then(|line| line.strip_suffix(" bbs"))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(bb_count > 0);

    let bb_binary = &trace[bb_line_end + 1..];
    assert_eq!(bb_binary.len(), bb_count * 8);

    let _ = std::fs::remove_file(&trace_path);
}
