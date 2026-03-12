use std::fs;
use std::path::{Path, PathBuf};

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

const ENTRY_POINT: u64 = 0x400000;

fn build_x86_64_feed_file_blob(path: &str, message: &[u8]) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    assert!(
        !path_bytes.contains(&0),
        "guest path must not contain embedded NUL bytes"
    );
    assert!(
        !message.is_empty(),
        "guest message must not be empty for this test fixture"
    );

    let path_len = path_bytes.len() + 1;
    let code_len = 79_u64;
    let path_addr = ENTRY_POINT + code_len;
    let msg_addr = path_addr + path_len as u64;

    let mut blob = Vec::with_capacity(code_len as usize + path_len + message.len());

    blob.extend_from_slice(&[0xB8, 0x01, 0x01, 0x00, 0x00]);
    blob.extend_from_slice(&[0x48, 0xC7, 0xC7, 0x9C, 0xFF, 0xFF, 0xFF]);
    blob.extend_from_slice(&[0x48, 0xBE]);
    blob.extend_from_slice(&path_addr.to_le_bytes());
    blob.extend_from_slice(&[0xBA, 0x41, 0x02, 0x00, 0x00]);
    blob.extend_from_slice(&[0x41, 0xBA, 0xA4, 0x01, 0x00, 0x00]);
    blob.extend_from_slice(&[0x0F, 0x05]);
    blob.extend_from_slice(&[0x89, 0xC3]);
    blob.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&[0x89, 0xDF]);
    blob.extend_from_slice(&[0x48, 0xBE]);
    blob.extend_from_slice(&msg_addr.to_le_bytes());
    blob.extend_from_slice(&[0xBA]);
    blob.extend_from_slice(&(message.len() as u32).to_le_bytes());
    blob.extend_from_slice(&[0x0F, 0x05]);
    blob.extend_from_slice(&[0xB8, 0x03, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&[0x89, 0xDF]);
    blob.extend_from_slice(&[0x0F, 0x05]);
    blob.extend_from_slice(&[0xB8, 0x3C, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&[0x31, 0xFF]);
    blob.extend_from_slice(&[0x0F, 0x05]);
    blob.extend_from_slice(path_bytes);
    blob.push(0);
    blob.extend_from_slice(message);

    assert_eq!(blob.len(), code_len as usize + path_len + message.len());
    blob
}

fn write_blob_fixture(path: &Path, blob: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create parent directory for blob fixture");
    }

    fs::write(path, blob).expect("failed to write raw blob fixture");
}

#[test]
fn io_write_x86_64_oslinux_fileloader() {
    let rootfs_path = Path::new("/");
    let fixture_path = std::env::temp_dir().join(format!(
        "valkyrie_feed_file_{}_{}.bin",
        std::process::id(),
        std::thread::current().name().unwrap_or("fileloader")
    ));
    let output_path = PathBuf::from("/tmp/valkyrie_feed_file_output.txt");
    let output_message = b"feed-file-ok\n";
    let guest_output_path = output_path
        .to_str()
        .expect("expected UTF-8 temp path for guest output");

    let _ = fs::remove_file(&fixture_path);
    let _ = fs::remove_file(&output_path);

    let blob = build_x86_64_feed_file_blob(guest_output_path, output_message);
    write_blob_fixture(&fixture_path, &blob);

    let cfg = ValkyrieConfig::new(
        Arch::X86_64,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .code_base_addr(ENTRY_POINT)
    .entry_point(ENTRY_POINT)
    .feed_file(&fixture_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();

    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );

    let content = fs::read(&output_path).expect("failed to read file written by guest");
    assert_eq!(
        content, output_message,
        "unexpected content in {:?}: {content:?}",
        output_path
    );

    VMemory::dump_stacks(&mut vk);

    fs::remove_file(&fixture_path).expect("failed to remove raw blob fixture");
    fs::remove_file(&output_path).expect("failed to remove guest output file");
}
