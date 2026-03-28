use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VMemory, Valkyrie, ValkyrieConfig};

static NETWORK_TEST_GUARD: Mutex<()> = Mutex::new(());

fn reset_network_guest_paths(rootfs_path: &Path) {
    let tmp_dir = rootfs_path.join("tmp");
    fs::create_dir_all(&tmp_dir).expect("failed to create rootfs /tmp before test");

    for file_name in ["valkyrie_missing.sock", "valkyrie_network_tcp"] {
        let path = tmp_dir.join(file_name);
        crate::rm_file_if_exists!(&path)
            .unwrap_or_else(|e| panic!("failed to remove {path:?} before test: {e}"));
    }
}

fn run_network_guest(arch: Arch, enable_host_tcp: bool) -> Valkyrie {
    let rootfs_path = crate::linux_rootfs_glibc(arch);
    reset_network_guest_paths(&rootfs_path);
    if enable_host_tcp {
        fs::write(rootfs_path.join("tmp").join("valkyrie_network_tcp"), b"1")
            .expect("failed to create host tcp guest trigger");
    }

    let network_bin_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("examples_src")
        .join("build")
        .join(match arch {
            Arch::X86_64 => "network_linux_64",
            Arch::X86 => "network_linux_32",
        });

    let cfg = ValkyrieConfig::new(
        arch,
        OsType::Linux,
        rootfs_path.to_string_lossy().to_string(),
    )
    .unwrap()
    .verbose(true)
    .feed_elf(network_bin_path)
    .unwrap();

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();
    vk
}

fn spawn_tcp_listener() -> TcpListener {
    TcpListener::bind(("127.0.0.1", 4444)).expect("failed to bind tcp listener")
}

#[test]
fn basic_network_x86_64_feed_elf_dynamic() {
    let _guard = NETWORK_TEST_GUARD.lock().unwrap();
    let mut vk = run_network_guest(Arch::X86_64, false);
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    VMemory::dump_stacks(&mut vk);
}

#[test]
fn basic_network_x86_feed_elf_dynamic() {
    let _guard = NETWORK_TEST_GUARD.lock().unwrap();
    let mut vk = run_network_guest(Arch::X86, false);
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    VMemory::dump_stacks(&mut vk);
}

#[test]
fn host_tcp_network_x86_64_feed_elf_dynamic() {
    let _guard = NETWORK_TEST_GUARD.lock().unwrap();
    let rootfs_path = crate::linux_rootfs_glibc(Arch::X86_64);
    let listener = spawn_tcp_listener();
    let server = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("failed to set tcp listener nonblocking");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut accepted = None;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted = Some(stream);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(err) => panic!("failed to accept tcp guest: {err}"),
            }
        }
        let mut stream = accepted.expect("guest never connected to tcp listener");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("failed to set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("failed to set write timeout");

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).expect("failed to read guest payload");
        assert_eq!(&buf[..n], b"hello-from-guest\n");
        stream
            .write_all(b"ack\n")
            .expect("failed to write tcp listener response");
        thread::sleep(Duration::from_millis(100));
    });

    let mut vk = run_network_guest(Arch::X86_64, true);
    assert_eq!(
        vk.exit_status,
        Some(0),
        "guest exited with unexpected status: {:?}",
        vk.exit_status
    );
    VMemory::dump_stacks(&mut vk);
    server.join().expect("tcp listener thread panicked");
    crate::rm_file_if_exists!(rootfs_path.join("tmp").join("valkyrie_network_tcp"))
        .expect("failed to remove host tcp guest trigger");
}
