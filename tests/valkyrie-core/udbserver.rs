use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use valkyrie_rs::vtype::{Arch, OsType};
use valkyrie_rs::{VState, Valkyrie, ValkyrieConfig};

#[test]
fn test_udbserver_simple_run() {
    const SAMPLE_X86_64: [u8; 1] = [0xC3];
    let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let cfg = ValkyrieConfig::new(Arch::X86_64, OsType::BareMetal, "/".to_string())
        .unwrap()
        .entry_point(0x400000)
        .debug(true)
        .debug_port(port)
        .feed_baremetal(&SAMPLE_X86_64)
        .unwrap();

    let gdb_client = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(mut stream) => {
                    stream.write_all(b"$c#63").unwrap();
                    thread::sleep(Duration::from_millis(100));
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(err) => panic!("failed to connect to udbserver: {err}"),
            }
        }
    });

    let mut vk = Valkyrie::new(cfg).unwrap();
    vk.run().unwrap();
    gdb_client.join().unwrap();

    assert_eq!(vk.vstate, VState::Ended);
}
