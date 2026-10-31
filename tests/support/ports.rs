//! Process-test ports cannot come from the driver's ephemeral source-port pool.
//! Advisory leases survive until this test process exits; never unlink a lease
//! inode while another process could still hold it. All state is test-only.

use std::{
    fs::{File, OpenOptions},
    net::{TcpListener, UdpSocket},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(super) fn free_port() -> u16 {
    static LEASES: Mutex<Vec<File>> = Mutex::new(Vec::new());
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    static EPHEMERAL: OnceLock<(u16, u16)> = OnceLock::new();
    let &(low, high) = EPHEMERAL.get_or_init(|| {
        let text = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .expect("Linux test ephemeral port range");
        let values: Vec<u16> = text
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 2);
        assert!(values[0] <= values[1]);
        (values[0], values[1])
    });
    let root = std::env::temp_dir().join("rust-reality-process-test-ports");
    std::fs::create_dir_all(&root).expect("test port lease directory");
    const COUNT: usize = 65_536 - 1024;
    for _ in 0..COUNT {
        let offset = (std::process::id() as usize + NEXT.fetch_add(1, Ordering::Relaxed)) % COUNT;
        let port = u16::try_from(1024 + offset).unwrap();
        if (low..=high).contains(&port) {
            continue;
        }
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(port.to_string()))
            .expect("test port lease file");
        match lease.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => continue,
            Err(error) => panic!("test port lease: {error}"),
        }
        // Wildcard probes also reject ports already used on another loopback
        // address. Kernel-assigned outgoing ports cannot enter this range.
        let Ok(tcp) = TcpListener::bind(("0.0.0.0", port)) else {
            continue;
        };
        let Ok(udp) = UdpSocket::bind(("0.0.0.0", port)) else {
            continue;
        };
        if let Err(error) = TcpListener::bind(("::1", port))
            && error.kind() == std::io::ErrorKind::AddrInUse
        {
            continue;
        }
        LEASES.lock().unwrap().push(lease);
        drop((tcp, udp));
        return port;
    }
    panic!("no unleased process-test port outside ephemeral range");
}
