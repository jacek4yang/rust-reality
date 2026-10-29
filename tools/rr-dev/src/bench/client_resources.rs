//! Client connection residency observations outside the setup timing window.
use std::{path::Path, time::Duration};

use super::{process::proc_starttime, profile_workload, stability::collect};

/// Retain baseline, held-connection and post-close kernel observations.
/// No memory or performance acceptance verdict is inferred from residency.
pub(super) fn capture(
    pid: u32,
    sha256: &str,
    socks_port: u16,
    origin_port: u16,
    directory: &Path,
) -> Result<(), String> {
    let start = proc_starttime(pid).ok_or("client unavailable before resource ladder")?;
    let mut held = Vec::new();
    for level in [0, 1, 8, 32, 128] {
        while held.len() < level {
            held.push(profile_workload::open_socks(socks_port, origin_port)?);
        }
        for sample in 0..3 {
            for stream in &held {
                require_open(stream)?;
            }
            retain(
                pid,
                sha256,
                &start,
                directory,
                &format!("held-{level}-{sample}"),
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    drop(held);
    // These are elapsed-time-labelled observations, not an assertion that all
    // asynchronous transport cleanup completed at the first sample.
    let closed = std::time::Instant::now();
    for millis in [0, 100, 500, 1000, 2000] {
        std::thread::sleep(Duration::from_millis(millis).saturating_sub(closed.elapsed()));
        retain(
            pid,
            sha256,
            &start,
            directory,
            &format!("closed-{millis}ms"),
        )?;
    }
    Ok(())
}

fn require_open(stream: &std::net::TcpStream) -> Result<(), String> {
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let peek = stream.peek(&mut [0]);
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    match peek {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Ok(0) => Err("held client connection closed during resource ladder".to_owned()),
        Ok(_) => Err("unexpected response on idle client resource connection".to_owned()),
        Err(error) => Err(format!("held client resource connection failed: {error}")),
    }
}

fn retain(
    pid: u32,
    sha256: &str,
    start: &str,
    directory: &Path,
    label: &str,
) -> Result<(), String> {
    let observed = collect::observe(pid, &directory.join("client.log"))?;
    let path = directory.join(format!("client-resources-{label}.json"));
    std::fs::write(
        &path,
        serde_json::to_vec(&observed).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("could not retain {}: {error}", path.display()))?;
    if !observed.errors.is_empty()
        || observed.initial_start_ticks.as_deref() != Some(start)
        || observed.final_start_ticks.as_deref() != Some(start)
        || observed.initial_executable_sha256.as_deref() != Some(sha256)
        || observed.final_executable_sha256.as_deref() != Some(sha256)
    {
        return Err(format!(
            "invalid client resource observation: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::{Shutdown, TcpListener, TcpStream},
    };

    #[test]
    fn closed_connection_cannot_count_as_held() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        require_open(&client).unwrap();
        server.shutdown(Shutdown::Both).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert!(require_open(&client).is_err());
    }
}
