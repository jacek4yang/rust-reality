//! Reproducible loopback-only captures from the pinned, unmodified stock binary.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const BINARY_SHA256: &str = "e783b9d2b46ed1ab3617c59b04dfbce38c999322d018c6e060f18d88bf6158aa";
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Private(PathBuf);
impl Drop for Private {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(super) fn collect(binary: &Path, output: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(binary)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if digest(&bytes) != BINARY_SHA256 {
        return Err("not the pinned stock Xray 26.10.29 Linux x86_64 binary".into());
    }
    let version = Command::new(binary).arg("version").output()?;
    if !version.status.success() {
        return Err("Xray version command failed".into());
    }
    let version = String::from_utf8(version.stdout)?;
    if !version.starts_with("Xray 26.10.29 ") || !version.contains("0afec66") {
        return Err("Xray version identity mismatch".into());
    }
    fs::create_dir(output)?;
    let private = Private(std::env::temp_dir().join(format!(
        "rr-xray-capture-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    )));
    fs::create_dir(&private.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private.0, fs::Permissions::from_mode(0o700))?;
    }
    let mut samples = Vec::new();
    for (profile, concrete) in [
        ("chrome", "HelloChrome_133"),
        ("firefox", "HelloFirefox_148"),
    ] {
        fs::create_dir(output.join(profile))?;
        for sample in 0..20 {
            let wire = capture_one(binary, &private.0, profile)?;
            rr_fingerprint::decode(&wire)?;
            let name = format!("{profile}/sample-{sample:02}.tls");
            fs::write(output.join(&name), &wire)?;
            samples.push(json!({"file":name,"profile":profile,"concreteProfile":concrete,"sha256":digest(&wire)}));
        }
        println!("{profile}: 20 stock Xray ClientHello records captured");
    }
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "schemaVersion":1, "xrayVersion":"v26.10.29", "xrayCommit":"0afec66085a85191e9dd2a4a6646c7c9a94688d1",
            "utlsCommit":"aa6edf4b11af82e110eea845bb2983d30138d651", "binarySha256":BINARY_SHA256,
            "binaryVersionOutput":version,
        "captureToolSha256":digest(&fs::read(std::env::current_exe()?)?),
        "captureSourceSha256":digest(include_bytes!("xray.rs")),
        "platform":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH},
        "conditions":{"address":"loopback","serverName":"browser-capture.test",
                "freshProcessPerSample":true,"authentication":"synthetic test credentials; capture endpoint closes after ClientHello; no authenticated-session claim"},
            "samples":samples
        }))?,
    )?;
    Ok(())
}

fn capture_one(binary: &Path, private: &Path, profile: &str) -> Result<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let reserve = TcpListener::bind("127.0.0.1:0")?;
    let socks = reserve.local_addr()?.port();
    drop(reserve);
    let config = json!({"log":{"loglevel":"error"},
        "inbounds":[{"listen":"127.0.0.1","port":socks,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":port,
            "users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none","flow":"xtls-rprx-vision"}]}]},
            "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
                "serverName":"browser-capture.test","fingerprint":profile,
                "publicKey":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","shortId":"0102030405060708"}}}]});
    let path = private.join("config.json");
    fs::write(&path, serde_json::to_vec(&config)?)?;
    let mut process = Process(
        Command::new(binary)
            .args(["run", "-config"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut client = loop {
        if let Ok(stream) =
            TcpStream::connect_timeout(&([127, 0, 0, 1], socks).into(), Duration::from_millis(100))
        {
            break stream;
        }
        if process.0.try_wait()?.is_some() {
            return Err("Xray exited before SOCKS startup".into());
        }
        if Instant::now() >= deadline {
            return Err("Xray SOCKS startup deadline".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    client.write_all(&[5, 1, 0])?;
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err("Xray SOCKS greeting".into());
    }
    client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])?;
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if Instant::now() >= deadline {
            return Err("Xray ClientHello deadline".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut header = [0; 5];
    socket.read_exact(&mut header)?;
    if header[..3] != [22, 3, 1] {
        return Err("unexpected Xray TLS record framing".into());
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut wire = header.to_vec();
    wire.resize(5 + length, 0);
    socket.read_exact(&mut wire[5..])?;
    Ok(wire)
}
