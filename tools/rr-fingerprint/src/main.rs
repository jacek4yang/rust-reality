//! Native browser collection and offline ClientHello evidence entrypoint.
mod capture;
mod webdriver;
mod xray;
use std::{fs::File, io::Read};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 3 && args[0] == "capture-xray" {
        return xray::collect(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
        );
    }
    if args.len() == 4 && args[0] == "compare" {
        let chrome = match args[1].to_str() {
            Some("chrome") => true,
            Some("firefox") => false,
            _ => return Err("browser profile".into()),
        };
        let read = |path: &std::ffi::OsStr| -> Result<Vec<u8>, std::io::Error> {
            let mut bytes = Vec::new();
            File::open(path)?
                .take((rr_fingerprint::MAX_CAPTURE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        };
        rr_fingerprint::compare::compare(&read(&args[2])?, &read(&args[3])?, chrome)?;
        println!("ClientHello structural comparison passed");
        return Ok(());
    }
    if args.len() == 3 && args[0] == "prepare" {
        return capture::prepare(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
        );
    }
    if args.len() == 3 && args[0] == "serve" {
        return capture::serve(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[2]),
        );
    }
    if args.len() == 4 && args[0] == "collect" {
        return webdriver::collect(
            args[1].to_str().ok_or("browser name")?,
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
        );
    }
    if args.len() != 1 {
        return Err("usage: rr-fingerprint CAPTURE.tls | prepare PRIVATE_DIR CA_DER | serve PRIVATE_DIR OUTPUT_DIR | collect chrome|firefox BINARY OUTPUT_DIR | compare chrome|firefox REFERENCE CANDIDATE | capture-xray BINARY NEW_OUTPUT_DIR".into());
    }
    let mut input = Vec::new();
    File::open(&args[0])?
        .take((rr_fingerprint::MAX_CAPTURE_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    let hello = rr_fingerprint::decode(&input)?;
    println!("{}", serde_json::to_string_pretty(&hello)?);
    Ok(())
}
