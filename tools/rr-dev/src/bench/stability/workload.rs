//! Fixed host workloads; receipts record execution and exact transferred bytes.

use super::{
    collect,
    fixture::Machines,
    guest,
    schema::{Artifact, Transfer},
    transfer,
};
use crate::process::Tool;
use std::{
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

/// One bounded batch on a selected LINE. The first concurrency-sized wave can
/// use paced uploads to keep ownership live at the fixed load checkpoints.
pub struct Batch<'a> {
    pub id: &'a str,
    pub line: &'a str,
    pub socks_port: u16,
    pub count: usize,
    pub concurrency: usize,
    pub paced_wave: bool,
    /// Absolute campaign-relative restore boundary; never admit after this time.
    pub admission_deadline_ms: Option<u64>,
}

/// Shared immutable source files and output owner for host-generated traffic.
pub struct Driver<'a> {
    pub root: &'a Path,
    pub output: PathBuf,
    pub epoch: u64,
    pub sources: [Artifact; 2],
    pub clock: (u64, Instant),
    pub max_clock_drift_ms: u64,
}

pub fn artifact(root: &Path, path: &Path) -> Result<Artifact, String> {
    Ok(Artifact {
        path: path
            .strip_prefix(root)
            .map_err(|_| "artifact outside campaign")?
            .to_str()
            .ok_or("non-UTF-8 artifact")?
            .to_owned(),
        sha256: collect::file_digest(path)?,
    })
}

pub fn save(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn admission_before(now: u64, deadline: u64) -> Result<(), String> {
    if now >= deadline {
        Err("fault workload admission reached the fixed restore boundary".to_owned())
    } else {
        Ok(())
    }
}

impl Driver<'_> {
    fn elapsed(&self) -> Result<u64, String> {
        let now = collect::unix_ms()?;
        let elapsed =
            u64::try_from(self.clock.1.elapsed().as_millis()).map_err(|_| "host clock overflow")?;
        if now.abs_diff(self.clock.0.saturating_add(elapsed)) > self.max_clock_drift_ms {
            return Err("host wall clock moved relative to monotonic execution".to_owned());
        }
        now.checked_sub(self.epoch)
            .ok_or("transfer started before the fixed epoch".to_owned())
    }

    fn fetch(
        &self,
        id: &str,
        line: &str,
        socks_port: u16,
        upload: bool,
        size: u64,
        paced: bool,
    ) -> Result<Transfer, String> {
        let source = self.sources[usize::from(size == 4)].clone();
        let destination = self.output.join(format!("{id}.bin"));
        let path = if upload {
            format!("/upload/{id}")
        } else {
            format!("/payload-{size}.bin")
        };
        let mut args = vec![
            "--disable".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--fail".to_owned(),
            "--noproxy".to_owned(),
            String::new(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{socks_port}"),
            "--connect-timeout".to_owned(),
            "10".to_owned(),
            "--max-time".to_owned(),
            "43".to_owned(),
            "--output".to_owned(),
            destination.display().to_string(),
        ];
        if upload {
            args.extend([
                "--upload-file".to_owned(),
                self.root.join(&source.path).display().to_string(),
            ]);
        }
        if paced {
            args.extend(["--limit-rate".to_owned(), "256K".to_owned()]);
        }
        args.push(format!("http://127.0.0.1:8080{path}"));
        let started = self.elapsed()?;
        let mut curl = Tool::new("curl");
        for variable in [
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            curl = curl.env(variable, "");
        }
        let outcome = curl.args(&args).timeout(Duration::from_secs(44)).probe();
        let completed = self.elapsed()?;
        let downloaded = if !upload && destination.is_file() {
            Some(artifact(self.root, &destination)?)
        } else {
            None
        };
        save(
            &self.output.join(format!("{id}-command.json")),
            &serde_json::json!({
                "argv":args,"started_ms":started,"completed_ms":completed,"source":source,"received":downloaded,
                "exit_code":outcome.as_ref().ok().and_then(|result| result.code),"stderr":outcome.as_ref().ok().map(|result| &result.stderr),
                "error":outcome.as_ref().err().map(ToString::to_string),
            }),
        )?;
        let outcome = outcome.map_err(|error| error.to_string())?;
        if !outcome.success() {
            return Err(format!(
                "{id}: curl failed; command and partial bytes retained"
            ));
        }
        let bytes = size * 1_048_576;
        let (received_bytes, received_sha256) = if upload {
            (bytes, source.sha256.clone())
        } else {
            (
                fs::metadata(&destination)
                    .map_err(|error| error.to_string())?
                    .len(),
                downloaded
                    .as_ref()
                    .ok_or("missing download")?
                    .sha256
                    .clone(),
            )
        };
        Ok(Transfer {
            id: id.to_owned(),
            line: line.to_owned(),
            direction: if upload { "upload" } else { "download" }.to_owned(),
            started_ms: started,
            completed_ms: completed,
            expected_bytes: bytes,
            received_bytes,
            expected_sha256: source.sha256.clone(),
            received_sha256,
            source,
            download: downloaded,
            upload: None,
        })
    }

    fn snapshot(&self, machines: &Machines, label: &str) -> Result<(Vec<u8>, Artifact), String> {
        machines.verify_guest("landing")?;
        let result = machines
            .ssh(
                "landing",
                &[
                    "cat",
                    &format!("{}/output/http-origin-access.jsonl", guest::ROOT),
                ],
            )?
            .run()
            .map_err(|error| error.to_string())?;
        let path = self.output.join(format!("{label}-access.jsonl"));
        fs::write(&path, result.stdout.as_bytes()).map_err(|error| error.to_string())?;
        Ok((result.stdout.into_bytes(), artifact(self.root, &path)?))
    }

    fn execute_batch(&self, batches: &[Batch<'_>]) -> Vec<Result<Transfer, String>> {
        let failed = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let mut groups = Vec::new();
            for batch in batches {
                let failed = &failed;
                groups.push(scope.spawn(move || {
                    let next = AtomicUsize::new(0);
                    std::thread::scope(|workers| {
                        let handles: Vec<_> = (0..batch.concurrency)
                            .map(|_| {
                                workers.spawn(|| {
                                    let mut results = Vec::new();
                                    loop {
                                        if failed.load(Ordering::Relaxed) {
                                            break;
                                        }
                                        let index = next.fetch_add(1, Ordering::Relaxed);
                                        if index >= batch.count {
                                            break;
                                        }
                                        if let Some(deadline) = batch.admission_deadline_ms {
                                            // Soft stop: reaching the admission boundary is
                                            // scheduled termination, not a transfer failure.
                                            // In-flight fetches still complete; coverage is
                                            // enforced offline against the fixed restore time.
                                            match self
                                                .elapsed()
                                                .and_then(|now| admission_before(now, deadline))
                                            {
                                                Ok(()) => {}
                                                Err(_) => break,
                                            }
                                        }
                                        let paced = batch.paced_wave && index < batch.concurrency;
                                        let id = format!("{}-{}-{index:03}", batch.id, batch.line);
                                        let result = self.fetch(
                                            &id,
                                            batch.line,
                                            batch.socks_port,
                                            paced,
                                            if paced { 4 } else { 1 },
                                            paced,
                                        );
                                        if result.is_err() {
                                            failed.store(true, Ordering::Relaxed);
                                        }
                                        results.push(result);
                                    }
                                    results
                                })
                            })
                            .collect();
                        handles
                            .into_iter()
                            .flat_map(|handle| {
                                handle.join().unwrap_or_else(|_| {
                                    vec![Err("workload worker panicked".to_owned())]
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                }));
            }
            groups
                .into_iter()
                .flat_map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| vec![Err("workload group panicked".to_owned())])
                })
                .collect::<Vec<_>>()
        })
    }

    /// Retain every submitted attempt; after failure, stop admitting new work.
    /// A batch never silently retries a failed transfer.
    pub fn batch(
        &self,
        machines: &Machines,
        batches: &[Batch<'_>],
    ) -> Result<Vec<Transfer>, String> {
        let label = batches.first().ok_or("empty workload batch")?.id;
        let before = self.snapshot(machines, &format!("{label}-before"))?;
        let results = self.execute_batch(batches);
        let after = self.snapshot(machines, &format!("{label}-after"));
        let mut transfers = Vec::new();
        let mut errors = Vec::new();
        if let Err(error) = &after {
            errors.push(error.clone());
        }
        for result in results {
            match result {
                Ok(mut item) => {
                    if item.direction == "upload" {
                        match &after {
                            Ok(after) => match transfer::reconstruct_upload(
                                &before.0,
                                &after.0,
                                &format!("/upload/{}", item.id),
                                before.1.clone(),
                                after.1.clone(),
                            ) {
                                Ok(receipt) => {
                                    item.received_bytes = receipt.bytes;
                                    item.received_sha256.clone_from(&receipt.sha256);
                                    item.upload = Some(receipt);
                                }
                                Err(error) => errors.push(format!("{}: {error}", item.id)),
                            },
                            Err(error) => errors.push(error.clone()),
                        }
                    }
                    if item.received_bytes != item.expected_bytes
                        || item.received_sha256 != item.expected_sha256
                    {
                        errors.push(format!("{}: corrupted payload", item.id));
                    }
                    transfers.push(item);
                }
                Err(error) => errors.push(error),
            }
        }
        save(
            &self.output.join(format!("{label}-batch.json")),
            &serde_json::json!({"transfers":transfers,"errors":errors}),
        )?;
        if errors.is_empty() {
            Ok(transfers)
        } else {
            Err(errors.join("; "))
        }
    }

    /// Fixed 1/4-MiB directional attempts. Upload and download legs of each
    /// bidirectional attempt run concurrently on the selected LINE.
    pub fn integrity(
        &self,
        machines: &Machines,
        id: &str,
        line: &str,
        socks_port: u16,
        size: u64,
        direction: &str,
    ) -> Result<Transfer, String> {
        let before = self.snapshot(machines, &format!("{id}-before"))?;
        let (upload, download) = std::thread::scope(|scope| {
            let upload = (direction != "download").then(|| {
                scope.spawn(|| {
                    self.fetch(&format!("{id}-upload"), line, socks_port, true, size, false)
                })
            });
            let download = (direction != "upload").then(|| {
                scope.spawn(|| {
                    self.fetch(
                        &format!("{id}-download"),
                        line,
                        socks_port,
                        false,
                        size,
                        false,
                    )
                })
            });
            (
                upload.map(|handle| {
                    handle
                        .join()
                        .map_err(|_| "upload worker panicked".to_owned())
                        .and_then(|result| result)
                }),
                download.map(|handle| {
                    handle
                        .join()
                        .map_err(|_| "download worker panicked".to_owned())
                        .and_then(|result| result)
                }),
            )
        });
        let after = self.snapshot(machines, &format!("{id}-after"))?;
        let upload = upload.transpose()?;
        let download = download.transpose()?;
        let mut item = download
            .clone()
            .or_else(|| upload.clone())
            .ok_or("unknown integrity direction")?;
        if let Some(upload) = upload {
            item.upload = Some(transfer::reconstruct_upload(
                &before.0,
                &after.0,
                &format!("/upload/{}", upload.id),
                before.1,
                after.1,
            )?);
            item.started_ms = item.started_ms.min(upload.started_ms);
            item.completed_ms = item.completed_ms.max(upload.completed_ms);
        }
        id.clone_into(&mut item.id);
        direction.clone_into(&mut item.direction);
        save(&self.output.join(format!("{id}-integrity.json")), &item)?;
        Ok(item)
    }

    /// Keep one exact-byte echo flow over a fault boundary and retain only the
    /// prefix actually received. Expected connection loss is recorded separately.
    pub fn prefix(
        &self,
        id: &str,
        socks_port: u16,
        stop_at: u64,
        allow_disconnect: bool,
    ) -> Result<(Transfer, Option<u64>), String> {
        let started = collect::unix_ms()?;
        let attempted = self.echo_prefix(id, socks_port, stop_at, allow_disconnect);
        let written = save(
            &self.output.join(format!("{id}-terminal.json")),
            &serde_json::json!({
                "started_unix_ms":started,"completed_unix_ms":collect::unix_ms()?,"primary_error":attempted.as_ref().err(),
            }),
        );
        match (attempted, written) {
            (Err(primary), Err(secondary)) => Err(format!(
                "{primary}; prefix evidence also failed: {secondary}"
            )),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    fn echo_prefix(
        &self,
        id: &str,
        socks_port: u16,
        stop_at: u64,
        allow_disconnect: bool,
    ) -> Result<(Transfer, Option<u64>), String> {
        let started = self.elapsed()?;
        let mut stream = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], socks_port)),
            Duration::from_secs(10),
        )
        .map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&[5, 1, 0])
            .map_err(|error| error.to_string())?;
        let mut greeting = [0; 2];
        stream
            .read_exact(&mut greeting)
            .map_err(|error| error.to_string())?;
        if greeting != [5, 0] {
            return Err("prefix SOCKS authentication rejected".to_owned());
        }
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&8081_u16.to_be_bytes());
        stream
            .write_all(&connect)
            .map_err(|error| error.to_string())?;
        let mut reply = [0; 10];
        stream
            .read_exact(&mut reply)
            .map_err(|error| error.to_string())?;
        transfer::ipv4_socks_reply(&reply)?;
        let pattern: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let mut expected = Vec::new();
        let mut received = Vec::new();
        let mut failure = None;
        while self.elapsed()? < stop_at {
            expected.extend_from_slice(&pattern);
            let result = (|| {
                stream.write_all(&pattern)?;
                let mut remaining = pattern.len();
                while remaining > 0 {
                    let mut buffer = [0; 4096];
                    let read = stream.read(&mut buffer[..remaining])?;
                    if read == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    }
                    received.extend_from_slice(&buffer[..read]);
                    remaining -= read;
                }
                Ok::<_, std::io::Error>(())
            })();
            if let Err(error) = result {
                failure = Some((self.elapsed()?, error.to_string()));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let completed = self.elapsed()?;
        let prefix = &expected[..received.len()];
        let source_path = self.output.join(format!("{id}-expected-prefix.bin"));
        let received_path = self.output.join(format!("{id}-received-prefix.bin"));
        fs::write(&source_path, prefix).map_err(|error| error.to_string())?;
        fs::write(&received_path, &received).map_err(|error| error.to_string())?;
        let source = artifact(self.root, &source_path)?;
        let download = artifact(self.root, &received_path)?;
        let item = Transfer {
            id: id.to_owned(),
            line: "line-a".to_owned(),
            direction: "download".to_owned(),
            started_ms: started,
            completed_ms: completed,
            expected_bytes: prefix.len() as u64,
            received_bytes: received.len() as u64,
            expected_sha256: source.sha256.clone(),
            received_sha256: download.sha256.clone(),
            source,
            download: Some(download),
            upload: None,
        };
        save(
            &self.output.join(format!("{id}-prefix.json")),
            &serde_json::json!({"transfer":item,"failure":failure,"sent_bytes":expected.len()}),
        )?;
        if received.is_empty() || received != prefix || (failure.is_some() && !allow_disconnect) {
            return Err(format!("{id}: echo prefix failed; raw bytes retained"));
        }
        Ok((item, failure.map(|(time, _)| time)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::workspace::Workspace;
    use std::net::TcpListener;

    #[test]
    fn echo_prefix_retains_received_bytes_and_rejects_corruption_after_disconnect() {
        for corrupt in [false, true] {
            let workspace = Workspace::create("stability-prefix").unwrap();
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let peer = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).unwrap();
                let mut connect = [0; 10];
                stream.read_exact(&mut connect).unwrap();
                assert_eq!(&connect[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                for _ in 0..2 {
                    let mut chunk = [0; 4096];
                    stream.read_exact(&mut chunk).unwrap();
                    if corrupt {
                        chunk[0] ^= 1;
                    }
                    stream.write_all(&chunk).unwrap();
                }
            });
            let now = collect::unix_ms().unwrap();
            let source = Artifact {
                path: "unused".to_owned(),
                sha256: "a".repeat(64),
            };
            let driver = Driver {
                root: workspace.path(),
                output: workspace.path().to_path_buf(),
                epoch: now - 1,
                sources: [source.clone(), source],
                clock: (now, Instant::now()),
                max_clock_drift_ms: 50,
            };
            let result = driver.prefix("prefix", port, 1000, true);
            peer.join().unwrap();
            if corrupt {
                assert!(result.is_err());
            } else {
                let (receipt, failure) = result.unwrap();
                assert_eq!(receipt.received_bytes, 8192);
                assert!(failure.is_some());
                super::super::verify_transfer_files(workspace.path(), &receipt).unwrap();
            }
            assert_eq!(
                fs::metadata(workspace.join("prefix-received-prefix.bin"))
                    .unwrap()
                    .len(),
                8192
            );
            assert!(workspace.join("prefix-terminal.json").is_file());
        }
    }

    #[test]
    fn fault_admission_stops_at_the_boundary_without_relabeling_late_work() {
        assert!(admission_before(99, 100).is_ok());
        assert!(admission_before(100, 100).is_err());
        assert!(admission_before(101, 100).is_err());
        assert!(admission_before(u64::MAX, u64::MAX).is_err());
        let workspace = Workspace::create("stability-admission").unwrap();
        let now = collect::unix_ms().unwrap();
        let source = Artifact {
            path: "unused".to_owned(),
            sha256: "a".repeat(64),
        };
        let driver = Driver {
            root: workspace.path(),
            output: workspace.path().to_path_buf(),
            epoch: now - 1,
            sources: [source.clone(), source],
            clock: (now, Instant::now()),
            max_clock_drift_ms: 50,
        };
        let results = driver.execute_batch(&[Batch {
            id: "expired",
            line: "line-a",
            socks_port: 1,
            count: 100,
            concurrency: 2,
            paced_wave: false,
            admission_deadline_ms: Some(0),
        }]);
        // Soft stop yields no forged transfers and no hard error tokens; the
        // offline evaluator still rejects missing coverage or late completions.
        assert!(results.is_empty());
        assert_eq!(fs::read_dir(workspace.path()).unwrap().count(), 0);
    }

    #[test]
    fn socks_reply_parser_rejects_wrong_versions_reserved_bytes_and_shapes() {
        let valid = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        transfer::ipv4_socks_reply(&valid).unwrap();
        for index in 0..4 {
            let mut changed = valid;
            changed[index] ^= 1;
            assert!(transfer::ipv4_socks_reply(&changed).is_err());
        }
        assert!(transfer::ipv4_socks_reply(&valid[..9]).is_err());
    }
}
