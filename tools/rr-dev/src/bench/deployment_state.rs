//! Deployment run process lifecycle state.
//!
//! Owns [`RunPlan`], [`RunOutcome`], and [`RunState`] (port allocation and helper
//! / origin / xray-client spawn) so section modules can depend on a leaf type
//! module without pulling orchestration. Section dispatch remains in
//! [`super::deployment`].

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use crate::bench::{
    config::{self, RealityIdentity},
    evidence::RunDirectory,
    host_lock::HostLock,
    identity::Binary,
    process::Child,
    soak,
    workspace::Workspace,
};

use super::deployment_plan::Plan;
use super::deployment_util::isolated_environment;

#[derive(Debug, Clone)]
pub(crate) struct RunPlan {
    pub(crate) repo: PathBuf,
    pub(crate) rust_bin: PathBuf,
    pub(crate) xray_bin: PathBuf,
    pub(crate) out_dir: PathBuf,
    pub(crate) run_id: String,
    pub(crate) program: Plan,
    pub(crate) keep_work: bool,
}

#[derive(Debug)]
pub(crate) struct RunOutcome {
    pub(crate) summary_path: PathBuf,
    pub(crate) marker_path: PathBuf,
}

pub(crate) struct RunState<'a> {
    pub(crate) plan: &'a RunPlan,
    pub(crate) rust: Binary,
    pub(crate) xray: Binary,
    pub(crate) harness_sha256: String,
    pub(crate) run: RunDirectory,
    pub(crate) workspace: Workspace,
    pub(crate) lock: HostLock,
    pub(crate) children: Vec<Child>,
    pub(crate) next_port: u16,
    pub(crate) port_limit: u16,
}

impl RunState<'_> {
    pub(crate) fn port(&mut self) -> Result<u16, String> {
        if self.next_port >= self.port_limit {
            return Err("deployment runtime exhausted its reserved port block".to_owned());
        }
        let port = self.next_port;
        self.next_port += 1;
        Ok(port)
    }

    pub(crate) fn spawn_helper(
        &mut self,
        label: &str,
        args: &[String],
        log_name: &str,
        port: u16,
    ) -> Result<(), String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("could not identify rr-dev executable: {error}"))?;
        let mut child = Child::spawn_isolated(
            label,
            &executable,
            args,
            self.workspace.path(),
            &isolated_environment(),
            &self.workspace.join(log_name),
        )
        .map_err(|error| error.to_string())?;
        child
            .wait_for_port(port, Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        self.children.push(child);
        Ok(())
    }

    pub(crate) fn spawn_origin(
        &mut self,
        label: &str,
        directory: &Path,
        port: u16,
        tls: Option<(&Path, &Path)>,
    ) -> Result<(), String> {
        let mut args = vec![
            "bench".to_owned(),
            "origin".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--payload-dir".to_owned(),
            directory.display().to_string(),
            "--put-log".to_owned(),
            self.workspace
                .join(&format!("{label}-put.jsonl"))
                .display()
                .to_string(),
            "--label".to_owned(),
            label.to_owned(),
        ];
        if let Some((certificate, key)) = tls {
            args.extend([
                "--tls-cert".to_owned(),
                certificate.display().to_string(),
                "--tls-key".to_owned(),
                key.display().to_string(),
            ]);
        }
        self.spawn_helper(label, &args, &format!("{label}.log"), port)
    }

    pub(crate) fn spawn_xray_client(
        &mut self,
        label: &str,
        server_port: u16,
        socks_port: u16,
        public_key: &str,
        identity: &RealityIdentity,
    ) -> Result<(), String> {
        let path = self.workspace.join(&format!("{label}.json"));
        soak::write_config(
            &path,
            &config::xray_client(identity, server_port, socks_port, public_key).to_python_json(),
        )?;
        let child = soak::spawn_xray_client(
            label,
            &self.xray,
            &path,
            &self.workspace,
            &self.workspace.join(&format!("{label}.log")),
            socks_port,
        )?;
        self.children.push(child);
        Ok(())
    }
}
