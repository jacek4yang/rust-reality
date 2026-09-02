//! The production server: one node, one role, one bound set of listeners.
//!
//! The subsystem is split by lifetime, and reading it in that order is the
//! fastest way in:
//!
//! - `resources` decides what this process may consume, once, before anything
//!   is built.
//! - `bootstrap` turns a validated configuration into every process-lifetime
//!   authority and publishes generation zero.
//! - `store` holds those authorities and the current generation; `reload`
//!   decides which edits a running process can accept at all.
//! - `snapshot` is one immutable generation — what a connection accepted right
//!   now will use for its whole life.
//! - `supervisor` binds, spawns, and supervises; `listener` is one accept
//!   loop; `connection` is one accepted connection.
//! - `monitor` holds the periodic tasks, `event` the log emitters, and `error`
//!   what can go wrong at each level.
//!
//! The cut that matters: process-lifetime state is built once and *borrowed*
//! by each generation. A reload replaces what a connection reads, never what
//! bounds it, so no number of reloads can multiply an admission ceiling while
//! old sessions still hold old permits.

mod bootstrap;
mod connection;
mod error;
mod event;
mod listener;
mod monitor;
mod reload;
mod resources;
mod snapshot;
mod store;
mod supervisor;

#[cfg(test)]
mod fixture;

pub use error::{ProductionServerError, RuntimeUpdateError};

use std::{
    future::Future,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::mpsc;

use crate::{
    config::{ValidatedConfig, load},
    runtime::{PressureGauge, machine::MachineReport},
};

use bootstrap::ListenerPlan;
use store::RuntimeStore;

/// Fully compiled production server using only REALITY-protected Vision inbounds.
///
/// New connections acquire one lock-free immutable runtime snapshot. A successful
/// reload swaps configuration, assets, routing, outbounds, users, REALITY state,
/// resource limits, and logging as one generation. Existing connections retain
/// their previous generation. Listener addresses and replay-cache policy are cold
/// settings because replacing either without a process restart can create a bind
/// outage or weaken replay retention.
pub struct ProductionServer {
    listeners: Vec<ListenerPlan>,
    runtime: Arc<RuntimeStore>,
    config_path: Option<PathBuf>,
}

impl ProductionServer {
    /// Compiles one programmatically supplied production configuration.
    ///
    /// This constructor supports deterministic tests and embedded service managers.
    /// Use [`Self::from_path`] when SIGHUP configuration reload is required.
    ///
    /// # Errors
    ///
    /// Returns a validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_config(config: ValidatedConfig) -> Result<Self, ProductionServerError> {
        Self::assemble(config, None, None)
    }

    /// Loads and compiles a production configuration while retaining its path for
    /// SIGHUP reload.
    ///
    /// # Errors
    ///
    /// Returns a load, validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ProductionServerError> {
        let path = path.as_ref().to_path_buf();
        let config = load(&path).map_err(RuntimeUpdateError::Load)?;
        Self::assemble(config, Some(path), None)
    }

    /// Compiles one already-loaded configuration against a caller-detected
    /// machine view.
    ///
    /// The serve bootstrap uses this constructor: it detects the machine
    /// before building the Tokio runtime so the runtime topology and the
    /// startup policy derivation share one detection, then hands the report
    /// over instead of letting the server detect again.
    ///
    /// # Errors
    ///
    /// Returns a validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_loaded(
        config: ValidatedConfig,
        config_path: Option<PathBuf>,
        machine: MachineReport,
    ) -> Result<Self, ProductionServerError> {
        Self::assemble(config, config_path, Some(machine))
    }

    fn assemble(
        config: ValidatedConfig,
        config_path: Option<PathBuf>,
        machine: Option<MachineReport>,
    ) -> Result<Self, ProductionServerError> {
        let (listeners, runtime) = bootstrap::build(config, machine)?;
        Ok(Self {
            listeners,
            runtime,
            config_path,
        })
    }

    /// Returns the live resource-pressure gauge.
    ///
    /// In standard resource mode the gauge never leaves `Normal`. In
    /// dedicated mode the pressure monitor publishes the combined
    /// descriptor/memory state. Supervisors and tests can observe it; the
    /// listener and admission governor already consult it on their own.
    #[must_use]
    pub fn pressure_gauge(&self) -> PressureGauge {
        self.runtime.pressure.clone()
    }

    /// Binds every configured listener before serving any connection and runs
    /// until SIGINT or SIGTERM. On Unix, SIGHUP requests one complete atomic
    /// configuration reload. Assets are also revalidated on their configured
    /// interval while the last good generation remains live on every failure.
    ///
    /// # Errors
    ///
    /// Returns a bind, accept, signal, or task-supervision error.
    pub async fn run(self) -> Result<(), ProductionServerError> {
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        #[cfg(unix)]
        let reload_task: Option<tokio::task::JoinHandle<()>> = {
            let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .map_err(ProductionServerError::Signal)?;
            Some(tokio::spawn(supervisor::forward_reload_signals(
                signal,
                reload_sender,
            )))
        };
        #[cfg(not(unix))]
        let reload_task: Option<tokio::task::JoinHandle<()>> = {
            let _sender = reload_sender;
            None
        };

        let result =
            supervisor::supervise(self, supervisor::shutdown_signal(), reload_receiver, true).await;
        if let Some(task) = reload_task {
            task.abort();
        }
        result
    }

    /// Runs until an injected shutdown future completes, without installing
    /// process signals or scheduled asset/configuration reloads. The normal
    /// low-cost process-wide route refresh remains active.
    ///
    /// # Errors
    ///
    /// Returns a bind, accept, or task-supervision error.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), ProductionServerError>
    where
        F: Future<Output = Result<(), io::Error>> + Send,
    {
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        let result = supervisor::supervise(self, shutdown, reload_receiver, false).await;
        drop(reload_sender);
        result
    }
}
