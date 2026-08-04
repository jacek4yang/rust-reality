//! A bounded eBPF `SOCKHASH` redirect backend.
//!
//! # Correctness properties this module is built around
//!
//! * **Collision-safe flow identity.** The key is the complete bidirectional
//!   4-tuple, captured once at arm time. Keying on the listener port alone —
//!   as the recovered reference tree did — collides across every concurrent
//!   connection accepted by the same listener.
//! * **Arm-time capture.** The key is read while both sockets are connected.
//!   Reading it during teardown is unreliable: a socket that has already reset
//!   returns `ENOTCONN` from `getpeername`.
//! * **Transactional installation.** Both directions are installed together, or
//!   neither is. A partial install is rolled back completely, and an unarmed
//!   flow continues through userspace instead of being dropped.
//! * **Bounded everything.** The map has a fixed `max_entries`; armed relays are
//!   admitted against a fixed permit count that accounts for two directions per
//!   relay; every arithmetic step is checked.
//! * **Measured drain.** A FIN is not propagated until the redirected byte count
//!   has crossed a drain barrier established at arm time. `FIONREAD` and
//!   `SIOCOUTQ` are not assumed to observe the redirect backlog.

use std::{
    io, mem,
    net::SocketAddr,
    os::fd::RawFd,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    Budget, BudgetError,
    bpf::{self, Insn},
    capability::{DeclineReason, Probe, ProbeReport},
};

/// The backend name used in capability reports.
pub const BACKEND: &str = "sockhash";

/// `BPF_MAP_TYPE_SOCKHASH`.
const BPF_MAP_TYPE_SOCKHASH: u32 = 18;
/// `BPF_PROG_TYPE_SK_MSG`.
const BPF_PROG_TYPE_SK_MSG: u32 = 16;
/// `BPF_MAP_CREATE`.
const BPF_MAP_CREATE: i32 = 0;
/// `BPF_PROG_LOAD`.
const BPF_PROG_LOAD: i32 = 5;

/// A complete bidirectional flow identity captured at arm time.
///
/// Both endpoints and both ports are present, and the key is stored in a fixed
/// byte layout so the eBPF program and userspace agree exactly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowKey {
    /// Local address bytes, IPv4-mapped for v4 flows.
    pub local_address: [u8; 16],
    /// Remote address bytes, IPv4-mapped for v4 flows.
    pub remote_address: [u8; 16],
    /// Local port in host order.
    pub local_port: u16,
    /// Remote port in host order.
    pub remote_port: u16,
    /// Address family discriminator: 4 or 6.
    pub family: u8,
}

impl FlowKey {
    /// The exact serialized key size shared with the map definition.
    pub const SIZE: usize = 16 + 16 + 2 + 2 + 1 + 3;

    /// Captures a flow identity from both connected endpoints.
    #[must_use]
    pub fn capture(local: SocketAddr, remote: SocketAddr) -> Self {
        let (local_address, family) = address_bytes(local);
        let (remote_address, _) = address_bytes(remote);
        Self {
            local_address,
            remote_address,
            local_port: local.port(),
            remote_port: remote.port(),
            family,
        }
    }

    /// Returns the same flow seen from the peer's side.
    ///
    /// The verdict program looks up the reversed key, so a redirect resolves the
    /// *other* socket of the pair rather than the one that produced the message.
    #[must_use]
    pub const fn reversed(self) -> Self {
        Self {
            local_address: self.remote_address,
            remote_address: self.local_address,
            local_port: self.remote_port,
            remote_port: self.local_port,
            family: self.family,
        }
    }

    /// Serializes the key into its exact wire layout.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0_u8; Self::SIZE];
        bytes[..16].copy_from_slice(&self.local_address);
        bytes[16..32].copy_from_slice(&self.remote_address);
        bytes[32..34].copy_from_slice(&self.local_port.to_be_bytes());
        bytes[34..36].copy_from_slice(&self.remote_port.to_be_bytes());
        bytes[36] = self.family;
        bytes
    }
}

fn address_bytes(address: SocketAddr) -> ([u8; 16], u8) {
    match address {
        SocketAddr::V4(v4) => {
            let mut bytes = [0_u8; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&v4.ip().octets());
            (bytes, 4)
        }
        SocketAddr::V6(v6) => (v6.ip().octets(), 6),
    }
}

/// Bounded admission for concurrently armed relays.
///
/// Each relay occupies two map entries, one per direction, so admission is
/// accounted in directions rather than relays and every step is checked.
#[derive(Debug)]
pub struct Admission {
    used_directions: AtomicU32,
    max_directions: u32,
}

impl Admission {
    /// Creates admission state for `max_relays` concurrent relays.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Overflow`] when two directions per relay cannot be
    /// represented.
    pub fn new(max_relays: u32) -> Result<Self, BudgetError> {
        let max_directions = max_relays.checked_mul(2).ok_or(BudgetError::Overflow)?;
        if max_directions == 0 {
            return Err(BudgetError::ZeroRelays);
        }
        Ok(Self {
            used_directions: AtomicU32::new(0),
            max_directions,
        })
    }

    /// Reserves both directions of one relay, or refuses.
    ///
    /// # Errors
    ///
    /// Returns [`DeclineReason::ResourceLimit`] when the bound is reached.
    pub fn try_admit(&self) -> Result<AdmissionGuard<'_>, DeclineReason> {
        let mut current = self.used_directions.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(2).ok_or(DeclineReason::ResourceLimit)?;
            if next > self.max_directions {
                return Err(DeclineReason::ResourceLimit);
            }
            match self.used_directions.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(AdmissionGuard { admission: self }),
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns how many directions are currently reserved.
    #[must_use]
    pub fn used_directions(&self) -> u32 {
        self.used_directions.load(Ordering::Acquire)
    }

    /// Returns the configured direction bound.
    #[must_use]
    pub const fn max_directions(&self) -> u32 {
        self.max_directions
    }
}

/// A reservation released on drop, including on every error path.
#[derive(Debug)]
pub struct AdmissionGuard<'admission> {
    admission: &'admission Admission,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        let _ignored = self.admission.used_directions.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |used| Some(used.saturating_sub(2)),
        );
    }
}

/// A transactional record of what has been installed so far.
///
/// Rollback is driven by this list rather than by remembering control flow, so
/// a failure at any step undoes exactly the steps that succeeded.
#[derive(Debug, Default)]
pub struct ArmTransaction {
    installed: Vec<FlowKey>,
}

impl ArmTransaction {
    /// Creates an empty transaction.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            installed: Vec::new(),
        }
    }

    /// Records a successfully installed direction.
    pub fn record(&mut self, key: FlowKey) {
        self.installed.push(key);
    }

    /// Returns the keys installed so far, most recent last.
    #[must_use]
    pub fn installed(&self) -> &[FlowKey] {
        &self.installed
    }

    /// Consumes the transaction and returns the keys that must be removed.
    #[must_use]
    pub fn into_rollback(mut self) -> Vec<FlowKey> {
        self.installed.reverse();
        self.installed
    }

    /// Marks the transaction committed, leaving nothing to roll back.
    pub fn commit(&mut self) {
        self.installed.clear();
    }
}

/// A per-direction drain barrier measured from redirected byte counts.
///
/// A FIN must not be propagated to the peer's write side until the bytes the
/// verdict program already redirected have actually been acknowledged. The
/// barrier records the acknowledgement baseline at arm time so a counter that
/// was already nonzero before arming cannot be mistaken for progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainBarrier {
    baseline_acked: u64,
    redirected: u64,
}

impl DrainBarrier {
    /// Records the acknowledgement baseline for one direction at arm time.
    #[must_use]
    pub const fn armed(baseline_acked: u64) -> Self {
        Self {
            baseline_acked,
            redirected: 0,
        }
    }

    /// Adds redirected bytes reported by the eBPF statistics map.
    ///
    /// # Errors
    ///
    /// Returns an error rather than wrapping on overflow.
    pub fn add_redirected(&mut self, bytes: u64) -> io::Result<()> {
        self.redirected = self
            .redirected
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("redirected byte count overflow"))?;
        Ok(())
    }

    /// Returns whether every redirected byte has been acknowledged.
    ///
    /// `acked` is the peer's cumulative acknowledgement counter, read from the
    /// same source as the baseline. Wrapping is handled by comparing deltas
    /// rather than absolute values.
    #[must_use]
    pub const fn is_drained(&self, acked: u64) -> bool {
        acked.wrapping_sub(self.baseline_acked) >= self.redirected
    }

    /// Returns the redirected byte count for accounting.
    #[must_use]
    pub const fn redirected(&self) -> u64 {
        self.redirected
    }
}

/// Probes what the running kernel and policy actually permit.
///
/// Nothing here states that a particular capability set suffices. The probe
/// creates the exact map type and loads the exact program type the backend
/// needs, and reports the kernel's answer.
#[must_use]
pub fn probe(budget: Budget) -> ProbeReport {
    if !cfg!(target_os = "linux") {
        return ProbeReport::declined(BACKEND, DeclineReason::UnsupportedOperatingSystem);
    }
    if budget.validate().is_err() {
        return ProbeReport::declined(BACKEND, DeclineReason::ResourceLimit);
    }
    let map = create_sockhash(budget.max_relays.saturating_mul(2));
    let report = ProbeReport::new(BACKEND).with("map_create", Probe::from_result(&map));
    let Ok(map_fd) = map else {
        return report;
    };
    let program = bpf::stream_verdict_program(map_fd, 16);
    let loaded = load_sk_msg_program(&program);
    let report = report.with("prog_load", Probe::from_result(&loaded));
    if let Ok(fd) = loaded {
        close(fd);
    }
    close(map_fd);
    report
}

/// Creates one bounded `SOCKHASH`.
///
/// # Errors
///
/// Returns the kernel error, which the caller classifies into a fixed reason.
pub fn create_sockhash(max_entries: u32) -> io::Result<RawFd> {
    let mut attr: bpf_attr_map_create = unsafe_zeroed();
    attr.map_type = BPF_MAP_TYPE_SOCKHASH;
    attr.key_size = u32::try_from(FlowKey::SIZE)
        .map_err(|_| io::Error::other("flow key size is unrepresentable"))?;
    attr.value_size = 4;
    attr.max_entries = max_entries.max(1);
    bpf_syscall(
        BPF_MAP_CREATE,
        (&raw const attr).cast::<libc::c_void>(),
        MAP_CREATE_ABI_SIZE,
    )
}

/// Loads the stream-verdict program.
///
/// # Errors
///
/// Returns the kernel error, which the caller classifies into a fixed reason.
pub fn load_sk_msg_program(program: &[Insn]) -> io::Result<RawFd> {
    let license = c"GPL";
    let mut attr: bpf_attr_prog_load = unsafe_zeroed();
    attr.prog_type = BPF_PROG_TYPE_SK_MSG;
    attr.insn_cnt =
        u32::try_from(program.len()).map_err(|_| io::Error::other("program is too large"))?;
    attr.insns = program.as_ptr() as u64;
    attr.license = license.as_ptr() as u64;
    bpf_syscall(
        BPF_PROG_LOAD,
        (&raw const attr).cast::<libc::c_void>(),
        PROG_LOAD_ABI_SIZE,
    )
}

fn close(fd: RawFd) {
    // SAFETY: `fd` was produced by a successful `bpf(2)` call in this module and
    // is not owned by any other object.
    unsafe {
        libc::close(fd);
    }
}

fn unsafe_zeroed<T>() -> T {
    // SAFETY: every `bpf_attr` variant is a plain-old-data `#[repr(C)]` struct of
    // integers and pointers, for which an all-zero bit pattern is a valid and
    // meaningful value (the kernel treats zeroed fields as "unset").
    unsafe { mem::zeroed() }
}

fn bpf_syscall(command: i32, attr: *const libc::c_void, size: usize) -> io::Result<RawFd> {
    // SAFETY: `attr` points to a live, correctly sized `bpf_attr` variant for
    // `command`, and `size` is that variant's exact size. The kernel copies at
    // most `size` bytes and never retains the pointer.
    let result = unsafe { libc::syscall(libc::SYS_bpf, command, attr, size) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    RawFd::try_from(result).map_err(|_| io::Error::other("bpf returned an invalid descriptor"))
}

/// Byte size of the `BPF_MAP_CREATE` attribute prefix this crate declares.
///
/// `bpf(2)` takes the attribute size as an argument and applies
/// `bpf_check_uarg_tail_zero`: a caller may pass a shorter prefix of the
/// kernel's own `bpf_attr` and the kernel treats the missing tail as zero. The
/// prefix below therefore stays valid across kernel versions that append
/// fields, while the offset assertions in the tests pin the fields the backend
/// actually sets.
const MAP_CREATE_ABI_SIZE: usize = 72;

/// Byte size of the `BPF_PROG_LOAD` attribute prefix this crate declares.
const PROG_LOAD_ABI_SIZE: usize = 120;

#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_attr_map_create {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_attr_prog_load {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{
        Admission, ArmTransaction, Budget, DrainBarrier, FlowKey, MAP_CREATE_ABI_SIZE,
        PROG_LOAD_ABI_SIZE, bpf_attr_map_create, bpf_attr_prog_load, probe,
    };

    fn v4(port: u16, last: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, last), port))
    }

    fn v6(port: u16, last: u16) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last), port))
    }

    #[test]
    fn the_attribute_layouts_match_the_kernel_abi() {
        // The kernel copies exactly these many bytes; a mismatch silently
        // truncates or over-reads the attribute union.
        // Sizes are asserted against the layout the kernel documents for each
        // attribute variant; a mismatch silently truncates or over-reads the
        // attribute union.
        assert_eq!(
            core::mem::size_of::<bpf_attr_map_create>(),
            MAP_CREATE_ABI_SIZE
        );
        assert_eq!(
            core::mem::size_of::<bpf_attr_prog_load>(),
            PROG_LOAD_ABI_SIZE
        );
        assert_eq!(core::mem::align_of::<bpf_attr_map_create>(), 8);
        assert_eq!(core::mem::align_of::<bpf_attr_prog_load>(), 8);

        // The offsets are the real contract: the kernel reads each field at a
        // fixed byte position inside the attribute union.
        assert_eq!(core::mem::offset_of!(bpf_attr_map_create, map_type), 0);
        assert_eq!(core::mem::offset_of!(bpf_attr_map_create, key_size), 4);
        assert_eq!(core::mem::offset_of!(bpf_attr_map_create, value_size), 8);
        assert_eq!(core::mem::offset_of!(bpf_attr_map_create, max_entries), 12);
        assert_eq!(core::mem::offset_of!(bpf_attr_map_create, map_flags), 16);
        assert_eq!(core::mem::offset_of!(bpf_attr_map_create, map_name), 28);

        assert_eq!(core::mem::offset_of!(bpf_attr_prog_load, prog_type), 0);
        assert_eq!(core::mem::offset_of!(bpf_attr_prog_load, insn_cnt), 4);
        assert_eq!(core::mem::offset_of!(bpf_attr_prog_load, insns), 8);
        assert_eq!(core::mem::offset_of!(bpf_attr_prog_load, license), 16);
        assert_eq!(core::mem::offset_of!(bpf_attr_prog_load, log_level), 24);
    }

    #[test]
    fn concurrent_flows_from_one_listener_never_collide() {
        let listener = v4(443, 1);
        let first = FlowKey::capture(listener, v4(50_001, 2));
        let second = FlowKey::capture(listener, v4(50_002, 2));
        let third = FlowKey::capture(listener, v4(50_001, 3));

        assert_ne!(first, second, "different remote ports must differ");
        assert_ne!(first, third, "different remote addresses must differ");
        assert_ne!(first.to_bytes(), second.to_bytes());
        assert_ne!(first.to_bytes(), third.to_bytes());
    }

    #[test]
    fn ipv4_and_ipv6_flows_are_distinguishable() {
        let four = FlowKey::capture(v4(443, 1), v4(50_000, 2));
        let six = FlowKey::capture(v6(443, 1), v6(50_000, 2));

        assert_eq!(four.family, 4);
        assert_eq!(six.family, 6);
        assert_ne!(four.to_bytes(), six.to_bytes());
    }

    #[test]
    fn reversing_a_flow_key_swaps_both_endpoints() {
        let key = FlowKey::capture(v4(443, 1), v4(50_000, 2));
        let reversed = key.reversed();

        assert_eq!(reversed.local_address, key.remote_address);
        assert_eq!(reversed.remote_address, key.local_address);
        assert_eq!(reversed.local_port, key.remote_port);
        assert_eq!(reversed.remote_port, key.local_port);
        assert_eq!(reversed.reversed(), key);
    }

    #[test]
    fn the_serialized_key_length_is_fixed() {
        let key = FlowKey::capture(v4(443, 1), v4(50_000, 2));
        assert_eq!(key.to_bytes().len(), FlowKey::SIZE);
        assert_eq!(FlowKey::SIZE, 40);
    }

    #[test]
    fn admission_accounts_two_directions_per_relay() {
        let admission = Admission::new(2).expect("two relays must be admissible");
        assert_eq!(admission.max_directions(), 4);

        let first = admission.try_admit().expect("first relay must be admitted");
        let second = admission
            .try_admit()
            .expect("second relay must be admitted");
        assert_eq!(admission.used_directions(), 4);
        assert!(
            admission.try_admit().is_err(),
            "a third relay must be refused at the bound"
        );

        drop(first);
        assert_eq!(admission.used_directions(), 2);
        let third = admission
            .try_admit()
            .expect("a freed slot must be reusable");
        drop(second);
        drop(third);
        assert_eq!(admission.used_directions(), 0);
    }

    #[test]
    fn a_zero_relay_bound_is_rejected() {
        assert!(Admission::new(0).is_err());
    }

    #[test]
    fn rollback_undoes_exactly_the_installed_directions() {
        let mut transaction = ArmTransaction::new();
        let first = FlowKey::capture(v4(443, 1), v4(50_000, 2));
        let second = first.reversed();
        transaction.record(first);
        assert_eq!(transaction.installed(), [first]);
        transaction.record(second);

        let rollback = transaction.into_rollback();
        assert_eq!(
            rollback,
            vec![second, first],
            "rollback must undo installations in reverse order"
        );
    }

    #[test]
    fn a_committed_transaction_rolls_nothing_back() {
        let mut transaction = ArmTransaction::new();
        transaction.record(FlowKey::capture(v4(443, 1), v4(50_000, 2)));
        transaction.commit();
        assert!(transaction.into_rollback().is_empty());
    }

    #[test]
    fn the_drain_barrier_ignores_progress_made_before_arming() {
        // The peer had already acknowledged 1000 bytes before this relay armed.
        let mut barrier = DrainBarrier::armed(1_000);
        barrier.add_redirected(500).expect("count must record");

        assert!(
            !barrier.is_drained(1_400),
            "pre-arm acknowledgements must not count as drained redirect bytes"
        );
        assert!(barrier.is_drained(1_500));
        assert_eq!(barrier.redirected(), 500);
    }

    #[test]
    fn the_drain_barrier_handles_counter_wrap() {
        let mut barrier = DrainBarrier::armed(u64::MAX - 10);
        barrier.add_redirected(20).expect("count must record");

        assert!(!barrier.is_drained(u64::MAX));
        assert!(barrier.is_drained(9_u64.wrapping_sub(0)));
    }

    #[test]
    fn redirected_counts_are_checked_rather_than_wrapping() {
        let mut barrier = DrainBarrier::armed(0);
        barrier.add_redirected(u64::MAX).expect("count must record");
        assert!(barrier.add_redirected(1).is_err());
    }

    #[test]
    fn the_probe_reports_a_fixed_reason_without_privilege() {
        let report = probe(Budget {
            max_relays: 8,
            buffer_bytes: 4096,
            max_shards: 1,
            queue_depth: 8,
        });
        assert_eq!(report.backend(), "sockhash");
        if !report.is_available() {
            assert!(
                report.overall().reason().is_some(),
                "an unavailable backend must always name a fixed reason"
            );
        }
    }
}
