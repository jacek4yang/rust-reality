# ADR 0071: Stock Xray Vision client write half-close is not signaled on the REALITY tunnel

Status: Proposed

This ADR is a proposal only. It does not authorize an implementation or
protocol change. It must not be treated as Accepted, and it must not be merged
as anything other than Proposed, without Lumi approval.

## Context

ADR 0059 requires unmodified stock Xray-core Client → rust-reality Server
ingress for VLESS + REALITY + Vision (and XUDP). rust-reality Client → stock
Xray Server is not required. PR #479 added fail-closed Exact-head Native
receipts that a stock Xray `xtls-rprx-vision` SOCKS client can carry a
length-framed 128 KiB TCP echo through rust-reality NXR and Handoff LINE +
LANDING, with a `/proc` proof that LANDING owns the origin TCP connection.
Those receipts deliberately do **not** use a client write half-close.

The residual, observed while writing #479, is: after the SOCKS client writes a
payload and `Shutdown::Write`s, a loopback origin that waits for that FIN
before echoing will receive the payload and eventually a FIN, write the reply,
and the Xray SOCKS client then sees EOF (`failed to fill whole buffer` /
`UnexpectedEof`) instead of the reply. The same sizes (16 B, 1 KiB, 128 KiB)
pass when the origin replies after `read_exact` and does **not** wait for FIN.
Rust-client `browser_profiles_*_tcp_preserve_bytes_and_half_close` tests
through NXR and Handoff still PASS.

The question is where the half-close is lost: rust-reality Vision/REALITY
relay (Direct vs NXR vs Handoff), or the stock Xray client / Vision behavior
itself. This ADR records the RCA. No product, protocol, timeout, evaluator, or
path-filter change is in scope until Lumi accepts a later implementation ADR.

Pinned stock Xray for all measurements is `tools/fixtures/stock-xray.json`:
XTLS/Xray-core v26.10.31 (`a4a3dff5b20c2faae567b742c172c7b95e75c083`), binary
SHA-256 `cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1`.
Xray-core source citations below are from that tag.

## Proven

### rust-reality already preserves write half-close for its own client

On rust-reality 2.4.1 (`origin/main` `6949dda10f150d087a9fd4be3c0d2713c1ba1ea4`),
a rust-reality SOCKS client that writes 16 bytes and `Shutdown::Write`s, with
the origin waiting for FIN before echoing, completed as follows (times from
probe start; budget 8 s):

| Path | payload | FIN | reply written | client |
| --- | --- | --- | --- | --- |
| rust client → rust Direct | 26 ms | 26 ms | 26 ms | ok |
| rust client → rust NXR | 25 ms | 25 ms | 25 ms | ok |
| rust client → rust Handoff | 25 ms | 25 ms | 25 ms | ok |

This matches the existing `browser_profiles_*_tcp` process tests. The rust
client, on local read returning 0, calls `VisionIo::shutdown`, which sends an
authenticated TLS `close_notify` and shuts down the transport writer
(`src/client/session.rs`, `src/protocol/reality/tls13/application_io.rs`).
The rust-reality server treats `TlsApplicationIoError::PeerAlert { description: 0 }`
(close_notify) as **uplink-only** end: it flushes staged Vision payload, then
`shutdown`s (CloseWrite) the origin, settles uplink `Closed`, and leaves
downlink running (`src/server/vision/relay_uplink.rs`). It does **not** map
`VisionCommand::End` (padding ends, subsequent bytes are raw) to origin FIN.

### Stock Xray client length-framed Vision TCP through rust-reality works

The same 16-byte echo with `half_close=false` (origin replies after payload,
no FIN wait) PASSed through rust Direct, NXR, and Handoff in 10–11 ms. A
stock Xray client `Shutdown::Write` **with the origin still not waiting for
FIN** also PASSed on rust Direct (10 ms): after the SOCKS write half-close,
downlink is still usable if the origin has already written the reply. This
agrees with #479's Native length-framed receipts.

### Stock Xray client does not signal inner write half-close on the tunnel

For stock Xray client → rust Direct, NXR, and Handoff, 16 B and 1 KiB, with
`Shutdown::Write` and the origin waiting for FIN, every case failed the same
way:

| Path | payload | FIN | reply written | client result | client_at |
| --- | --- | --- | --- | --- | --- |
| Xray → rust Direct, 16 B | 10 ms | 1007–1008 ms | same as FIN | failed to fill whole buffer | 1007–1008 ms |
| Xray → rust Direct, 1 KiB | 10 ms | 1009 ms | 1009 ms | failed to fill whole buffer | 1008–1009 ms |
| Xray → rust NXR, 16 B | 10 ms | 1008 ms | 1008 ms | failed to fill whole buffer | 1007 ms |
| Xray → rust Handoff, 16 B | 10 ms | 1008 ms | 1008 ms | failed to fill whole buffer | 1007 ms |

The pattern is identical on Direct, NXR, and Handoff, so the loss is not in
the NXR or Handoff carrier.

When the same Xray client config set `policy.levels.0.downlinkOnly` (and
`uplinkOnly`) to **60 seconds** against rust Direct: origin payload arrived at
10 ms, the origin's FIN read then timed out at the 8 s probe budget, and the
SOCKS client also timed out. **No origin FIN occurred at all** while the Xray
session stayed up. Therefore the ~1008 ms FIN in the default case is not a
prompt rust-reality half-close. It is a side effect of the Xray client
tearing the TLS session down after one second of downlink inactivity, which
rust-reality then observes as close_notify / transport close and only then
CloseWrites the origin — too late, because the SOCKS client already got EOF
from the same teardown.

That one-second delay matches stock Xray `SessionDefault` timeouts in
`features/policy/policy.go` (`DownlinkOnly: time.Second * 1`). VLESS outbound
`postRequest` runs `defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)`
and, after `buf.Copy` from the SOCKS pipe returns EOF, does **not** close or
half-close the Vision/REALITY writer (`proxy/vless/outbound/outbound.go`,
comment `Indicates the end of request payload` followed by an empty
`switch`). `task.Run` is `postRequest` plus `OnSuccess(getResponse,
Close(clientWriter))` — there is no `Close(serverWriter)` after uplink EOF.
Vision's only commands are padding `Continue` / `End` / `Direct`
(`proxy/proxy.go`); there is no Vision command for inner TCP FIN.
`VisionWriter` uses a one-slot `nil` MultiBuffer only to insert empty
`CommandPaddingContinue` padding that hides the VLESS header, not to signal
half-close. `SuppressOuterCloseNotify` applies only after a Direct/splice
switch, which this plaintext echo never reaches (Xray debug logs show uplink
`XtlsPadding` with command `0` / Continue only).

Xray debug on the failing rust Direct cases showed the rust-reality preamble
(`Xtls Unpadding` content 0, command Continue) and then no downlink reply
block, until the next probe started ~1 s later. With `downlinkOnly=60`, the
log likewise shows only the preamble, and the session stays up until the
probe deadline.

### Where the half-close is lost

**Proven:** the inner SOCKS write half-close is lost **inside the stock Xray
Vision client**, before rust-reality. rust-reality's Vision/REALITY relay
(Direct, NXR, and Handoff) never receives a close_notify or any other uplink
end-of-write signal, so it correctly leaves the origin write side open. The
FIN that the original #479 diagnostic saw on the origin is the **later**
Xray `DownlinkOnly` (default 1 s) session teardown, not a successful
half-close path. rust-reality is not dropping a reply that the origin had
already been allowed to write; the origin is still blocked on FIN when Xray
cancels.

## Not proven / hypothesized

- **Stock Xray client → stock Xray server** was attempted as a vendor control
  (same 16-byte half-close echo, Xray 26.10.31 on both sides, `xray x25519`
  keys, `realitySettings.target` pointing at the same OpenSSL 1.3 `s_server`
  cover style used with rust-reality). The REALITY handshake did not complete
  (`REALITY: processed invalid connection … handshake did not complete
  successfully`; client `failed to find an available destination`). That
  control is **not** a result about half-close. From the client source above
  it is *hypothesized* that a stock Xray server would also never see an
  inner-FIN signal and would behave the same once handshake is healthy. That
  remains unproven here.
- The Xray process log does not print a literal `DownlinkOnly` token. The
  1 s mechanism is inferred from the measured 1007–1009 ms teardown, the
  default `DownlinkOnly: 1s`, the `SetTimeout(DownlinkOnly)` defer, and the
  `downlinkOnly=60` experiment (no 1 s FIN, no FIN within 8 s). That chain
  is strong; a named log line was not required to trust it.
- Whether a later Xray-core revision added a Vision payload-end close after
  `a4a3dff` was not surveyed. This ADR is pinned to v26.10.31.

## Options

**Option A — Document as an interop residual; no implementation change
(recommended).** Keep the #479 length-framed Native gates. Do not treat
`assert_echo` (client FIN then read reply) as a rust-reality product defect
or a release blocker. rust↔rust half-close remains required and already
tested. Optionally add, in a later docs/test-only PR, an `#[ignore]`
expected-failure note so the residual cannot be mistaken for a regression in
the length-framed path.

**Option B — Adopt a future Xray Vision / session half-close signal.** If
upstream later defines a compatible way to mark inner write EOF while the
TLS session stays up (a new command, or a documented use of close_notify /
Direct splice CloseWrite), rust-reality may implement that under a new ADR.
Do **not** invent a unilateral Vision command or reuse `End` / `Direct` for
TCP FIN. `End` means padding has ended; treating it as origin FIN would
CloseWrite destinations when padding stops mid-session (including during an
inner TLS handshake).

**Option C — Compatibility heuristics (idle-after-upload FIN, silent uplink
as FIN, widening timeouts to paper over the 1 s cancel).** Rejected. An
idle heuristic would false-FIN live uploads and weakens direction semantics.
Raising Xray `downlinkOnly` only delays SOCKS teardown; with 60 s it still
never delivers origin FIN (`downlinkOnly=60` experiment). This must not be
"fixed" by relaxing rust-reality auth, padding validation, or Native
evaluators.

**Option D — Change rust-reality to emit or expect close_notify on some
frame Xray already sends at inner FIN.** Rejected as a current work item:
v26.10.31 does not send close_notify, Vision End, or a writer Close at that
point (proven above). There is nothing additional for the server to decode.

## Security implications

- Vision padding commands stay Continue / End / Direct with their current
  direction semantics. This proposal does not weaken UUID/auth validation,
  padding decode fail-closed behavior, or Direct-boundary authentication.
- close_notify remains the only uplink-end signal rust-reality already
  honors for origin CloseWrite. That signal is an authenticated TLS alert,
  not a substitute for Vision auth.
- Option C heuristics and any mapping of `VisionCommand::End` or
  `Direct` onto TCP FIN are rejected because they can half-close an origin
  before the client is done uploading, and they confuse padding-mode
  transitions with transport shutdown.
- No change to REALITY handshake, user validation, or splice/Direct
  readiness.

## Interop impact

- rust-reality Client ↔ rust-reality Server: write half-close remains
  working on Direct, NXR, and Handoff. No change under Option A.
- Stock Xray Client → rust-reality Server: length-framed and bidirectional
  TCP Vision (no origin wait-for-FIN) remain the ADR 0059 ingress
  requirement and already have Native receipts via #479. The wait-for-FIN
  echo pattern stays a documented residual of the stock client, not a
  rust-reality regression.
- rust-reality Client → stock Xray Server: still not required (ADR 0059).
- Operators who need "upload then FIN, then read a reply" through a stock
  Xray Vision client should not expect that pattern to work against
  rust-reality (or, hypothesized, against stock Xray server) on v26.10.31
  while padding mode is still active and Direct/splice has not started.
  Applications that finish the download without waiting for a client FIN
  (typical HTTP/1.1 request with `Content-Length`, or #479-style
  length-framed echo) are unaffected.

## Test plan (if Option A is accepted)

1. Leave Exact-head Native stock Xray NXR/Handoff TCP Vision length-framed
   steps unchanged (`stock_xray_client_*_tcp_vision_landing_is_sender`).
2. Leave rust-client `browser_profiles_*_tcp_preserve_bytes_and_half_close`
   as the half-close proof for rust-reality.
3. Do not add a default-CI or Native fail-closed assertion that the stock
   Xray wait-for-FIN echo must PASS (that would be a new, currently false,
   product claim).
4. Optional later, docs/test-only: an `#[ignore]` expected-failure (or
   explicitly documented) probe that records the 1 s `DownlinkOnly` teardown
   versus `downlinkOnly=60` producing no FIN. That probe must not change
   protocol behavior and must not be greened by skip/timeout relaxation.
5. If Option B is ever chosen, a new ADR must require a deterministic
   matrix: rust client and stock Xray client, Direct / NXR / Handoff, with
   and without origin wait-for-FIN, plus a passing vendor control once a
   healthy stock Xray server harness exists. Auth, padding, and Direct
   transitions must keep failing closed.

## Recommendation

Adopt **Option A**. The half-close is lost in the stock Xray Vision client
(proven). rust-reality's Vision/REALITY relay, including Direct vs NXR vs
Handoff, is not dropping a signaled FIN, and rust↔rust half-close already
works. No protocol or implementation change should ship until Lumi accepts a
follow-up that implements a real upstream signal (Option B).

## Decision

Pending Lumi. This document proposes Status: Proposed only. It does not
accept a product change. After approval, the ADR may be merged as Proposed
(documentation). Promoting it to Accepted, or starting Option B work, needs a
separate Lumi decision.
