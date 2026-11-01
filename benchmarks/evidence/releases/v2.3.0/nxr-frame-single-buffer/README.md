# NXR UDP frame writer allocation diagnostic

The qualified baseline source is `54c204af0a1c9a8568c530b8d3ffadaded39e25c`.
Its `src/protocol/nxr_udp/` bytes match the runtime candidate `76dd5448`.
This diagnostic invokes the canonical encoder with a preallocated output;
it does not measure the complete association or network path.

The 15 matched cases cover absent, IPv4, IPv6, domain and maximum-domain
addresses with 64, 1200 and 7526 payload bytes. Each pair subtracts the
zero-iteration process startup from 10000 encoded frames. Heaptrack reports
one incremental allocation per frame without a destination and two with a
destination in every case. Backtraces attribute these to `encode_frame`.
The retained traces include startup and the initial decode/round-trip check;
those operations are identical within each pair and are not hot-path counts.

`baseline/probe-source.txt` contains the exact Rust driver, and `identity.json`
records the pinned compiler, release rlib identity and compiler invocation.
Build the library at that source with `cargo build --release --lib --all-features
--locked --message-format=json`, then compile the driver with the same compiler,
`-C opt-level=3 -C panic=abort -C debuginfo=2`, the library's `--extern`
argument and its release dependency search directory. Run each address/size
pair with arguments `0 ADDRESS SIZE` and `10000 ADDRESS SIZE` under heaptrack.
Analyze using `heaptrack_print --file TRACE --print-peaks=0
--print-allocators=1 --print-temporary=0 --disable-builtin-suppressions
--disable-embedded-suppressions`. Installed heaptrack is 1.5.0.

The compilation preflights selected the scratch directory's wrong compiler,
then its default unwind panic strategy; both failed before collection and
were corrected to the repository toolchain/release strategy. The first trace
analysis passed an integer instead of the Boolean allocator-print option;
the existing zero-iteration trace was retained and analyzed after correcting
the invocation. These are diagnostic harness errors, not product failures.

No timing, throughput, zero-allocation session, or production workload claim
follows from this encoder-only experiment. The optimization requires separate
post-change measurements, unchanged wire bytes, adversarial and integration
checks, full quality gates, and the applicable release qualification.
