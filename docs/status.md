# rust-echo-client implementation status

The alignment reference is `cpp-echo-client` at
`40372b6566f2440ddd03983c5cb100b14bd81d3c`.

| Rust module | Responsibility |
| --- | --- |
| `contract.rs`, `types.rs`, `main.rs` | CLI defaults, decimal ranges, UTF-16 token consumption/capacity, cross-field diagnostic precedence and exit classification |
| `native.rs` | Winsock/socket RAII, RIO/ConnectEx tables, registered arenas, one-shot notification state and checked native descriptors |
| `engine.rs` | One-time extension/endpoint resolution, worker shards, shared reports/deadline, IOCP stop wakeups, generation drain/join and diagnostics |
| `internal.rs` | Session state, fixed attempt deadlines, quota ledger, one send/receive pair, reconnect pacing and indexed timer heap |
| `payload.rs`, `metrics.rs` | Byte-exact patterns, terminal accounting and 64-bit batch latency histogram |

TCP batches use `RIO_MSG_WAITALL`; a short receive or failed native operation spends the
attempt as lost. Partial sends reuse the same registered window and account each successful
segment. Echo/corruption is settled only after both operations complete. A corrupted complete
batch advances the quota and the session continues. Reconnect never refunds claimed quota.
UDP attempts contain one unchanged payload with no sequence header, preserving the reference's
wire format and exact datagram-length validation.

The worker clock uses QueryPerformanceCounter with a checked, cached frequency. Session
deadlines, pacing, reconnects and cancellation grace periods retain raw tick precision;
only IOCP waits round the remaining duration up to milliseconds, matching C++. Latency
samples have the reference's one-microsecond minimum. Native
completion batches remember the first attempt failure so later send entries still retire
ownership without counting traffic or reposting a remainder after that failure.

Controlled stop applies to the whole run, including workers that already finished, and leaves
unclaimed quota out of the loss count. Fatal stop settles remaining claimed attempts as lost.
Periodic `report` lines aggregate every worker even under `/q`; the final line has the same
counter order and approximate histogram percentiles as C++.

Rust retains explicit generation tags and an ownership boundary between the scheduler and
native transport. Each worker owns one VirtualAlloc arena containing all TX and RX windows.
Send windows have independent registrations; receive windows share a separate aggregate
registration. This follows the [Windows RIOSend contract](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_riosend),
which reserves the entire send registration until completion. The complete worker arena
fits in a DWORD, and the single outstanding send slot is stored inline without a dynamic
free list. Closing sockets cancels requests but does not release their
OVERLAPPED or registered memory until completions drain. If the provider cannot safely drain
within the bounded shutdown grace period, the affected resources are retained until process
exit and the run reports an internal error. This safety behavior is deliberate.

`tests/cli_contract.rs` covers process argument diagnostics, including malformed Windows UTF-16.
`tests/transport_contract.rs` uses bounded local TCP/UDP peers to exercise corruption/continued
quota, trimmed batches, fragmented TCP writes, EOF prefixes, UDP short datagrams, global reports
and a controlled stop after another worker completed. Unit tests cover the corresponding pure
state transitions, capacity budgets and long latency values.

Build scripts refresh the official Git dependency before building and remove the generated
`Cargo.lock` on exit. Debug runs `cargo build` and `cargo test`; Release runs both with
`--release`. `format.ps1` runs `cargo fmt`. Reference-server interop is optional when
`-InteropServerPath` is supplied. No test result is implied by this source inventory;
use the current build output for verification results.
