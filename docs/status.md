# rust-echo-client implementation status

Handover notes for the remaining work, with the windows-rs 0.100 facts that were verified
by the compiler (they are not guesses; each one cost a build cycle to establish).

## Implemented and verified

| Module | Responsibility | Tests |
|---|---|---|
| `types.rs` | protocol, exit codes, options, defaults | - |
| `contract.rs` | strict CLI parsing, checked arithmetic | 4 |
| `native.rs` | Winsock RAII, socket owner, registered socket, socket options, RIO table, ConnectEx | - |
| `endpoint.rs` | IPv4 sockaddr, local bind, ConnectEx issue, SO_UPDATE_CONNECT_CONTEXT | 2 |
| `rio.rs` | completion queue, IOCP wake-up, lazy notify, registered buffers, request queue | - |
| `clock.rs` | GetTickCount64 time and GetQueuedCompletionStatus blocking | - |
| `completion.rs` | request-context encode/decode, status classification | 3 |
| `overlapped.rs` | one-operation-in-flight discipline for OVERLAPPED | 1 |
| `arena.rs` | VirtualAlloc arena, registration, bounded RIO_BUF views | 1 |
| `timer.rs` | fixed-capacity index minimum heap | 5 |
| `session.rs` | per-session state machine | 6 |
| `scheduler.rs` | deadlines, intervals, reconnects, counters | 6 |
| `worker.rs` | drain loop, stop flag, run deadline, Transport/Clock abstractions | 4 |
| `payload.rs` | payload modes, byte-exact verification, statistics | 5 |
| `tests/cli_contract.rs` | process contract (help, usage errors, exit codes) | 4 |

## Status: complete

Every layer listed above is implemented, and verification is byte-exact against both
reference servers:

| Gate | Result |
| --- | --- |
| cargo test | 37 library tests + 1 partition test + 5 CLI process contract tests, all passing |
| build_debug.ps1 -InteropServerPath (cpp server) | 7 interop cases (TCP 5 / UDP 2, including 12 sessions over 3 workers), all passing |
| tests/interop_echo_tests.ps1 -ServerPath (swift server) | 7 interop cases, all passing |

Both protocols are covered: TCP uses ConnectEx with SO_UPDATE_CONNECT_CONTEXT, UDP sets its
peer with a synchronous connect and then reuses the RIO receive/send pair. Each worker owns
its own completion queue, IOCP and registered arena, and /threads partitions the sessions.