# rust-echo-client

Windows x64 MSVC RIO echo client, the Rust port of `cpp-echo-client` (Swift port:
`swift-echo-client`). Data I/O is always RIO and completion notification is always IOCP;
there is no fallback backend.

## Status

The contract, native, completion, arena, timer, session, scheduler, worker, transport and
clock layers implement RIO data paths for TCP (ConnectEx) and UDP
(synchronous peer connect), one completion queue and registered arena per worker, lazy
IOCP notification, an index timer heap, reconnect and stop handling, and exit-code
classification. The main thread aggregates periodic reports and wakes each worker's IOCP
when the shared run deadline or a console stop fires.

## Command line

```
rust-echo-client target /p tcp|udp [/r port] [/l port] [/n count] [/t seconds] [/i ms]
                 [/d text | /z bytes | /zt bytes] [/k tcp-depth] [/c sessions]
                 [/threads workers] [/w seconds] [/rc [seconds]] [/report seconds]
                 [/b bytes] [/cq capacity] [/memory bytes] [/q] [/stats]
```

Switch forms `/x`, `-x`, `--x` and `=value` are all accepted and matched ASCII
case-insensitively. Exit codes: 0 success, 1 usage error, 2 network/transport failure,
3 echo verification failure, 4 internal failure.

`/n` is the quota per session; zero means unlimited. TCP `/k` puts that many echo units in
one attempt, with one receive and one send outstanding. The final batch is trimmed to the
remaining quota. TCP receives use `RIO_MSG_WAITALL`; a short completion fails the attempt.
Both native operations must complete before an echo is settled, and the attempt has one
fixed timeout. A complete but corrupt echo spends its quota and the session continues.
UDP preserves datagram boundaries and sends the same payload on every attempt, as the C++
reference does; it adds no sequence header.

`/threads 0` uses the active processor count across Windows processor groups, capped at 64
and the session count. `/w 0` and `/report 0` disable their respective timers. `/q` suppresses
the default final line; `/stats` forces it. `/report` remains enabled under `/q`. A controlled
stop cancels unfinished claimed attempts without turning unclaimed quota into losses.

Set `CEC_DIAG_FILE` to collect one notification accounting line per worker after teardown.
Diagnostics use the same fields as the C++ client and never change the production result.

## Build and verify

```powershell
pwsh -NoProfile -File format.ps1
pwsh -NoProfile -File build_release.ps1   # cargo build --release + cargo test --release
pwsh -NoProfile -File build_debug.ps1     # cargo build + cargo test
```

Both build gates refresh the Git dependency and remove the generated `Cargo.lock` on exit.
Pass `-InteropServerPath <server.exe>` to also run the TCP/UDP byte-for-byte interop gate.

## Dependency

`windows` from the windows-rs default Git branch. The dependency tracks upstream without a
manifest revision pin or a checked-in `Cargo.lock`. That line generates its bindings at build time and names its modules after
Windows headers (`windows::Win32::winsock2`, `mswsock`, `mswsockdef`, `ws2`,
`ioapiset`, `minwinbase`, `memoryapi`, `errhandlingapi`), and its `WSAID_*` GUIDs are
not exported, so `WSAID_MULTIPLE_RIO` and `WSAID_CONNECTEX` are declared locally.
