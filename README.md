# rust-echo-client

Windows x64 RIO echo client, the Rust port of `cpp-echo-client` (Swift port:
`swift-echo-client`). Data I/O is always RIO and completion notification is always IOCP;
there is no fallback backend.

## Status

The contract, native, completion, arena, timer, session, scheduler, worker, transport and
clock layers are implemented and verified: RIO data paths for TCP (ConnectEx) and UDP
(synchronous peer connect), one completion queue and registered arena per worker, lazy
IOCP notification, an index timer heap, reconnect and stop handling, and exit-code
classification. Verification is byte-exact against both reference servers.

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

## Build and verify

```powershell
pwsh -NoProfile -File build_debug.ps1      # cargo build + cargo test, Debug
pwsh -NoProfile -File build_release.ps1    # cargo build + cargo test, Release
```

## Dependency

`windows` 0.100.0 from the windows-rs default branch (pinned by revision in
`Cargo.lock`). That line generates its bindings at build time and names its modules after
Windows headers (`windows::Win32::winsock2`, `mswsock`, `mswsockdef`, `ws2`,
`ioapiset`, `minwinbase`, `memoryapi`, `errhandlingapi`), and its `WSAID_*` GUIDs are
not exported, so `WSAID_MULTIPLE_RIO` and `WSAID_CONNECTEX` are declared locally.
