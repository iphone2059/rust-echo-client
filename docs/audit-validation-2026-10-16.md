# Incremental active-count validation (2026-10-16)

On baseline `9c37fb8`, the scheduler now maintains the count of `active_counted` sessions at state
transitions. `publish_progress` reads it in O(1); closing and reconnecting sessions retain their
previous reporting semantics. Native ownership and shared snapshot synchronization are unchanged.

Validation ran `format.ps1`, `build_release.ps1`, `build_debug.ps1` in that order. Both modes passed
80 unit tests, 6 CLI tests and 6 transport process tests. Five new tests cover count transitions,
duplicate events, initial failures, reconnects, quota/corruption/pacing, stop/drain and snapshot publication.
The official windows-rs Git dependency was refreshed by each build (`ee70f1e7`); no Cargo.lock is retained.

Each mode additionally passed the existing shared C++ reset storm driver against the Rust executable:
budgets 0 and 32, eight sessions and four workers. Both controls echoed actual traffic, recovered from
resets, and ended with active=0 and pending=0. These are functional checks, not a comparative benchmark.

Source `src/internal.rs` SHA-256: `d3ba987f7fbdb08cc44c623b81db6d2c1be9727efc11fae54539161980245e53`.

| Product | SHA-256 |
| --- | --- |
| Release | `e4a1f6439dae1f86286881beab380f2390419bc3fb0cad1ab7c1512ce305462b` |
| Debug | `5b1d80eb80fee161aba8e353a1c6516bbb47bf020229b2ddb75cac625fc43ef1` |

Retained gate and reset logs:
`C:\Users\Administrator\echo-project\.superpowers\audit-fixes-20261016\rust-echo-client-20261016T151437636Z`.
