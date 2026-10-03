//! Process contract tests: the binary's argument handling is observable behaviour and is
//! verified here rather than only through the parser's unit tests.

use std::process::Command;

fn client() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rust-echo-client"))
}

#[test]
fn help_exits_zero_and_lists_the_contract() {
    for switch in ["/h", "-h", "--help", "/HELP"] {
        let output = client().arg(switch).output().expect("run client");
        assert!(output.status.success(), "{switch} must succeed");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("Usage: rust-echo-client"), "{switch} must print usage");
        assert!(text.contains("/p tcp|udp"), "{switch} must document /p");
        assert!(text.contains("always RIO"), "{switch} must state the RIO contract");
    }
}

#[test]
fn the_help_switch_does_not_mask_a_malformed_command_line() {
    let output = client()
        .args(["/h", "/p", "sctp"])
        .output()
        .expect("run client");
    assert_eq!(output.status.code(), Some(1), "a bad protocol is still a usage error");
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("Invalid arguments"));
}

#[test]
fn usage_errors_exit_one_with_a_reason() {
    let cases: [&[&str]; 5] = [
        &[],
        &["127.0.0.1"],
        &["127.0.0.1", "/p", "sctp"],
        &["127.0.0.1", "/p", "tcp", "/n"],
        &["127.0.0.1", "/p", "tcp", "second-host"],
    ];
    for case in cases {
        let output = client().args(case).output().expect("run client");
        assert_eq!(output.status.code(), Some(1), "case {case:?} must exit 1");
        let text = String::from_utf8_lossy(&output.stderr);
        assert!(
            text.contains("Invalid arguments") && text.contains("Usage:"),
            "case {case:?} must explain the usage error"
        );
    }
}

#[test]
fn the_udp_path_runs_the_datagram_engine() {
    // Port 1 has no listener; the datagram path must still start the engine and report a
    // transport outcome instead of being refused as an unknown mode.
    let output = client()
        .args(["127.0.0.1", "/p", "udp", "/r", "1", "/n", "1", "/t", "1", "/c", "1"])
        .output()
        .expect("run client");
    assert!(
        matches!(output.status.code(), Some(2) | Some(3)),
        "unexpected exit code {:?}",
        output.status.code()
    );
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!text.contains("not implemented"));
}

#[test]
fn a_connection_to_a_closed_port_reports_a_transport_failure() {
    // Port 1 has no listener in a normal session, so the connect is refused; the run must
    // end with the network/echo class rather than hanging or claiming success.
    let output = client()
        .args(["127.0.0.1", "/p", "tcp", "/r", "1", "/n", "1", "/t", "1", "/c", "1"])
        .output()
        .expect("run client");
    assert!(
        matches!(output.status.code(), Some(2) | Some(3)),
        "unexpected exit code {:?}",
        output.status.code()
    );
}
