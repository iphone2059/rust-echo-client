//! Local peers exercise the observable batching and terminal accounting contract.
#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::{Command, Output};
use std::time::Duration;

fn accept(listener: &TcpListener) -> std::net::TcpStream {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let started = std::time::Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("blocking accepted socket");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "accept timed out"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn client(protocol: &str, port: u16, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rust-echo-client"))
        .args([
            "127.0.0.1",
            "/p",
            protocol,
            "/r",
            &port.to_string(),
            "/t",
            "2",
            "/threads",
            "1",
            "/q",
            "/stats",
        ])
        .args(extra)
        .output()
        .expect("run client")
}

fn final_fields(output: &Output) -> std::collections::BTreeMap<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("final "))
        .expect("final metrics");
    line.split_whitespace()
        .filter_map(|field| field.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[test]
fn corrupt_tcp_batch_continues_and_trims_the_last_batch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        for (attempt, length) in [12, 12, 6].into_iter().enumerate() {
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).expect("read batch");
            assert_eq!(bytes, b"abcdef".repeat(length / 6));
            if attempt == 0 {
                bytes[0] ^= 1;
            }
            stream.write_all(&bytes).expect("echo batch");
        }
    });
    let output = client(
        "tcp",
        port,
        &["/d", "abcdef", "/n", "5", "/k", "2", "/cq", "64"],
    );
    peer.join().expect("peer");
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let fields = final_fields(&output);
    for (key, value) in [
        ("attempted", "5"),
        ("echoed", "3"),
        ("corrupted", "2"),
        ("lost", "0"),
        ("pending", "0"),
        ("sent_bytes", "30"),
        ("received_bytes", "30"),
    ] {
        assert_eq!(fields[key], value, "{key}");
    }
}

#[test]
fn split_tcp_writes_complete_one_waitall_receive() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).expect("request");
        for byte in bytes {
            stream.write_all(&[byte]).expect("echo byte");
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let output = client("tcp", port, &["/d", "abcdef", "/n", "1"]);
    peer.join().expect("peer");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(final_fields(&output)["echoed"], "1");
}

#[test]
fn tcp_eof_with_a_prefix_spends_the_attempt_as_lost() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).expect("request");
        stream.write_all(&bytes[..3]).expect("prefix");
    });
    let output = client("tcp", port, &["/d", "abcdef", "/n", "1"]);
    peer.join().expect("peer");
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let fields = final_fields(&output);
    assert_eq!(fields["lost"], "1");
    assert_eq!(fields["echoed"], "0");
    assert_eq!(fields["received_bytes"], "0");
    assert_eq!(fields["network_errors"], "1");
}

#[test]
fn short_udp_datagram_is_corrupted_and_the_next_attempt_can_succeed() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut bytes = [0; 6];
        for attempt in 0..2 {
            let (length, address) = socket.recv_from(&mut bytes).expect("request");
            assert_eq!(length, 6);
            let echoed = if attempt == 0 {
                &bytes[..3]
            } else {
                &bytes[..]
            };
            socket.send_to(echoed, address).expect("echo datagram");
        }
    });
    let output = client("udp", port, &["/d", "abcdef", "/n", "2"]);
    peer.join().expect("peer");
    assert_eq!(output.status.code(), Some(3));
    let fields = final_fields(&output);
    assert_eq!(fields["corrupted"], "1");
    assert_eq!(fields["echoed"], "1");
    assert_eq!(fields["lost"], "0");
    assert_eq!(fields["pending"], "0");
}

#[test]
fn quiet_still_allows_global_periodic_reports() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 6];
        while stream.read_exact(&mut bytes).is_ok() {
            if stream.write_all(&bytes).is_err() {
                break;
            }
        }
    });
    let output = client(
        "tcp",
        port,
        &[
            "/d", "abcdef", "/n", "0", "/i", "25", "/w", "2", "/report", "1",
        ],
    );
    peer.join().expect("peer");
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.lines()
            .any(|line| line.starts_with("report ") && line.contains("sessions=1"))
    );
    let report = text
        .lines()
        .find(|line| line.starts_with("report "))
        .expect("periodic report");
    let echoed = report
        .split_whitespace()
        .find_map(|field| field.strip_prefix("echoed="))
        .unwrap();
    assert!(
        echoed.parse::<u64>().unwrap() > 0,
        "first report must include completed echoes"
    );
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("final "))
            .count(),
        1
    );
    assert_eq!(final_fields(&output)["lost"], "0");
}

#[test]
fn a_controlled_stop_suppresses_unclaimed_quota_when_a_peer_worker_already_finished() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut first = accept(&listener);
        let mut second = accept(&listener);
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let finished = std::thread::spawn(move || {
            for _ in 0..3 {
                let mut bytes = [0; 6];
                first.read_exact(&mut bytes).expect("request");
                first.write_all(&bytes).expect("echo");
            }
        });
        let mut request = [0; 6];
        second.read_exact(&mut request).expect("stalled request");
        let mut ignored = Vec::new();
        let _ = second.read_to_end(&mut ignored);
        finished.join().expect("finished peer");
    });
    let output = client(
        "tcp",
        port,
        &[
            "/d", "abcdef", "/n", "3", "/c", "2", "/threads", "2", "/t", "5", "/w", "1",
        ],
    );
    peer.join().expect("peer");
    assert_eq!(output.status.code(), Some(0));
    let fields = final_fields(&output);
    assert_eq!(fields["echoed"], "3");
    assert_eq!(fields["attempted"], "4");
    assert_eq!(fields["cancelled"], "1");
    assert_eq!(fields["lost"], "0");
    assert_eq!(fields["pending"], "0");
}
