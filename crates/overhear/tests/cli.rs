use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use overhear_testgen::scenarios::scenarios;
use overhear_testgen::{
    BCAST, TFrame, eth, eth_ipv4, mac, pcap_bytes, write_pcap, write_pcap_linktype,
    write_pcapng_tsoffset,
};

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&dir).expect("tmp dir");
    dir.join(name)
}

fn cmd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_overhear"));
    c.env("TZ", "UTC");
    c
}

fn run(args: &[&str]) -> Output {
    cmd().args(args).output().expect("run overhear")
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn generic_frames() -> Vec<TFrame> {
    scenarios()
        .into_iter()
        .find(|(n, _)| *n == "generic")
        .expect("generic scenario")
        .1
}

fn pcap_arg(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn bcast_frame(i: u32) -> TFrame {
    TFrame {
        sec: 1_795_266_131,
        usec: i % 1_000_000,
        data: eth(BCAST, mac(1), 0x88b5, &[1; 20]),
        orig_len: None,
    }
}

#[test]
fn file_output_matches_golden() {
    let golden = fs::read_to_string(data("generic.line")).expect("golden");
    let out = run(&["-r", pcap_arg(&data("generic.pcap"))]);
    assert_eq!(s(&out.stdout), golden);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        s(&out.stderr).starts_with("overhear: 10 packets"),
        "stderr: {}",
        s(&out.stderr)
    );
}

#[test]
fn filter_expression_narrows() {
    let golden = fs::read_to_string(data("generic.line")).expect("golden");
    // libpcap's `vlan` sees only the outer 802.1Q tag, so the double-tagged
    // frame ("[200.100]") does not match.
    let want = golden
        .lines()
        .filter(|l| l[24..].starts_with("UDP") && !l.contains("[200.100]"))
        .count();
    let out = run(&["-r", pcap_arg(&data("generic.pcap")), "udp"]);
    assert_eq!(out.status.code(), Some(0));
    let text = s(&out.stdout);
    let got = text.lines().filter(|l| l[24..].starts_with("UDP")).count();
    assert_eq!(got, want, "output: {text}");
    assert!(
        text.lines()
            .all(|l| l[24..].starts_with("UDP") || l[24..].starts_with("IPv4")),
        "output: {text}"
    );
}

#[test]
fn unicast_tcp_is_filtered_by_default() {
    // IPv4 header, protocol 6, no payload worth decoding.
    let mut ip = vec![
        0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    ip.extend_from_slice(&[0; 20]);
    let f = TFrame {
        sec: 1_795_266_131,
        usec: 0,
        data: eth_ipv4(mac(2), mac(1), &ip),
        orig_len: None,
    };
    let path = tmp("unicast_tcp.pcap");
    write_pcap(&path, &[f]).expect("write");
    let out = run(&["-r", pcap_arg(&path)]);
    assert_eq!(out.stdout, b"");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn rejects_non_ethernet_capture() {
    let path = tmp("raw_ip.pcap");
    write_pcap_linktype(&path, 101, &[bcast_frame(0)]).expect("write");
    let out = run(&["-r", pcap_arg(&path)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(s(&out.stderr).contains("unsupported link type 101"));
}

#[test]
fn json_and_tui_conflict() {
    let out = run(&["-j", "-t"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(s(&out.stderr).contains("-j and -t can not be combined"));
}

#[test]
fn bad_memory_size() {
    let out = run(&["--max-memory", "10K", "-r", pcap_arg(&data("generic.pcap"))]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bad_pin_exits_1_with_reason() {
    let pcap = data("generic.pcap");
    for (flag, value, reason) in [
        ("--dhcp-server", "bogus", "'bogus' is not an IPv4 address"),
        ("--dhcp-server", "10.0.0.1@5000", "'5000' is not a VLAN"),
        (
            "--router",
            "10.0.0.1",
            "'10.0.0.1' is not a MAC or IPv6 address",
        ),
    ] {
        let out = run(&["-r", pcap_arg(&pcap), flag, value]);
        assert_eq!(out.status.code(), Some(1), "{flag} {value}");
        assert!(
            s(&out.stderr).contains(reason),
            "{flag} {value}: {}",
            s(&out.stderr)
        );
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn pins_are_accepted() {
    let golden = fs::read_to_string(data("generic.line")).expect("golden");
    let out = run(&[
        "-r",
        pcap_arg(&data("generic.pcap")),
        "--dhcp-server",
        "10.0.0.1",
        "--dhcp-server",
        "10.0.0.2@100",
        "--router",
        "fe80::1@200.100",
        "--router",
        "02:00:5e:10:00:01",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    assert_eq!(s(&out.stdout), golden);
}

#[test]
fn broken_pipe_is_quiet() {
    let frames: Vec<TFrame> = (0..20_000).map(bcast_frame).collect();
    let path = tmp("many.pcap");
    write_pcap(&path, &frames).expect("write");
    let mut child = cmd()
        .args(["-r", pcap_arg(&path)])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).expect("read");
    assert!(!line.is_empty());
    // The reader (and the pipe's read end) is dropped here.
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(s(&out.stderr), "");
}

#[test]
fn truncated_file_exits_1_after_output() {
    let frames: Vec<TFrame> = (0..3).map(bcast_frame).collect();
    let mut bytes = pcap_bytes(&frames);
    bytes.truncate(bytes.len() - 10);
    let path = tmp("cut.pcap");
    fs::write(&path, bytes).expect("write");
    let out = run(&["-r", pcap_arg(&path)]);
    assert_eq!(s(&out.stdout).lines().count(), 2);
    assert!(s(&out.stderr).contains("truncated capture file"));
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn out_of_range_timestamp_prints_epoch() {
    let path = tmp("farfuture.pcapng");
    write_pcapng_tsoffset(&path, 1 << 62, &[bcast_frame(0)]).expect("write");
    let out = run(&["-r", pcap_arg(&path)]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    assert!(
        s(&out.stdout).starts_with('@'),
        "stdout: {}",
        s(&out.stdout)
    );
}

#[test]
fn lists_interfaces() {
    let out = run(&["-D"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        s(&out.stdout).lines().any(|l| l.starts_with("lo\t")),
        "stdout: {}",
        s(&out.stdout)
    );
}

#[test]
fn stdin_dash_reads_pcap() {
    let golden = fs::read_to_string(data("generic.line")).expect("golden");
    let mut child = cmd()
        .args(["-r", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin
        .write_all(&pcap_bytes(&generic_frames()))
        .expect("feed");
    drop(stdin);
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(s(&out.stdout), golden);
}
