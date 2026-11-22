use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use overhear_testgen::scenarios::{merged, scenarios};
use overhear_testgen::{
    BCAST, TFrame, arp, eth, eth_ipv4, eth_vlan, mac, pcap_bytes, write_pcap, write_pcap_linktype,
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
    // Every UDP line, untagged, tagged and double-tagged ("[200.100]").
    let want = golden
        .lines()
        .filter(|l| l[24..].starts_with("UDP"))
        .count();
    let out = run(&["-r", pcap_arg(&data("generic.pcap")), "udp"]);
    assert_eq!(out.status.code(), Some(0));
    let text = s(&out.stdout);
    let got = text.lines().filter(|l| l[24..].starts_with("UDP")).count();
    assert_eq!(got, want, "output: {text}");
    assert!(text.contains("[200.100]"), "output: {text}");
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
fn unicast_qinq_arp_passes_the_filter() {
    let payload = arp(
        2,
        mac(1),
        "192.168.1.1".parse().expect("ip"),
        mac(2),
        "192.168.1.2".parse().expect("ip"),
    );
    let f = TFrame {
        sec: 1_795_266_131,
        usec: 0,
        data: eth_vlan(
            mac(2),
            mac(1),
            &[(0x88a8, 200), (0x8100, 100)],
            0x0806,
            &payload,
        ),
        orig_len: None,
    };
    let path = tmp("unicast_qinq_arp.pcap");
    write_pcap(&path, &[f]).expect("write");
    // The built-in filter alone, and narrowed by filter words.
    for extra in [&[][..], &["arp"][..]] {
        let mut args = vec!["-r", pcap_arg(&path)];
        args.extend_from_slice(extra);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(0), "{extra:?}");
        let text = s(&out.stdout);
        assert_eq!(text.lines().count(), 1, "{extra:?}: {text}");
        assert!(text.contains("[200.100]") && text.contains("ARP"), "{text}");
    }
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
fn hex_and_tui_conflict() {
    let out = run(&["-t", "-H", "-r", pcap_arg(&data("generic.pcap"))]);
    assert_eq!(out.status.code(), Some(1));
    assert!(s(&out.stderr).contains("-H and -t can not be combined"));
    assert!(out.stdout.is_empty());
}

#[test]
fn bad_memory_size() {
    let out = run(&["--max-memory", "3M", "-r", pcap_arg(&data("generic.pcap"))]);
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

/// The DHCP, mDNS and ARP scenarios in one capture, in time order. Written
/// once: tests run in parallel, and one must not read it while another
/// rewrites it.
fn dhcp_mdns_arp() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let path = tmp("dhcp_mdns_arp.pcap");
        write_pcap(&path, &merged(&["dhcp", "mdns", "arp"]).expect("merge")).expect("write");
        path
    })
}

/// The lines of the named golden line files in time order, as one capture
/// would show them: same-time lines keep the order the files were named in.
fn golden_merged(names: &[&str]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for n in names {
        let text = fs::read_to_string(data(&format!("{n}.line"))).expect("golden");
        lines.extend(text.lines().map(str::to_owned));
    }
    lines.sort_by(|a, b| a[..23].cmp(&b[..23]));
    lines.iter().map(|l| format!("{l}\n")).collect()
}

/// The protocol column of a line of line output.
fn tag(line: &str) -> &str {
    line[24..30].trim_end()
}

const KNOWN: &str = "(known: arp, dhcp, nd, mdns, llmnr, nbns, ssdp, lldp, cdp, stp)";

#[test]
fn proto_keeps_only_the_named_protocols() {
    let path = dhcp_mdns_arp();
    let out = run(&["-r", pcap_arg(path), "--proto", "dhcp,mdns"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    let text = s(&out.stdout);
    assert!(
        text.lines()
            .all(|l| ["DHCP", "mDNS", "WARN", "NOTE"].contains(&tag(l))),
        "output: {text}"
    );
    // Exactly the DHCP and mDNS scenarios' own output, warnings included.
    assert_eq!(text, golden_merged(&["dhcp", "mdns"]));
}

#[test]
fn proto_names_may_be_repeated_and_mixed_case() {
    let path = dhcp_mdns_arp();
    let out = run(&[
        "-r",
        pcap_arg(path),
        "--proto",
        "MDNS",
        "--proto",
        "Dhcp,mdns",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    assert_eq!(s(&out.stdout), golden_merged(&["dhcp", "mdns"]));
}

#[test]
fn proto_arp_keeps_only_arp() {
    let path = dhcp_mdns_arp();
    let golden = fs::read_to_string(data("arp.line")).expect("golden");
    let out = run(&["-r", pcap_arg(path), "--proto", "arp"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    let text = s(&out.stdout);
    assert!(
        text.lines().all(|l| tag(l) != "DHCP" && tag(l) != "mDNS"),
        "output: {text}"
    );
    // The ARP scenario's own output, its truncated ARP frame and warning included.
    assert_eq!(text, golden);
}

#[test]
fn each_proto_keeps_its_whole_scenario() {
    for (scenario, protos, others) in [
        ("dhcp", "dhcp", "arp,nd,mdns,llmnr,nbns,ssdp,lldp,cdp,stp"),
        ("mdns", "mdns", "llmnr,nbns,ssdp"),
        ("arp", "arp", "dhcp,nd"),
        ("nd", "ndp", "arp,mdns"),
        ("llmnr_nbns", "llmnr,netbios", "mdns,dhcp"),
        ("ssdp", "ssdp", "mdns,llmnr"),
        ("lldp_cdp", "lldp,cdp", "stp"),
        ("stp", "stp", "lldp,cdp"),
    ] {
        let pcap = data(&format!("{scenario}.pcap"));
        let golden = fs::read_to_string(data(&format!("{scenario}.line"))).expect("golden");
        let out = run(&["-r", pcap_arg(&pcap), "--proto", protos]);
        assert_eq!(out.status.code(), Some(0), "{scenario}: {}", s(&out.stderr));
        assert_eq!(s(&out.stdout), golden, "{scenario} --proto {protos}");
        let out = run(&["-r", pcap_arg(&pcap), "--proto", others]);
        assert_eq!(out.status.code(), Some(0), "{scenario}: {}", s(&out.stderr));
        assert_eq!(s(&out.stdout), "", "{scenario} --proto {others}");
    }
}

#[test]
fn proto_works_in_json_mode() {
    let path = dhcp_mdns_arp();
    let out = run(&["-j", "-r", pcap_arg(path), "--proto", "arp"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    let golden = fs::read_to_string(data("arp.jsonl")).expect("golden");
    assert_eq!(s(&out.stdout), golden);
}

#[test]
fn unknown_proto_exits_1_with_the_known_names() {
    let pcap = data("generic.pcap");
    for (value, msg) in [
        (
            "bogus",
            format!("overhear: unknown protocol \"bogus\" {KNOWN}\n"),
        ),
        (
            "dhcp,xyz",
            format!("overhear: unknown protocol \"xyz\" {KNOWN}\n"),
        ),
        ("", format!("overhear: empty protocol name {KNOWN}\n")),
        ("dhcp,", format!("overhear: empty protocol name {KNOWN}\n")),
    ] {
        let out = run(&["-r", pcap_arg(&pcap), "--proto", value]);
        assert_eq!(out.status.code(), Some(1), "{value:?}");
        assert_eq!(s(&out.stderr), msg, "{value:?}");
        assert!(out.stdout.is_empty(), "{value:?}");
    }
}

#[test]
fn proto_and_filter_words_both_narrow() {
    let path = dhcp_mdns_arp();
    // The words alone also let through ARP for that host.
    let words = run(&["-r", pcap_arg(path), "host", "192.168.1.1"]);
    assert_eq!(words.status.code(), Some(0), "stderr: {}", s(&words.stderr));
    assert!(
        s(&words.stdout).lines().any(|l| tag(l) == "ARP"),
        "{}",
        s(&words.stdout)
    );

    let out = run(&[
        "-r",
        pcap_arg(path),
        "--proto",
        "dhcp",
        "host",
        "192.168.1.1",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", s(&out.stderr));
    // The DHCP frames from 192.168.1.1 (its replies go to the broadcast
    // address), and the baseline they set.
    let golden = fs::read_to_string(data("dhcp.line")).expect("golden");
    let want: String = golden
        .lines()
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f[2] == "DHCP" && f[3] == "192.168.1.1")
                || l.ends_with("NOTE  expected DHCP server 192.168.1.1 (learned)")
        })
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(want.lines().count(), 8, "{want}");
    assert_eq!(s(&out.stdout), want);
}

#[test]
fn proto_is_in_the_help() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let help = s(&out.stdout);
    let line = help
        .lines()
        .find(|l| l.trim_start().starts_with("--proto <NAMES>"))
        .unwrap_or_else(|| panic!("no --proto in: {help}"));
    assert!(
        line.ends_with(
            "  Only these protocols (comma-separated): arp, dhcp, nd, mdns, llmnr, nbns, ssdp, lldp, cdp, stp"
        ),
        "{line}"
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
