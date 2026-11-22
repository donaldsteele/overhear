# overhear — design

2026-11-21 · status: draft for review

## 1. Intent

overhear is a passive listener for the traffic a machine on a LAN receives without asking for it: broadcast and multicast frames, plus the replies those protocols send. It answers two questions, live or from a capture file:

- **Who is on this LAN?** A table of devices built only from what they announce: MAC, addresses, names, vendor, services.
- **What are they saying?** Every packet decoded and shown, in the spirit of dhcpdump: readable as text, consumable as JSON.

It also warns about the few things on a LAN that usually mean trouble: a second DHCP server, an unexpected IPv6 router, two machines claiming one address, and a host answering name lookups it shouldn't.

It comes out of contributing to dhcpdump (security fixes and a JSON mode). The lessons from that work shape the constraints here. Rust removes the memory-safety bugs. It does not remove the two design problems found there: tracker memory that grew without bound from attacker traffic, and privileges kept after start. Those are designed in from day one.

## 2. Goals, non-goals, anti-goals

**Goals (v1)**

- Decode, from Ethernet captures: ARP, DHCPv4, IPv6 neighbour discovery and router adverts, mDNS, LLMNR, NetBIOS name service, SSDP, LLDP, CDP, STP/RSTP/MSTP.
- Show every other broadcast or multicast frame as a generic line (EtherType or IP protocol and ports, addresses, length), so nothing reaching the port is silently hidden.
- Three ways to see it: a one-line-per-packet log (default), JSON lines (`-j`), and a live screen with the device table and warnings (`-t`).
- Work live (`-i`) and on capture files (`-r`), with tcpdump-style filter expressions.
- Four warnings (section 5.6), useful with no configuration on a home LAN and pinnable on a managed one.
- Survive hostile traffic: no crash, no hang, bounded memory, no terminal escape injection.
- Linux first. Everything specific to one system lives in one module, so a Windows (Npcap) version can follow without restructuring.

**Non-goals (v1, possibly later; see section 9)**

- Saved history across runs. The `-j` output is the way to keep history.
- DHCPv6, IGMP/MLD group decoding, NetBIOS datagram/browser announcements, PVST+, Wake-on-LAN recognition (these show as generic lines).
- Reassembling IPv4/IPv6 fragments.
- Link types other than Ethernet: no 802.11 monitor mode, no Linux `-i any` (cooked capture).
- Windows release (designed for, shipped in the next phase).

**Anti-goals — if overhear does any of these, it has failed even if it works**

- **Sends anything.** No probes, no active scanning, no DNS or reverse lookups, no fetching SSDP `LOCATION` URLs, no update checks. It only listens. The one exception is a lookup the user explicitly asks for in the arguments: libpcap resolves host names written in a filter expression (`host gateway.lan`) through the system resolver, and the `-Z` user is looked up through NSS. overhear never starts a lookup on its own or because of anything it hears. The man page says this, and recommends numeric addresses in filters for strict silence (call).
- Crashes, hangs or slows to a halt on malformed or deliberately crafted packets.
- Uses memory that grows with attacker traffic without a hard limit.
- Writes packet bytes to the terminal in a way that can move the cursor, change colours or spoof text.
- Keeps root or capabilities after the capture is open.
- Needs configuration before it says anything useful on a home LAN.

## 3. Constraints

- Rust, edition 2024, minimum Rust 1.85: Debian 13's packaged Rust, so it builds with the distro toolchain. Development uses 1.99.
- **Targets: x86-64 and 64-bit ARM (aarch64) Linux from v1** (Don: Raspberry Pi included). Reference Pi: Raspberry Pi 4 running 64-bit Raspberry Pi OS or Debian. Pi 5 is expected to just work; Pi 3 and Zero 2 W are best effort; 32-bit ARM (armhf) is not a target (call).
- Release binaries are built against glibc 2.36 (Debian 12, and Raspberry Pi OS based on it), so one `.deb` per architecture runs on both Debian 12 and 13 based systems; a binary built on this Debian 13 machine would otherwise need glibc 2.41 and fail on most Pis in use today (call; how, e.g. a Debian 12 container or a glibc-versioned cross build, is the builder's).
- Capture through libpcap (≥ 1.10, Debian 13 has 1.10.5) via the `pcap` crate. On Windows later: Npcap, which users install themselves (the free licence forbids bundling).
- All decoding code is ours (section 4). Other dependencies kept few, maintained, and able to build for Windows (e.g. crossterm, not a Unix-only terminal library).

## 4. Approaches considered

| | approach | for | against |
|---|---|---|---|
| 1 | libpcap plus existing decoder crates (`etherparse`, `dhcproto`, `simple-dns`) and ratatui | fastest to something working | these crates fail a whole packet on one bad field, so no partial decode with a reason, which is what makes dhcpdump useful on messy networks; robustness against hostile input is whatever each crate has |
| **2** | **libpcap for capture, our own decoders for everything above it** | libpcap does what it is long tested at (live, files, filters, portability, Windows via Npcap); the decoders, where hostile bytes land and where the tool's value is, are ours: zero-copy, never panic, partial decode with reasons, fuzzed from day one | more code (decoders are most of the project); C dependency, as dhcpdump |
| 3 | pure Rust, Linux only: raw packet sockets, our decoders, a Rust capture file reader | one self-contained binary | Linux only (Windows cannot capture at layer 2 without a driver), no filter expressions, low-level socket and ring code to get right |

**Chosen: 2** (Don). It puts the effort where the tool differs and where the security risk is, and it is the only one of the three that can reach Windows. **Linux first, Windows designed in** (Don).

## 5. Design

Marking: **(Don)** decided by Don; **(agreed)** proposed in the discussion and accepted; **(call)** decided while writing this document, open to change; anything else not marked is left to the builder.

### 5.1 Command line

```
overhear [-i IFACE | -r FILE] [-j | -t] [-v] [-H] [-p] [-Z USER]
         [--dhcp-server IP[@VLAN]]... [--router MAC|IPV6[@VLAN]]... [--max-memory SIZE]
         [-D] [FILTER EXPRESSION...]
```

| flag | meaning |
|---|---|
| `-i IFACE` | listen live (default: libpcap's default interface) |
| `-r FILE` | read a pcap or pcapng file |
| `-j` | JSON lines instead of text (agreed) |
| `-t` | live screen (agreed); refused together with `-j` |
| `-v` | full decode of each packet instead of one line (agreed) |
| `-H` | add the frame as a hex dump (text) or `frame_hex` (JSON), as dhcpdump does (call) |
| `-p` | do not put the interface in promiscuous mode; promiscuous is the default, as in tcpdump, so mirror ports work (call) |
| `-Z USER` | user to switch to when started as root (default `nobody`) (call) |
| `--dhcp-server IP[@VLAN]` | expected DHCP server, repeatable (agreed); `@VLAN` limits the pin to one segment (section 5.6) (call) |
| `--router MAC\|IPV6[@VLAN]` | expected IPv6 default router (by MAC or link-local address), repeatable (agreed); `@VLAN` as above (call) |
| `--max-memory SIZE` | memory budget for all tracked state, default 64 MiB (call) |
| `-D` | list interfaces with friendly names and addresses, then exit (call; needed on Windows, useful everywhere) |
| trailing words | a tcpdump filter expression, combined with the default filter by AND, so it narrows what overhear sees (call) |

**Default filter (call).** Applied in the kernel: broadcast and multicast frames, plus unicast frames of the decoded protocols (ARP; UDP ports 67, 68, 137, 1900, 5353, 5355; ICMPv6 types 133–137). On a mirror port or hub this catches the unicast replies the warnings need. It must also match VLAN-tagged frames: classic BPF port tests do not look past a VLAN tag on their own, so the expression has a `vlan and (...)` arm. The same filter applies to `-r` files.

Exit status: 0 on normal end (end of file, SIGINT, SIGTERM); 1 on errors (bad arguments, capture cannot be opened, unsupported link type, privilege drop failed). On exit in text or JSON mode, a summary (packets, kernel drops, devices) goes to stderr in text mode and as a `status` line in JSON mode.

### 5.2 Architecture

A Cargo workspace with two crates (call):

- **`overhear-decode`**: pure decoders, no I/O, no dependencies, `#![forbid(unsafe_code)]`. Takes `&[u8]` plus a link type and returns a structured, borrowed view of the packet. Testable and fuzzable without libpcap on any platform.
- **`overhear`** (binary): command line, capture sources, platform module, device table, warning rules, the four renderers.

Data flow:

```
capture thread                      main / UI thread
  Source (libpcap) ──frames──▶ bounded channel ──▶ decode ─▶ track ─▶ warn ─▶ render
```

- The capture thread only reads frames (timestamp, original length, bytes) and pushes them to a bounded channel. When the channel is full it counts the drop instead of blocking libpcap's buffer forever; drops are reported (section 5.8).
- The main thread decodes, updates the device table, runs the warning rules and renders. In `-t` mode it redraws at a fixed rate (at most 10 frames a second) independent of packet rate, and handles keys. Line and JSON output are written as packets arrive; they must reach a terminal or pipe without delay (how, e.g. flushing per packet unless stdout is a regular file, is the builder's).
- **Sources** sit behind one interface (`next() -> Option<Frame>`, link type, stats). v1 has the libpcap source for live and files. Tests and fuzzers feed frames through the same interface from a pure-Rust pcap/pcapng reader (e.g. the `pcap-file` crate, as a dev dependency), so the whole pipeline is tested without libpcap or Npcap (call).

### 5.3 Platform module

One module with a Linux implementation now and a Windows implementation later (Don: Windows designed in). Its whole surface:

- `list_interfaces()`: name, friendly name, addresses (for `-D` and for accepting friendly names in `-i`).
- `open_live(iface, promisc, filter)` and `open_file(path, filter)` → Source.
- `drop_privileges(opts)` (section 5.9).

Nothing outside this module may use `cfg(unix)`/`cfg(windows)`, libc calls or libpcap directly (call). To keep that honest, `cargo check --target x86_64-pc-windows-gnu` runs on every change from v1, with a stub Windows implementation that compiles (call; if the `pcap` crate's build script blocks a check without the Npcap SDK, the builder gates it behind a feature and notes it).

### 5.4 Decoders

**Principles (all agreed or call):**

- Zero-copy: a decoded packet borrows from the frame bytes.
- **Never panic on packet data.** All reads go through a bounds-checked cursor (`u8()`, `be16()`, `take(n)` returning `Option`/`Result`). The decoder crate denies `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, and uses checked arithmetic for anything derived from packet fields.
- **Partial decode.** A decoder returns everything it could parse plus a list of problems, each with a reason (`"truncated"`, `"length not a multiple of 4"`, `"compression pointer loop"`, …) and the offending bytes. One bad option or record does not discard the rest of the packet. This mirrors the malformed handling built for dhcpdump's JSON mode.
- Every loop over packet structure is bounded by the remaining bytes, and the few that could revisit bytes are explicitly limited: DNS compression pointers must point strictly backwards (so name decoding terminates), at most 255 bytes per name and 63 per label; IPv6 extension header chains limited to 8; VLAN tags limited to 4.

**Layers:**

- **Ethernet**: Ethernet II (EtherType ≥ 0x0600) and 802.3 with LLC/SNAP (length ≤ 1500, needed for STP and CDP). VLAN tags 0x8100 (C), 0x88a8 (S), 0x9100 (legacy QinQ), outer first.
- **IPv4**: header and options length checked. Fragments: first fragment decoded as far as it goes and marked; later fragments shown generically. No reassembly.
- **IPv6**: extension header walk to the upper-layer protocol.
- **UDP**: dispatched to an application decoder by well-known port (either side). Anything else to a broadcast/multicast address is a generic line.

**Protocols, what is shown, and what feeds the device table:**

| protocol | recognised by | one-line summary shows | feeds the device table |
|---|---|---|---|
| ARP | EtherType 0x0806 | request / reply / probe (RFC 5227, sender 0.0.0.0) / announcement (gratuitous) | sender MAC ↔ IPv4; sender MAC differing from the frame source is noted in `-v` |
| DHCPv4 | UDP 67/68 | message type, client MAC, offered/requested IP, server, hostname | the device is the client hardware address (`chaddr`), not the frame source, because relays forward for clients: hostname (12), client FQDN (81), vendor class (60), requested/assigned IP. Option decoding as complete as dhcpdump's in `-v` (names for all codes, typed values for the common ones, overload and long options handled) |
| IPv6 ND | ICMPv6 133–137 | RS, RA (prefixes, flags, lifetime, RDNSS), NS (DAD when from ::), NA, redirect | link-layer address options ↔ IPv6 addresses; routers marked as routers. ND with hop limit ≠ 255 is flagged invalid (RFC 4861) |
| mDNS | UDP 5353 | query names, or announced records (`name → address`, service instances) | `.local` host name ↔ addresses; services from PTR/SRV; model hints from TXT keys such as `md=` and `model=` (call) |
| LLMNR | UDP 5355 | query name and type, or answer | names answered by a host |
| NetBIOS NS | UDP 137 | query / registration / release / refresh, name with its type suffix | NetBIOS name, workgroup/domain from group names |
| SSDP | UDP 1900 | NOTIFY alive/byebye with NT, M-SEARCH with ST, or a search response | `SERVER` string, device type from NT/ST, `LOCATION` (shown, **never fetched**). Header parsing bounded (line length, header count) |
| LLDP | EtherType 0x88cc | system name, port, capabilities | system name/description, capabilities (bridge, router, AP, phone), management address, port VLAN. Organisation-specific TLVs shown as OUI/subtype/hex in `-v` |
| CDP | SNAP OUI 00000c, PID 0x2000 | device ID, port, platform | device ID, platform, software version, addresses, native VLAN |
| STP | LLC 0x42 | version (STP/RSTP/MSTP), root bridge, cost, bridge, port, topology-change flag | the bridge MAC is marked as a switch; the live screen header shows the current root bridge (call) |
| other | any broadcast/multicast frame | EtherType or IP protocol, ports, length | MAC, and IP source if present, "heard" |

### 5.5 Device table (agreed)

- Keyed by MAC address. A MAC seen on several VLANs is one device with the VLANs listed, and each address is recorded with the segment it was seen on (call).
- Each device holds: MAC (marked "random" when the locally administered bit is set, as with phones' private addresses) (call); IPv4 and IPv6 addresses; names with where each came from; vendor; services and device type hints; LLDP/CDP details; protocols heard; first and last heard; packet count.
- **Display name priority (call):** DHCP hostname > mDNS host name > NetBIOS name > LLDP/CDP system name.
- **Vendor (call):** from the IEEE MA-L/MA-M/MA-S registries, bundled in the binary as a generated compact table (so it works the same on Windows and offline), with a script to refresh it. MA-M and MA-S are matched before MA-L.
- **Bounded per device (call):** at most 16 IPv4, 16 IPv6, 16 names, 64 services, each string at most 255 bytes. Beyond that, the oldest entry of that kind is replaced.
- In memory for the run only; no saved history (agreed).

### 5.6 Warnings (agreed)

**Segments (call).** All warning state is kept per segment: one segment per VLAN tag stack seen (QinQ written outer.inner, e.g. `200.100`), and untagged traffic is its own segment. This covers expected servers, address-claim history and name-answer windows. On a trunk or mirror port carrying several VLANs, each VLAN's own DHCP server and router are then learned separately, and overlapping address ranges on different VLANs don't conflict. A pin without `@VLAN` applies to every segment; `--dhcp-server 10.0.0.1@100` applies to VLAN 100 only. Warnings and `baseline` events name their segment.

**Expected servers.** In each segment, the first DHCP server and the first IPv6 default router heard become the expected ones. A `baseline` event is printed when that happens, so the user can see what was trusted. `--dhcp-server` and `--router` pin the expected ones instead (repeatable for failover pairs), so a rogue that happens to speak first is not trusted.

**What counts as a router (call).** Many home networks have several legitimate senders of router adverts besides the real router: Thread/Matter border routers (HomePod mini, Apple TV, Nest hubs) and mesh Wi-Fi systems. These usually advertise with router lifetime 0, meaning "not a default router", and carry route information or private (ULA, `fc00::/7`) prefixes. Warning about every one of them would make the tool noisy on exactly the home networks it should need no setup for. So:

- A **default router** is a sender of router adverts with lifetime > 0. Only default routers are learned as expected.
- A lifetime-0 sender is recorded in the device table as "router, no default route" and does not warn, **unless** it advertises something that can redirect other machines: DNS servers (RDNSS/DNSSL options) or a global prefix for address autoconfiguration (a prefix option with the A flag set, outside `fc00::/7` and `fe80::/10`). That fires the lower-severity form of the rule below.

| rule | fires when | notes |
|---|---|---|
| second DHCP server | an OFFER, ACK or NAK comes from a server identifier (option 54, else the IP source) that is not expected | relayed replies keep the real server's identifier, so relays don't trigger it |
| unexpected router | high severity: a router advert with lifetime > 0 from a MAC / link-local address that is not an expected default router. Lower severity: a lifetime-0 advert from a sender that is not expected, carrying DNS servers or a global autoconfiguration prefix | a pinned `--router` is exempt from both |
| address conflict | an IPv4 address in an ARP sender field, or an IPv6 address in a neighbour advert, is claimed by a different MAC than the one recorded for it | worded neutrally (`192.168.1.1 now claimed by B, was A 3 min ago`) because failover (VRRP/HSRP/CARP), moving VMs and lease reuse also cause it. Marked higher severity when the address belongs to an expected DHCP server or router (call). Probes (sender 0.0.0.0, NS from ::) are ignored |
| suspicious name answers | (a) the same LLMNR/NetBIOS name, or the same mDNS unique address record, is answered by two different MACs with different data within 5 minutes; (b) one host answers LLMNR/NetBIOS queries for 3 or more different names within 5 minutes, the pattern of poisoning tools such as Responder (thresholds: call) | |

**What a passive listener can see.** On a switched network, unicast replies (many DHCP offers, all LLMNR and NetBIOS answers) reach only their destination. overhear then sees them only when this host is the one asking, or when it runs on a mirror port or hub. The rules are written to work with whatever arrives, and the man page and README must say this plainly. Active probing would close the gap but is an anti-goal.

**Operational warnings (call):** kernel or channel drops, and memory-budget evictions ("device table full, dropping least recently heard devices: possible MAC flood"). These are reported at most once a minute while they continue.

**Repeats.** Each warning has a key (rule plus subject). The first occurrence is reported immediately; repeats are counted and summarised at most once a minute per key. The live screen keeps the latest 200.

### 5.7 Output

**Untrusted strings (call).** Packet text is shown as text only when it is safe:

- Text and live screen: valid UTF-8 is shown, because mDNS device names legitimately carry non-ASCII (`Bjørn's iPhone`). Control characters (C0, DEL, C1) and Unicode format characters (bidi overrides, zero-width characters) are written as visible escapes (`\x1b`, `\u{202e}`), and invalid UTF-8 bytes as `\xNN`. One-line mode truncates long fields with `…`.
- NetBIOS names and SSDP headers are not UTF-8 by definition: printable ASCII is shown, anything else escaped.
- JSON: strings are valid UTF-8 with control and format characters escaped as `\uXXXX`. A field whose bytes are not valid UTF-8 is written as `<field>_hex` instead.
- This is stricter than "print what the packet says" on purpose: a hostile hostname must not be able to move the terminal cursor or reverse displayed text.

**Line mode (agreed):**

```
14:02:11.204 ARP   02:00:5e:10:00:14  who-has 192.168.1.1 tell 192.168.1.20
14:02:12.010 DHCP  192.168.1.254      OFFER 192.168.1.80 to 02:00:5e:10:00:39
14:02:12.010 WARN  second DHCP server 192.168.1.254 (expected 192.168.1.1)
```

Time, protocol, source (IP when there is one, else MAC), summary. VLAN-tagged frames show the tag. With `-r` the time includes the date (call). A timestamp that cannot be shown as a calendar date (e.g. pcapng with a huge `if_tsoffset`, the cause of dhcpdump's crash) is shown as `@<epoch seconds>` and never panics.

**Verbose (`-v`):** a block per packet with every layer and field, laid out like dhcpdump's output, problems marked inline.

**JSON (`-j`) (agreed, details call):** one object per line, flushed per line. Every line has `"schema": 1` and `"type"`:

- `packet`: `ts` (epoch seconds, microsecond fraction), `time` (ISO 8601 local time with offset and milliseconds, or `null` if not representable), `vlan`, `src`/`dst` `{mac, ip}`, `proto`, a protocol-specific object, `problems` (each with reason and hex), `frame_hex` with `-H`.
- `warning`: `rule`, `severity`, `subject`, `message`, related MACs/addresses, `count` for summarised repeats.
- `baseline`: what was learned as expected.
- `status`: drops, evictions, and the end-of-run summary.

Conventions follow the schema worked out for dhcpdump's `-j` (issue #9): typed values, the reason a field is malformed plus its raw hex, hex for non-text bytes. The exact field list per protocol is the builder's, written down in the man page and checked by tests.

**Live screen (`-t`) (agreed):**

```
 overhear  eth0   42 devices   1 warning   root 8000.00:11:22:33:44:01   14:05:33
 MAC                IP             NAME            VENDOR   HEARD
 02:00:5e:10:00:14  192.168.1.20   laptop          Intel    ARP DHCP mDNS
 02:00:5e:10:00:21  192.168.1.33   Living-Room-TV  Google   mDNS SSDP
 ── warnings ────────────────────────────────────────────────────────────────
 14:02:12  second DHCP server 192.168.1.254 (expected 192.168.1.1)
```

Built with ratatui on crossterm (both work on Windows). Keys (call): `q` quit, arrows/PgUp/PgDn select, `Enter` device details (all addresses, names with sources, services, LLDP/CDP data, VLANs, recent lines heard), `Esc` back, `s` cycle sort (last heard, MAC, IP, name, vendor, packets), `/` filter, `w` focus warnings, `p` pause the display (capture continues). A panic hook restores the terminal before any error is printed.

### 5.8 Resource limits (agreed; numbers call)

- **One memory budget** (`--max-memory`, default 64 MiB) covers every structure that grows with traffic: devices, address-claim history, name-answer windows, warning keys and the live screen's warning list. Each entry's size (struct plus heap strings) is accounted on insert, update and removal, and the total is kept in one counter, as done for dhcpdump's session tracker.
- Over budget: evict the least recently heard device and its related state. Pinned expected servers are never evicted. Report it (section 5.6).
- Per-device and per-string limits as in section 5.5.
- Bounded capture channel, drops counted and reported. libpcap's own drop counter is read and reported too.
- **Speed targets (call)**, measured with generated traffic of realistic sizes, output to `/dev/null`, no kernel drops over 5 minutes:
  - Raspberry Pi 4: 20,000 frames/s in line or JSON mode, with `-t` staying responsive (keys answered within 200 ms) at the same rate.
  - x86-64 (this development machine): 100,000 frames/s, as a regression guard.
  - Because the Pi is the tight one, the hot path (capture → decode → track → render) avoids per-packet heap allocation where it reasonably can, and the libpcap buffer size is set explicitly rather than left at the default.

### 5.9 Privileges (agreed)

Order: parse arguments → open the capture and set its filter → drop privileges → start threads and decoding. No packet byte is decoded before the drop.

**Linux:**

- Started as root: `setgroups([])`, `setgid`, `setuid` to the `-Z` user (default `nobody`), then verify that `setuid(0)` fails and exit with an error if it doesn't.
- Started as a normal user with file capabilities (`setcap cap_net_raw,cap_net_admin=eip`, the usual way to avoid root): clear the effective, permitted, inheritable and ambient capability sets. Keeping these after start was dhcpdump's `-Z` bug (fixed upstream as PR #7). Then verify the effective set is empty.
- Both paths set `PR_SET_NO_NEW_PRIVS`.
- A seccomp sandbox (for example, forbidding sends on the capture socket) is a later hardening step, not v1.

**Windows (later):** there is no equivalent drop. Who may capture is decided by Npcap's install option "restrict to administrators". `drop_privileges` documents this and does nothing.

## 6. Testing

- **Decoder unit tests**: hand-built byte vectors per protocol, from the RFC/spec layouts, with malformed variants of each (truncated at every field, bad lengths, pointer loops, oversize counts).
- **Generated captures, golden output**: a Rust generator (in the repo, e.g. an `xtask`) writes pcap files with crafted packets for every protocol and every warning scenario, including MAC floods and the out-of-range pcapng timestamp. Scenarios that must stay quiet are covered as well as those that must warn: a Thread border router's lifetime-0 advert with a ULA prefix and route information (no warning) versus one carrying RDNSS (lower-severity warning); a trunk with a different DHCP server and router per VLAN and overlapping address ranges (no warning); failover of a pinned server pair. Tests run the pipeline over them and compare text, `-v` and JSON output with checked-in expected files, under a fixed time zone.
- **No captures of real networks in the repo.** They contain device names and addresses. All checked-in test data is generated. Real captures may be used locally only.
- **Fuzzing (cargo-fuzz)**: one target per decoder, plus a pipeline target (decode → track → render text and JSON) that asserts no panic, every JSON line parses, text output contains no raw control bytes, and the memory counter matches a recount and stays within the budget.
- **Memory**: a flood test (a million random MACs with maximum-length names) checks resident memory stays near the budget.
- **Privileges**: the root path tested inside `unshare -U -r -n`; the file-capability path with a setcap copy of the binary in `$HOME`; both check `CapEff` is 0 and `setuid(0)` fails afterwards.
- **Live and "never sends"**: a veth pair in a private network namespace, a Rust injector replaying generated frames on one end, overhear on the other. Check the output, and check that no frame arrives from overhear's side beyond what the kernel itself sends (measured with overhear not running, IPv6 autoconfiguration disabled on the test interfaces).
- **Static checks**: clippy with the decoder deny list, rustfmt, cargo-audit, and the Windows `cargo check`.
- **ARM**: the aarch64 build runs the unit and golden-output tests under qemu user-mode emulation on the development machine on every change. The Pi speed target and a live capture run are checked on a real Raspberry Pi 4 before a release.

## 7. Repo and packaging

- Local git repo at `~/code/overhear`; published (e.g. GitHub under Don's account) only when Don says so.
- Licence: MIT, like Don's pubrs (call).
- README (including the "what a passive listener can see" section, setcap instructions, and a short "Raspberry Pi on a mirror port" guide), a man page, and Debian packages via cargo-deb for amd64 and arm64, cross-built for arm64 on the development machine.

## 8. Phases

1. **v1, Linux on x86-64 and Raspberry Pi (aarch64)**: everything in sections 5–7.
2. **Windows**: Npcap source, friendly interface names (adapter GUID → name), `-D`, packaging and "install Npcap first" instructions; decide whether `-r` can work without Npcap by loading `wpcap.dll` only when live capture is used.
3. **Later, by demand**: the non-goals list.

## 9. Later list (out of v1)

DHCPv6; IGMP/MLD group decoding; NetBIOS browser announcements (OS version and roles); PVST+; STP root-change and topology-change warnings; broadcast storm warnings; Linux `-i any`; device events in JSON (`device_new`, `device_changed`); saved history; a seccomp sandbox; DHCP fingerprinting from the parameter request list; Wake-on-LAN recognition.

## 10. Decisions and what is left to the builder

**Decided by Don:** the name; the scope (who is on the LAN and what they announce; the protocol list; device table; the four warnings; memory cap; privilege drop); approach 2; Linux first with Windows designed in; Raspberry Pi supported from v1.

**Proposed and accepted in discussion:** never sends; line / `-v` / `-j` / `-t` / `-r` / filter expression; expected servers learned from the first heard and pinnable; in-memory device table with a hard cap; no saved history.

**Calls made in this document** (open to change): what counts as a router (lifetime > 0 learned; lifetime-0 senders quiet unless they push DNS servers or a global prefix); warning state per VLAN segment with `@VLAN` pins; user-requested lookups (filter host names, `-Z` user) allowed and documented; Pi 4 as the reference Pi, aarch64 only (no 32-bit ARM); glibc 2.36 baseline for release builds; speed targets (Pi 4: 20k frames/s, x86-64: 100k); two-crate workspace; Source interface with a pure-Rust reader for tests; Windows `cargo check` from v1; default kernel filter and AND-combining user filters; `-H`, `-p`, `-Z` default `nobody`, `-D`, `--max-memory` default 64 MiB; UTF-8 display with escaping of control and format characters; display-name priority; bundled IEEE vendor table; per-device limits; name-answer thresholds; severity for conflicts on server addresses; operational warnings; JSON line types; live screen keys and root-bridge header; date in `-r` timestamps; MIT licence.

**Left to the builder:** crate choices beyond libpcap/ratatui/crossterm (argument parsing, time zones, JSON writing), provided they build on Windows; module layout inside the binary crate; exact JSON fields per protocol (documented in the man page); man page tooling; output flushing strategy per output type; channel size; refresh script format for the vendor table; test harness layout.
