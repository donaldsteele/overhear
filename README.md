# overhear

overhear is a passive listener for a local network. It decodes the traffic that
devices send to everybody (ARP, DHCP, IPv6 neighbour discovery, mDNS, LLMNR,
NetBIOS name service, SSDP, LLDP, CDP, spanning tree), keeps a table of the
devices it hears, and warns about things that look wrong: a second DHCP server, an
unexpected IPv6 router, two devices claiming one address, name-poisoning tools.

It never transmits. It does not answer queries, scan, or look up names, so it is
safe to leave on a mirror port of a network you do not own. It runs as one
small binary on Linux, x86-64 and arm64 (the arm64 packages are built and tested
under emulation; the Raspberry Pi hardware checks have not been run yet), as a
line-per-packet log, a verbose dump, JSON lines for scripts, or a full-screen view.

Everything that comes off the wire is treated as hostile. Text from packets is
escaped before it is shown, so a device cannot put terminal control sequences on
your screen, and privileges are dropped as soon as the capture is open.

```
$ overhear -r dhcp.pcap
2026-11-21 13:02:11.000 DHCP  02:00:5e:10:00:39  DISCOVER from 02:00:5e:10:00:39 "host-a"
2026-11-21 13:02:11.250 DHCP  192.168.1.1        OFFER 192.168.1.50 to 02:00:5e:10:00:39
2026-11-21 13:02:11.250 NOTE  expected DHCP server 192.168.1.1 (learned)
2026-11-21 13:02:11.500 DHCP  192.168.1.254      OFFER 192.168.1.51 to 02:00:5e:10:00:39
2026-11-21 13:02:11.500 WARN  second DHCP server 192.168.1.254 (expected 192.168.1.1)
```

(That output is from one of the generated sample captures used by the tests.)

## Install the package

Debian packages for amd64 and arm64 are built on Debian 12 (bookworm) and need no
newer glibc than 2.36, so they install on Debian 12 and later and on Raspberry Pi OS
64-bit (which is based on Debian 12).

```
sudo apt install ./overhear_0.1.0-1_amd64.deb     # or ..._arm64.deb
```

It installs `/usr/bin/overhear`, the manual page (`man overhear`) and this
README under `/usr/share/doc/overhear/`. It depends on `libpcap0.8` (1.10 or
newer).

## Build from source

You need Rust 1.85 or newer and the libpcap development files:

```
sudo apt install build-essential pkg-config libpcap-dev
cargo build --release
./target/release/overhear -D          # list interfaces
```

The result is `target/release/overhear`. To build the manual page:

```
pod2man --section 1 --center overhear --release "overhear 0.1.0" doc/overhear.pod | man -l -
```

## Run it

Capturing needs privileges. Either run it as root, in which case it switches to
the `nobody` user (or the one named with `-Z`) as soon as the capture is open:

```
sudo overhear -i eth0
```

or give the binary file capabilities once and run it as yourself:

```
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/overhear
overhear -i eth0
```

Either way, once the capture is open overhear has no privilege left: all
capabilities are cleared and `no_new_privs` is set. A recorded capture needs
no privileges at all: `overhear -r file.pcap`, or `-r -` for standard input.

Common uses:

```
overhear -i eth0                 one line per packet
overhear -t -i eth0              full-screen device list (q quits, / filters, s sorts)
overhear -v -i eth0              every decoded field
overhear -j -i eth0              JSON lines
overhear -i eth0 --dhcp-server 192.168.1.1 --router 02:00:5e:10:00:01
overhear -i eth0 --max-memory 16M
overhear -i eth0 host 192.168.1.20
```

Extra words at the end of the command line are a capture filter, joined to the
built-in one with "and". They can only narrow what is shown. The built-in filter
accepts broadcast and multicast frames, ARP, and the DHCP, NetBIOS, SSDP,
mDNS and LLMNR ports, and IPv6 neighbour discovery.

Two things to know about filters:

* Host and port names written in a filter are resolved by libpcap through the system
  resolver, which can send DNS queries. overhear itself never sends. For strict
  silence use numeric addresses and ports.
* The filter looks through at most two VLAN tags (QinQ). Unicast frames with
  three or more tags may be missed, and with filter words so may broadcast and
  multicast frames with three or more tags.

`man overhear` has the full description of every option, the warning rules,
and every JSON field.

## Warnings

| Rule | Severity | Meaning |
|------|----------|---------|
| second-dhcp-server | high | A DHCP OFFER, ACK or NAK from a server other than the expected one |
| unexpected-router | high or low | An IPv6 router advertisement from a router other than the expected one (high), or from a non-router that advertises DNS or a global prefix (low) |
| address-conflict | low, high for a known server or router | An IP address now claimed by a different MAC |
| suspicious-name-answers | low or high | One name answered by two devices (low), or one device answering for many names (high) |
| capture-drops | low | Frames were dropped by the kernel or by overhear |
| memory-eviction | low | The memory budget was reached and old devices were dropped |

The expected DHCP server and router are learned per VLAN segment: the first
one heard is trusted and announced with a `NOTE` line. To avoid trusting whoever
speaks first, name them with `--dhcp-server IP[@VLAN]` and `--router MAC|IPV6[@VLAN]`.
Untagged traffic is one segment; a priority tag (VLAN id 0) counts as untagged.
Learned state is kept for the untagged segment and at most 256 VLAN segments. Past
that the least recently used VLAN segment learns again, so whoever speaks first
there is trusted again; the untagged segment is never forgotten.
Neighbour discovery packets whose hop limit is not 255 are shown but never cause a warning.

The first time a warning happens it is shown at once; repeats are counted and
summarised once a minute.

## Raspberry Pi on a mirror port

A Raspberry Pi 4 with a USB or built-in Ethernet port should be enough to watch a
network all day. For switches that support it, mirror (SPAN) the ports you care about to
the port the Pi is plugged into:

1. Install the arm64 package: `sudo apt install ./overhear_0.1.0-1_arm64.deb`.
2. Give it capture rights: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/overhear`.
3. Plug the Pi into the mirror port. The port does not need an IP address; leave
   it unconfigured so the Pi sends nothing there.
4. Run `overhear -t -i eth0` (or `overhear -j -i eth0 > lan.jsonl` to keep a record).
5. If a `capture-drops` warning appears, the mirror carries more than the Pi can
   read. Narrow the mirror, or add filter words.

On a mirror port or a hub you see the unicast replies as well as the broadcasts. The
default memory budget of 64M should leave a Pi 4 plenty of room (not yet measured
on one); use `--max-memory 16M` on a small board.

## What a passive listener can see

A switch delivers broadcast and multicast frames to every port, so on any port overhear sees
DHCP discovers and offers, ARP requests, router advertisements, mDNS, SSDP, name
service announcements, LLDP, CDP and spanning tree. It does not see unicast
traffic between other devices, such as DHCP ACKs to a client elsewhere or ARP
replies, unless you listen on a mirror port, a tap or a hub, or the traffic is
addressed to you, or you provoke the replies with your own queries (overhear
never does). A device that never broadcasts is not seen at all. VLAN tags are
seen only when the port delivers them tagged.

## JSON output

`overhear -j` writes one JSON object per line, each starting with `"schema":1`
and a `"type"` of `packet`, `warning`, `baseline` or `status`. The examples are
lines of the golden files in `crates/overhear/tests/data/`.

A packet (ARP):

```json
{"schema":1,"type":"packet","ts":1795266131.000000,"time":"2026-11-21T13:02:11.000+00:00","len":60,"src":{"mac":"02:00:5e:10:00:01"},"dst":{"mac":"ff:ff:ff:ff:ff:ff"},"proto":"arp","arp":{"op":1,"kind":"request","sender_mac":"02:00:5e:10:00:01","sender_ip":"192.168.1.20","target_mac":"00:00:00:00:00:00","target_ip":"192.168.1.1"}}
```

An IPv6 router advertisement:

```json
{"schema":1,"type":"packet","ts":1795266131.250000,"time":"2026-11-21T13:02:11.250+00:00","len":134,"src":{"mac":"02:00:5e:10:00:01","ip":"fe80::1"},"dst":{"mac":"33:33:00:00:00:01","ip":"ff02::1"},"proto":"nd","nd":{"type":"ra","cur_hop_limit":64,"flags":0,"managed":false,"other":false,"lifetime":1800,"reachable":0,"retrans":0,"options":[{"type":"source_lla","mac":"02:00:5e:10:00:01"},{"type":"prefix","prefix":"2001:db8:1::","len":64,"on_link":true,"autonomous":true,"valid":2592000,"preferred":604800},{"type":"rdnss","lifetime":600,"servers":["2001:db8::53"]}]}}
```

A packet that could only be decoded in part (`problems` says where):

```json
{"schema":1,"type":"packet","ts":1795266192.500000,"time":"2026-11-21T13:03:12.500+00:00","len":34,"src":{"mac":"02:00:5e:10:00:04"},"dst":{"mac":"ff:ff:ff:ff:ff:ff"},"proto":"other","other":{"ethertype":2054,"payload_len":20},"problems":[{"layer":"arp","reason":"truncated","offset":14,"hex":"000108000604000102005e100004c0a801280000"}]}
```

A warning, and the baseline it is measured against:

```json
{"schema":1,"type":"baseline","ts":1795266131.250000,"time":"2026-11-21T13:02:11.250+00:00","segment":"untagged","what":"dhcp-server","ip":"192.168.1.1"}
{"schema":1,"type":"warning","ts":1795266131.500000,"time":"2026-11-21T13:02:11.500+00:00","rule":"second-dhcp-server","severity":"high","segment":"untagged","subject":"192.168.1.254","message":"second DHCP server 192.168.1.254 (expected 192.168.1.1)","macs":["02:00:5e:10:00:fe","02:00:5e:10:00:39"],"addrs":["192.168.1.254"],"count":1}
```

An IPv6 router baseline:

```json
{"schema":1,"type":"baseline","ts":1795266131.250000,"time":"2026-11-21T13:02:11.250+00:00","segment":"untagged","what":"router","ip":"fe80::1","mac":"02:00:5e:10:00:01"}
```

The last line of a complete run:

```json
{"schema":1,"type":"status","final":true,"packets":13,"kernel_drops":0,"channel_drops":0,"devices":6,"evictions":0}
```

A run that ends on an error (a truncated capture file, for example) has no final
status line, so a missing last line means the output may be incomplete.

Pick out the warnings with `jq`:

```
overhear -j -i eth0 | jq -c 'select(.type=="warning")'
```

## Exit status

0 when the run ended normally: end of the input, `q` in the full-screen view,
Ctrl-C or SIGTERM, or the reader of a pipe went away. 1 for any error: a bad
command line, an interface or file that cannot be opened, a bad filter, a
failure to drop privileges, a truncated capture file, a failure while
capturing. A second Ctrl-C exits at once.

## Development

Layout:

```
crates/overhear-decode/   packet decoding (no dependencies, no unsafe code)
crates/overhear/          the program: capture, tracking, warnings, output, full-screen view
crates/overhear-testgen/  generates the test captures and the load for speed tests
fuzz/                     cargo-fuzz targets
scripts/                  checks and tests
doc/overhear.pod          the manual page
docs/release-checklist.md manual steps before a release
packaging/                the Debian 12 build image
```

### The checks

```
scripts/check.sh
```

runs `cargo fmt --check`, clippy with warnings as errors, the tests, a Rust 1.85
build, the Windows check for the portable crates, `cargo audit`, `podchecker` on
the manual page, and the whole test suite again for arm64 in a Debian 12
container (`scripts/arm64-test.sh`, which also checks the glibc limit). It ends with
`all checks passed`. `SKIP_ARM=1 scripts/check.sh` skips the container run
while you iterate. It needs Docker, `cargo-audit` and the Windows target
(`rustup target add x86_64-pc-windows-msvc`). The advisories that `cargo audit`
accepts for now are listed, with the reason, in `.cargo/audit.toml`.

### Golden files

`crates/overhear/tests/data/` holds generated sample captures (`*.pcap`) and
the output expected for each in line, verbose and JSON form. All test data is
generated; no capture of a real network is ever committed. After a deliberate output change:

```
UPDATE_GOLDEN=1 cargo test -p overhear --test golden
git diff crates/overhear/tests/data    # read every change
```

The samples themselves are regenerated with
`cargo run -q -p overhear-testgen -- gen-samples crates/overhear/tests/data fuzz/corpus`.

### Fuzzing

```
cargo +nightly fuzz run decode -- -max_total_time=60
```

from the repository root; the other targets are `arp`, `dhcp`, `dns`, `nd`,
`nbns`, `ssdp`, `lldp`, `cdp`, `stp` and `pipeline`. Corpus policy: only the
seeds written by `gen-samples` are committed in `fuzz/corpus/decode`. What fuzzing
finds stays on your machine (`fuzz/corpus` is otherwise ignored); a crash is
turned into a unit test with a hand-built input instead.

### Scripts

| Script | What it does |
|--------|--------------|
| `scripts/check.sh` | All the checks above |
| `scripts/arm64-test.sh` | Tests and debug build for arm64 in the Debian 12 image, with the glibc 2.36 limit |
| `scripts/live-test.sh` | Runs the real binary on a veth pair in a private namespace, injects every sample, compares the output, and checks that overhear transmits nothing |
| `scripts/perf.sh RATE SECONDS` | Offers generated frames at RATE per second to overhear in line and JSON mode and passes when nothing is dropped and the injector reached at least 98% of RATE |
| `scripts/priv-test.sh` | Checks the privilege drop (root and `setcap`) on a real capture of `lo` (needs sudo) |
| `scripts/flood-test.sh` | Replays a million frames from different MACs and checks that the memory stays near the budget (64M gives at most 112 MiB resident) |
| `scripts/update-oui.sh` | Regenerates the vendor table from the IEEE registries |
| `scripts/release.sh` | Builds the manual page and both Debian packages (see below) |

`live-test.sh`, `perf.sh` and `flood-test.sh` use `target/release/`; build with
`cargo build --release --workspace` first. They use `unshare` and `ip` (the first two in a
private user and network namespace, so they need no root).

### Releasing

```
scripts/release.sh
```

needs Docker. It builds the manual page, then in the Debian 12 image builds the
release binaries and `.deb` packages for amd64 and arm64 and a `testgen` for
arm64, runs the arm64 tests, requires every release binary to need no newer
glibc than 2.36, and checks that each package lists the binary and the manual page.
The results are in `dist/` (not committed):

```
dist/overhear_0.1.0-1_amd64.deb
dist/overhear_0.1.0-1_arm64.deb
dist/testgen-arm64
```

Then work through `docs/release-checklist.md` on a Raspberry Pi 4.

## License

MIT; see `LICENSE`.
