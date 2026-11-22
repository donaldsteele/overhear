# Release checklist

## Speed (scripts/perf.sh)

`scripts/perf.sh RATE SECONDS` offers generated frames (perfgen, 500 devices) to
`overhear -i veth1` over a veth pair in a private namespace, in line mode and JSON mode,
and passes when overhear reports zero kernel drops and zero channel drops.

| Machine | Rate offered | Duration | Injector achieved | Line mode | JSON mode |
|---------|--------------|----------|-------------------|-----------|-----------|
| x86-64 (Linux 6.12, veth) | 100,000 pps | 300 s | 100,000 frames/s (30.0M frames per mode) | PASS, 0/0 drops | PASS, 0/0 drops |

Highest passing rate recorded on x86-64: 100,000 pps (the target; higher was not tried).

## Package build (scripts/release.sh)

Run `scripts/release.sh` on the build machine (Docker needed). It must finish with:

- `arm64 tests passed (max GLIBC_2.xx)`
- `amd64: glibc ok (max GLIBC_2.xx)` and `arm64: glibc ok (max GLIBC_2.xx)`, with xx no higher than 36
- `contents ok` for both packages
- `dist/` holding `overhear_0.1.0-1_amd64.deb`, `overhear_0.1.0-1_arm64.deb` and `testgen-arm64`

Build on 2026-11-21: both release binaries need at most GLIBC_2.34.

## Raspberry Pi 4 (manual)

Machine: Raspberry Pi 4, 64-bit Raspberry Pi OS (Debian 12 based). Needs `iproute2`,
`util-linux` (for `unshare`), `libcap2-bin` (for `setcap`) and passwordless `sudo`.

1. Install the arm64 package: `sudo apt install ./overhear_0.1.0-1_arm64.deb`.
2. Copy `testgen-arm64` and the `scripts/` directory to the Pi, along with
   `crates/overhear/tests/data/` (the scripts read the sample captures from there).
   Lay them out like a checkout so the scripts find what they expect:

   ```
   mkdir -p ~/overhear/target/release ~/overhear/crates/overhear/tests
   cp -r scripts ~/overhear/
   cp -r data ~/overhear/crates/overhear/tests/data   # data: the copied tests/data directory
   cp testgen-arm64 ~/overhear/target/release/testgen
   ln -s /usr/bin/overhear ~/overhear/target/release/overhear
   cd ~/overhear
   ```
3. `scripts/live-test.sh` prints `PASS` at the end and no `FAIL:` line.
4. `scripts/perf.sh 20000 300` reports PASS in both line and JSON mode (zero kernel and channel drops).
5. While `perf.sh` runs at 20,000 frames/s, start `overhear -t -i veth1` inside its
   network namespace and confirm that `q`, the arrow keys and Enter respond at once.
   (The script runs in a private namespace made with `unshare`; join it from a second
   terminal with `nsenter -t PID -U -n --preserve-credentials`, where PID is the process
   id of the running `perf.sh`.)
6. `SKIP_BUILD=1 scripts/priv-test.sh` prints `PASS` at the end and no `FAIL:` line.
7. Run `overhear -t` for 10 minutes on a real LAN. Every warning that appears must make
   sense for that network (a real second DHCP server, a real router change); note any that do not.
8. Record the results and the date below.

### Results

| Date | Pi / OS | live-test | perf 20000 x 300 s (line / JSON) | TUI under load | priv-test | 10 min on a LAN | Notes |
|------|---------|-----------|-----------------------------------|----------------|-----------|-----------------|-------|
|      |         |           |                                   |                |           |                 |       |
