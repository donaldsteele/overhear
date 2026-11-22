#!/usr/bin/env bash
# Fills the samples in site/index.html with real output of the release
# binary over the generated test captures, and regenerates site/manual.html
# from doc/overhear.pod.
#
#   scripts/site-samples.sh            rewrite the samples and the manual
#   scripts/site-samples.sh --check    compare only; exit 1 on any difference
#
# A sample sits between <!-- sample:NAME --> and <!-- /sample:NAME --> in
# index.html. Each command below runs with TZ=UTC, as shown, in a directory
# holding the captures of crates/overhear/tests/data and lan.pcap, six of
# them merged in time order by `testgen merge`. Its output (standard error
# included) is HTML-escaped.
# The live-screen sample is drawn by the live_frame example with the same
# code as `overhear -t`. When it changes, retake site/assets/screens/live.png.
set -euo pipefail
cd "$(dirname "$0")/.."

check=0
case "${1:-}" in
  --check) check=1 ;;
  "") ;;
  *) echo "usage: scripts/site-samples.sh [--check]" >&2; exit 2 ;;
esac
for tool in jq pod2html; do
  command -v "$tool" >/dev/null || { echo "site-samples.sh needs $tool" >&2; exit 1; }
done

cargo build --release -q -p overhear
cargo build --release -q -p overhear --example live_frame
cargo build --release -q -p overhear-testgen

root=$PWD
data=crates/overhear/tests/data
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# "overhear" in the commands is the release binary just built.
mkdir "$work/bin"
ln -s "$root/target/release/overhear" "$work/bin/overhear"
# The captures the commands read: the test captures, and lan.pcap holding
# the same six, in the same order, as the live-screen sample.
run=$work/run
mkdir "$run"
ln -s "$root/$data"/*.pcap "$run/"
"$root/target/release/testgen" merge "$run/lan.pcap" dhcp nd mdns llmnr_nbns lldp_cdp stp
export TZ=UTC LC_ALL=C.UTF-8

esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# sample NAME COMMAND: appends the prompt, the command and its output.
sample() {
  local name=$1 cmd=$2
  {
    printf '<span class="p">$ </span>'
    printf '%s\n' "$cmd" | esc
    (cd "$run" && PATH="$work/bin:$PATH" bash -c "set -o pipefail; $cmd" 2>&1) | esc
  } >>"$work/$name"
}

sample line 'overhear -r dhcp.pcap'
sample verbose 'overhear -v -r lldp_cdp.pcap \
  ether src 02:00:5e:10:00:60 or ether src 02:00:5e:10:00:63'
sample json 'overhear -j -r arp.pcap | head -n 1 | jq .'
sample warnings 'for f in dhcp nd arp llmnr_nbns mdns; do overhear -r $f.pcap; done 2>/dev/null | grep WARN'
sample pins 'overhear -r dhcp.pcap --dhcp-server 192.168.1.1 2>/dev/null | grep WARN'
sample pins 'overhear -r dhcp.pcap --dhcp-server 192.168.1.1 --dhcp-server 10.9.9.9@100 2>/dev/null | grep WARN'
sample jq "overhear -j -r dhcp.pcap | jq -c 'select(.type != \"packet\")'"
sample jq "overhear -j -r dhcp.pcap | jq -r 'select(.rule == \"second-dhcp-server\") | \"\\(.subject) \\(.macs[0])\"'"
sample jq "overhear -j -r dhcp.pcap | jq -rs 'map(select(.type == \"packet\") | .src.mac // empty) | unique | group_by(.[:8])[] | \"\\(length) \\(.[0][:8])\"'"

# The recipes, over lan.pcap.
sample recipe-proto 'overhear -r lan.pcap --proto dhcp,mdns'
sample recipe-rogue 'overhear -r lan.pcap --proto dhcp --dhcp-server 192.168.1.1'
sample recipe-routers 'overhear -r lan.pcap --proto nd --router fe80::1'
sample recipe-poison 'overhear -r lan.pcap --proto llmnr,nbns'
sample recipe-wiring 'overhear -r lan.pcap --proto lldp,cdp,stp'
sample recipe-jq "overhear -j -r lan.pcap | jq -r 'select(.type == \"warning\") | .message'"
sample recipe-jq "overhear -j -r lan.pcap | jq -r 'select(.type == \"packet\") | .proto' | sort | uniq -c"
sample recipe-jq "overhear -j -r lan.pcap --proto dhcp |
  jq -r 'select(.dhcp.op == 1) | \"\\(.dhcp.chaddr) \\(.dhcp.options[] | select(.code == 12) | .value)\"' |
  sort -u"

# The live screen, sorted by name, over six captures read in time order.
(cd "$data" && "$root/target/release/examples/live_frame" lan.pcap 100 26 name \
  dhcp.pcap nd.pcap mdns.pcap llmnr_nbns.pcap lldp_cdp.pcap stp.pcap) >"$work/tui"

# Replaces the text between the markers of each sample.
html=$(<site/index.html)
for f in "$work"/*; do
  [ -f "$f" ] || continue
  name=${f##*/}
  start="<!-- sample:$name -->" end="<!-- /sample:$name -->"
  if [[ $html != *"$start"*"$end"* ]]; then
    echo "site/index.html: no $start ... $end" >&2
    exit 1
  fi
  text=$(<"$f")
  html="${html%%"$start"*}$start$text$end${html#*"$end"}"
done
printf '%s\n' "$html" >"$work/index.html"

# The manual: pod2html with an HTML5 head, the site's stylesheet and a way home.
pod2html --infile doc/overhear.pod --title "overhear(1)" --cachedir "$work" --quiet |
  sed -e '/^<?xml /d' \
    -e 's|^<!DOCTYPE html .*|<!doctype html>|' \
    -e 's|^<html xmlns=.*|<html lang="en">|' \
    -e '/^<meta http-equiv="content-type" /d' \
    -e 's|^<head>$|<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<meta name="color-scheme" content="light dark">|' \
    -e 's|^<link rev="made" .*|<link rel="icon" type="image/png" href="favicon.png">\n<link rel="preconnect" href="https://fonts.googleapis.com">\n<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,500..700;1,9..144,500\&amp;family=IBM+Plex+Mono:wght@400;500\&amp;family=IBM+Plex+Sans:wght@400;500;600\&amp;display=swap" rel="stylesheet">\n<link rel="stylesheet" href="styles.css">|' \
    -e 's|^<body>$|<body class="man">\n<a class="skip" href="#main">Skip to content</a>\n<header class="top"><div class="wrap"><a class="brand" href="index.html"><img src="icon.svg" width="32" height="32" alt="">overhear</a><nav aria-label="Site"><a href="index.html">Home</a><a href="https://github.com/donaldsteele/overhear">GitHub</a></nav></div></header>\n<main id="main" class="wrap">\n<p class="folio">The manual page</p>\n<h1 class="man-title">overhear(1)</h1>|' \
    -e 's|^</body>$|</main>\n</body>|' >"$work/manual.html"

status=0
for page in index.html manual.html; do
  if [ "$check" = 1 ]; then
    if ! diff -u "site/$page" "$work/$page"; then
      echo "site/$page is out of date: run scripts/site-samples.sh" >&2
      status=1
    fi
  else
    cp "$work/$page" "site/$page"
  fi
done
[ "$check" = 1 ] || echo "site samples and manual written"
exit "$status"
