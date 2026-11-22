# Release checklist

## Speed (scripts/perf.sh)

`scripts/perf.sh RATE SECONDS` offers generated frames (perfgen, 500 devices) to
`overhear -i veth1` over a veth pair in a private namespace, in line mode and JSON mode,
and passes when overhear reports zero kernel drops and zero channel drops.

| Machine | Rate offered | Duration | Injector achieved | Line mode | JSON mode |
|---------|--------------|----------|-------------------|-----------|-----------|
| x86-64 (Linux 6.12, veth) | 100,000 pps | 300 s | 100,000 frames/s (30.0M frames per mode) | PASS, 0/0 drops | PASS, 0/0 drops |

Highest passing rate recorded on x86-64: 100,000 pps (the target; higher was not tried).
