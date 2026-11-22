use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use overhear_testgen::{
    flood, inject, oui::gen_oui, pcap_stream, perfgen, scenarios::scenarios, write_pcap,
};

fn gen_samples(data_dir: &Path, corpus_dir: &Path) -> std::io::Result<()> {
    let decode_dir = corpus_dir.join("decode");
    fs::create_dir_all(data_dir)?;
    fs::create_dir_all(&decode_dir)?;
    for (name, frames) in scenarios() {
        write_pcap(&data_dir.join(format!("{name}.pcap")), &frames)?;
        for (n, f) in frames.iter().enumerate() {
            fs::write(decode_dir.join(format!("{name}-{}", n + 1)), &f.data)?;
        }
    }
    Ok(())
}

/// Reads the three IEEE CSV files and writes the vendor table. The download date for the
/// header comes from `OUI_DATE` (set by scripts/update-oui.sh), so the output depends only
/// on the inputs.
fn gen_oui_file(mal: &str, mam: &str, mas: &str, out: &str) -> Result<(), String> {
    let read = |p: &str| fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
    let body = gen_oui(&read(mal)?, &read(mam)?, &read(mas)?)?;
    let date = std::env::var("OUI_DATE").unwrap_or_else(|_| "unknown".into());
    let text = match body.split_once("\n\n") {
        Some((head, rest)) => format!("{head}\n// Downloaded: {date}\n\n{rest}"),
        None => body,
    };
    fs::write(out, text).map_err(|e| format!("{out}: {e}"))
}

/// Writes a pcap of `n` flood frames to stdout.
fn flood_to_stdout(n: u64) -> std::io::Result<()> {
    let mut out = BufWriter::new(std::io::stdout().lock());
    pcap_stream(&mut out, flood(n))?;
    out.flush()
}

fn perfgen_to_file(out: &str, n: u64) -> std::io::Result<()> {
    let mut w = BufWriter::new(fs::File::create(out)?);
    pcap_stream(&mut w, perfgen(n))?;
    w.flush()
}

/// `inject <iface> <pcap...> [--rate PPS] [--seconds S]`
fn run_inject(iface: &str, rest: &[String]) -> ExitCode {
    let mut files = Vec::new();
    let mut rate = 1000u64;
    let mut seconds = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let parsed = match a.as_str() {
            "--rate" => it.next().and_then(|v| v.parse().ok()).map(|v| rate = v),
            "--seconds" => it
                .next()
                .and_then(|v| v.parse().ok())
                .map(|v| seconds = Some(v)),
            _ => {
                files.push(PathBuf::from(a));
                Some(())
            }
        };
        if parsed.is_none() {
            eprintln!("testgen: bad value for {a}");
            return ExitCode::from(2);
        }
    }
    if files.is_empty() || rate == 0 {
        eprintln!("usage: testgen inject <iface> <pcap...> [--rate PPS] [--seconds S]");
        return ExitCode::from(2);
    }
    match inject::inject(iface, &files, rate, seconds) {
        Ok((n, took)) => {
            println!("sent {n}");
            eprintln!(
                "testgen: sent {n} in {:.2}s ({:.0} frames/s)",
                took.as_secs_f64(),
                n as f64 / took.as_secs_f64().max(1e-9)
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("testgen: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, data, corpus] if cmd == "gen-samples" => {
            match gen_samples(Path::new(data), Path::new(corpus)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("testgen: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        [cmd, mal, mam, mas, out] if cmd == "gen-oui" => match gen_oui_file(mal, mam, mas, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("testgen: {e}");
                ExitCode::FAILURE
            }
        },
        [cmd, iface, rest @ ..] if cmd == "inject" => run_inject(iface, rest),
        [cmd, iface, secs] if cmd == "count-inbound" => match secs.parse::<f64>() {
            Ok(s) => match inject::count_inbound(iface, s) {
                Ok(n) => {
                    println!("{n}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("testgen: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("testgen: seconds: {e}");
                ExitCode::from(2)
            }
        },
        [cmd, out, n] if cmd == "perfgen" => match n.parse::<u64>() {
            Ok(n) => match perfgen_to_file(out, n) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("testgen: {out}: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("testgen: frame count: {e}");
                ExitCode::from(2)
            }
        },
        [cmd, n] if cmd == "flood" => match n.parse::<u64>() {
            Ok(n) => match flood_to_stdout(n) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("testgen: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(e) => {
                eprintln!("testgen: frame count: {e}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("usage: testgen gen-samples <data-dir> <corpus-dir>");
            eprintln!("       testgen flood <frames>");
            eprintln!("       testgen perfgen <out.pcap> <frames>");
            eprintln!("       testgen inject <iface> <pcap...> [--rate PPS] [--seconds S]");
            eprintln!("       testgen count-inbound <iface> <seconds>   (or until SIGINT)");
            eprintln!("       testgen gen-oui <oui.csv> <mam.csv> <oui36.csv> <out.rs>");
            ExitCode::from(2)
        }
    }
}
