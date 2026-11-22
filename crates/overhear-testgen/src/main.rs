use std::fs;
use std::path::Path;
use std::process::ExitCode;

use overhear_testgen::{oui::gen_oui, scenarios::scenarios, write_pcap};

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
        _ => {
            eprintln!("usage: testgen gen-samples <data-dir> <corpus-dir>");
            eprintln!("       testgen gen-oui <oui.csv> <mam.csv> <oui36.csv> <out.rs>");
            ExitCode::from(2)
        }
    }
}
