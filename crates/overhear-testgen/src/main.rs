use std::fs;
use std::path::Path;
use std::process::ExitCode;

use overhear_testgen::{scenarios::scenarios, write_pcap};

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
        _ => {
            eprintln!("usage: testgen gen-samples <data-dir> <corpus-dir>");
            ExitCode::from(2)
        }
    }
}
