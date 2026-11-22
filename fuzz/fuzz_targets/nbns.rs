#![no_main]

use overhear_decode::{Cursor, parse_nbns};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    if let Some(m) = parse_nbns(&mut c, &mut problems) {
        for r in &m.records {
            let _ = r.name.trimmed();
            let _ = overhear_decode::nb_entries(r.rdata).count();
        }
    }
});
