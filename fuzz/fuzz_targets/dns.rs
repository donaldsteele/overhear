#![no_main]

use overhear_decode::{Cursor, parse_dns};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    if let Some(m) = parse_dns(&mut c, &mut problems) {
        // Resolving every name must terminate too.
        let mut out = Vec::new();
        for q in &m.questions {
            q.name.write_dotted(&mut out);
        }
        for r in &m.records {
            r.name.write_dotted(&mut out);
        }
    }
});
