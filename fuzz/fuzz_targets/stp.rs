#![no_main]

use overhear_decode::{Cursor, parse_stp};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    if let Some(s) = parse_stp(&mut c, &mut problems) {
        let _ = s.config.map(|c| c.root.to_bytes());
    }
});
