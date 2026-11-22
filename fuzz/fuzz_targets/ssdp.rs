#![no_main]

use overhear_decode::{Cursor, parse_ssdp};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    if let Some(m) = parse_ssdp(&mut c, &mut problems) {
        let _ = m.header("LOCATION");
        let _ = m.header("nt");
    }
});
