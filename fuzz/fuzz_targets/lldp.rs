#![no_main]

use overhear_decode::{Cursor, parse_lldp};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    if let Some(l) = parse_lldp(&mut c, &mut problems) {
        let _ = (l.chassis(), l.port(), l.sysname(), l.sysdescr(), l.enabled());
    }
});
