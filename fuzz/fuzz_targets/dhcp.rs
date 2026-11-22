#![no_main]

use overhear_decode::{Cursor, parse_dhcp};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    let _ = parse_dhcp(&mut c, &mut problems);
});
