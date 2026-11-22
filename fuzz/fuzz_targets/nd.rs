#![no_main]

use overhear_decode::{Cursor, parse_nd};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let [typ, hop_limit, rest @ ..] = data else {
        return;
    };
    let mut problems = Vec::new();
    let mut c = Cursor::new(rest);
    let _ = parse_nd(&mut c, *typ, *hop_limit, &mut problems);
});
