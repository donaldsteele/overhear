#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = overhear_decode::decode(data);
});
