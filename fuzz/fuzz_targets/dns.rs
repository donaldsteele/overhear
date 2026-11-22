#![no_main]

use overhear_decode::{Cursor, RData, parse_dns};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut problems = Vec::new();
    let mut c = Cursor::new(data);
    if let Some(m) = parse_dns(&mut c, &mut problems) {
        // Resolving every name must terminate too.
        let mut out = Vec::new();
        let mut name = |n: &overhear_decode::Name<'_>| {
            n.write_dotted(&mut out);
            let _ = n.first_label();
        };
        for q in &m.questions {
            name(&q.name);
        }
        for r in &m.records {
            name(&r.name);
            match &r.rdata {
                RData::Ptr(t) => name(t),
                RData::Srv { target, .. } => name(target),
                _ => {}
            }
        }
    }
});
