//! Vendor names from the IEEE MA-L, MA-M and MA-S registries.

use overhear_decode::Mac;

#[rustfmt::skip]
mod table;

fn find<K: Ord + Copy>(rows: &[(K, u16)], key: K) -> Option<&'static str> {
    let i = rows.binary_search_by_key(&key, |r| r.0).ok()?;
    table::NAMES.get(usize::from(rows.get(i)?.1)).copied()
}

/// Registered organisation for a MAC (MA-S, then MA-M, then MA-L), or None for local,
/// multicast or unregistered addresses.
pub fn lookup(mac: Mac) -> Option<&'static str> {
    if mac.is_local() || mac.is_multicast() {
        return None;
    }
    let v = mac.0.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    find(table::MA_S, v >> 12)
        .or_else(|| find(table::MA_M, u32::try_from(v >> 20).ok()?))
        .or_else(|| find(table::MA_L, u32::try_from(v >> 24).ok()?))
}

const SUFFIXES: &[&str] = &[
    "inc",
    "inc.",
    "corporation",
    "corporate",
    "corp",
    "corp.",
    "co",
    "co.",
    "ltd",
    "ltd.",
    "limited",
    "llc",
    "gmbh",
    "ag",
    "sa",
    "s.a.",
    "bv",
    "b.v.",
    "technologies",
    "technology",
    "electronics",
    "international",
];

/// A short display form of an organisation name: cut at the first comma, drop trailing
/// company-form words, keep at most two words.
pub fn short(name: &str) -> String {
    let head = name.split(',').next().unwrap_or("");
    let mut words: Vec<&str> = head.split_whitespace().collect();
    while words.len() > 1
        && words
            .last()
            .is_some_and(|w| SUFFIXES.contains(&w.to_lowercase().as_str()))
    {
        words.pop();
    }
    words.truncate(2);
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_testgen::mac;

    #[test]
    fn short_names() {
        assert_eq!(short("Google, Inc."), "Google");
        assert_eq!(short("Apple, Inc."), "Apple");
        assert_eq!(short("Intel Corporate"), "Intel");
        assert_eq!(short("Raspberry Pi Trading Ltd"), "Raspberry Pi");
        assert_eq!(short("TP-LINK TECHNOLOGIES CO.,LTD."), "TP-LINK");
        assert_eq!(short("Cisco Systems, Inc"), "Cisco Systems");
    }

    #[test]
    fn lookups() {
        assert!(
            lookup(Mac([0, 0, 0x0c, 1, 2, 3]))
                .unwrap()
                .contains("Cisco")
        );
        assert!(
            lookup(Mac([0xdc, 0xa6, 0x32, 1, 2, 3]))
                .unwrap()
                .contains("Raspberry Pi")
        );
        assert_eq!(lookup(Mac(mac(1))), None);
        assert_eq!(lookup(Mac([1, 0, 0x5e, 0, 0, 1])), None);
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    #[test]
    fn tables_are_sorted_and_indexed() {
        fn sorted<K: Ord>(r: &[(K, u16)]) -> bool {
            r.windows(2).all(|w| w[0].0 < w[1].0)
        }
        assert!(sorted(table::MA_L) && sorted(table::MA_M) && sorted(table::MA_S));
        assert!(table::NAMES.windows(2).all(|w| w[0] < w[1]));
        let max = table::MA_L
            .iter()
            .map(|r| r.1)
            .chain(table::MA_M.iter().map(|r| r.1))
            .chain(table::MA_S.iter().map(|r| r.1))
            .max();
        assert!(usize::from(max.unwrap()) < table::NAMES.len());
        assert!(table::MA_L.len() + table::MA_M.len() + table::MA_S.len() > 30_000);
    }

    #[test]
    fn lookup_never_panics() {
        for a in 0..=255u8 {
            for b in [0u8, 0x7f, 0xff] {
                let _ = lookup(Mac([a, b, a, b, a, b]));
                let _ = lookup(Mac([a, 0, 0, 0, 0, b]));
            }
        }
    }
}

#[cfg(test)]
mod precedence_tests {
    use super::*;

    fn mac_from(v: u64) -> Mac {
        let b = v.to_be_bytes();
        Mac([b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    fn name(idx: u16) -> &'static str {
        table::NAMES[usize::from(idx)]
    }

    #[test]
    fn ma_m_and_ma_s_hits() {
        let (k, i) = table::MA_M[0];
        let m = mac_from((u64::from(k) << 20) | 0x5_4321);
        assert_eq!(lookup(m), Some(name(i)));
        let (k, i) = table::MA_S[0];
        let m = mac_from((k << 12) | 0x321);
        assert_eq!(lookup(m), Some(name(i)));
    }

    #[test]
    fn longer_prefix_wins_over_enclosing_registration() {
        // An MA-S block inside a registered MA-L must report the MA-S holder.
        let (k, i) = *table::MA_S
            .iter()
            .find(|(k, i)| {
                let l = u32::try_from(k >> 12).unwrap();
                table::MA_L
                    .binary_search_by_key(&l, |r| r.0)
                    .is_ok_and(|p| table::MA_L[p].1 != *i)
            })
            .expect("an MA-S nested in an MA-L");
        let l = u32::try_from(k >> 12).unwrap();
        let outer = table::MA_L[table::MA_L.binary_search_by_key(&l, |r| r.0).unwrap()].1;
        let m = mac_from((k << 12) | 0xabc);
        assert_eq!(lookup(m), Some(name(i)));
        assert_ne!(name(i), name(outer));
        // MA-M nested in an MA-L likewise.
        if let Some((k, i)) = table::MA_M.iter().find(|(k, i)| {
            table::MA_L
                .binary_search_by_key(&(k >> 4), |r| r.0)
                .is_ok_and(|p| table::MA_L[p].1 != *i)
        }) {
            assert_eq!(lookup(mac_from((u64::from(*k) << 20) | 1)), Some(name(*i)));
        }
    }
}
