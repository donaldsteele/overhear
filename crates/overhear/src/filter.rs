//! The capture filter: what overhear listens for by default.

pub const CORE: &str = "ether broadcast or ether multicast or arp or udp port 67 or udp port 68 or udp port 137 or udp port 1900 or udp port 5353 or udp port 5355 or (icmp6 and ip6[40] >= 133 and ip6[40] <= 137)";

/// The core filter, alone or narrowed by the user's words. The expression is
/// repeated behind `vlan` because that keyword shifts the offsets of
/// everything after it.
pub fn build_filter(user: &[String]) -> String {
    if user.is_empty() {
        return format!("({CORE}) or (vlan and ({CORE}))");
    }
    let u = user.join(" ");
    format!("(({CORE}) and ({u})) or (vlan and ({CORE}) and ({u}))")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::check_filter;

    #[test]
    fn user_words_narrow_both_arms() {
        let want = format!("(({CORE}) and (udp)) or (vlan and ({CORE}) and (udp))");
        assert_eq!(build_filter(&["udp".into()]), want);
    }

    #[test]
    fn empty_user_filter_is_core_twice() {
        let want = format!("({CORE}) or (vlan and ({CORE}))");
        assert_eq!(build_filter(&[]), want);
    }

    #[test]
    fn filters_compile() {
        check_filter(&build_filter(&[])).expect("default filter compiles");
        check_filter(&build_filter(&["host".into(), "10.0.0.1".into()]))
            .expect("narrowed filter compiles");
    }
}
