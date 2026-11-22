//! The capture filter: what overhear listens for by default, narrowed to the
//! protocols named with `--proto` and by the user's filter words.

pub const CORE: &str = "ether broadcast or ether multicast or arp or udp port 67 or udp port 68 or udp port 137 or udp port 1900 or udp port 5353 or udp port 5355 or (icmp6 and ip6[40] >= 133 and ip6[40] <= 137)";

/// A protocol `--proto` can name.
struct Proto {
    name: &'static str,
    aliases: &'static [&'static str],
    /// The capture filter expression that selects it.
    bpf: &'static str,
}

/// Every protocol `--proto` knows, in the order their expressions are joined.
const PROTOCOLS: [Proto; 10] = [
    Proto {
        name: "arp",
        aliases: &[],
        bpf: "arp",
    },
    Proto {
        name: "dhcp",
        aliases: &[],
        bpf: "udp port 67 or udp port 68",
    },
    Proto {
        name: "nd",
        aliases: &["ndp", "ipv6-nd"],
        bpf: "icmp6 and ip6[40] >= 133 and ip6[40] <= 137",
    },
    Proto {
        name: "mdns",
        aliases: &[],
        bpf: "udp port 5353",
    },
    Proto {
        name: "llmnr",
        aliases: &[],
        bpf: "udp port 5355",
    },
    Proto {
        name: "nbns",
        aliases: &["netbios"],
        bpf: "udp port 137",
    },
    Proto {
        name: "ssdp",
        aliases: &[],
        bpf: "udp port 1900",
    },
    Proto {
        name: "lldp",
        aliases: &[],
        bpf: "ether proto 0x88cc",
    },
    Proto {
        name: "cdp",
        aliases: &[],
        bpf: "ether dst 01:00:0c:cc:cc:cc",
    },
    Proto {
        name: "stp",
        aliases: &[],
        bpf: "ether dst 01:80:c2:00:00:00",
    },
];

/// `(known: arp, dhcp, …)`, for error messages.
fn known() -> String {
    let names: Vec<&str> = PROTOCOLS.iter().map(|p| p.name).collect();
    format!("(known: {})", names.join(", "))
}

/// The expression selecting the protocols named with `--proto`, one value
/// per use of the flag. A value may hold several names separated by commas;
/// names are matched in any case, and each protocol counts once. The result
/// is `(p1) or (p2) …` in the order of the table above, whatever the order
/// of the names.
pub fn proto_expr(values: &[String]) -> Result<String, String> {
    let mut wanted = [false; PROTOCOLS.len()];
    for name in values.iter().flat_map(|v| v.split(',')).map(str::trim) {
        if name.is_empty() {
            return Err(format!("empty protocol name {}", known()));
        }
        let lower = name.to_ascii_lowercase();
        let i = PROTOCOLS
            .iter()
            .position(|p| p.name == lower || p.aliases.contains(&lower.as_str()))
            .ok_or_else(|| format!("unknown protocol \"{name}\" {}", known()))?;
        wanted[i] = true;
    }
    let parts: Vec<String> = PROTOCOLS
        .iter()
        .zip(wanted)
        .filter(|&(_, w)| w)
        .map(|(p, _)| format!("({})", p.bpf))
        .collect();
    if parts.is_empty() {
        return Err(format!("empty protocol name {}", known()));
    }
    Ok(parts.join(" or "))
}

/// The capture filter: the core filter, alone or narrowed, in three arms:
/// untagged, one VLAN tag, and two (QinQ). In libpcap each `vlan` keyword
/// moves the offsets of everything after it in the expression, across `or`
/// too, so the third arm needs only one more `vlan` to look past the second
/// tag (`vlan and vlan` there would look past a third).
///
/// What narrows it is the `--proto` expression P and the user's filter words
/// U: `(P) and (U)` with both, or whichever was given, put into every arm.
pub fn build_filter(protos: &[String], user: &[String]) -> Result<String, String> {
    let words = user.join(" ");
    let u = match (protos.is_empty(), user.is_empty()) {
        (true, true) => {
            return Ok(format!(
                "({CORE}) or (vlan and ({CORE})) or (vlan and ({CORE}))"
            ));
        }
        (true, false) => words,
        (false, true) => proto_expr(protos)?,
        (false, false) => format!("({}) and ({words})", proto_expr(protos)?),
    };
    Ok(format!(
        "(({CORE}) and ({u})) or (vlan and ({CORE}) and ({u})) or (vlan and ({CORE}) and ({u}))"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::check_filter;

    const KNOWN: &str = "(known: arp, dhcp, nd, mdns, llmnr, nbns, ssdp, lldp, cdp, stp)";

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The three arms with `u` narrowing each, as `build_filter` writes them.
    fn arms_with(u: &str) -> String {
        format!(
            "(({CORE}) and ({u})) or (vlan and ({CORE}) and ({u})) or (vlan and ({CORE}) and ({u}))"
        )
    }

    #[test]
    fn user_words_narrow_every_arm() {
        assert_eq!(build_filter(&[], &strings(&["udp"])), Ok(arms_with("udp")));
    }

    #[test]
    fn empty_user_filter_is_core_for_zero_one_and_two_tags() {
        let want = format!("({CORE}) or (vlan and ({CORE})) or (vlan and ({CORE}))");
        assert_eq!(build_filter(&[], &[]), Ok(want));
    }

    #[test]
    fn proto_expression_for_dhcp_and_mdns() {
        let p = "(udp port 67 or udp port 68) or (udp port 5353)";
        assert_eq!(proto_expr(&strings(&["dhcp,mdns"])), Ok(p.to_owned()));
        assert_eq!(
            build_filter(&strings(&["dhcp,mdns"]), &[]),
            Ok(arms_with(p))
        );
    }

    #[test]
    fn proto_expression_for_each_name() {
        for (name, bpf) in [
            ("arp", "arp"),
            ("dhcp", "udp port 67 or udp port 68"),
            ("nd", "icmp6 and ip6[40] >= 133 and ip6[40] <= 137"),
            ("mdns", "udp port 5353"),
            ("llmnr", "udp port 5355"),
            ("nbns", "udp port 137"),
            ("ssdp", "udp port 1900"),
            ("lldp", "ether proto 0x88cc"),
            ("cdp", "ether dst 01:00:0c:cc:cc:cc"),
            ("stp", "ether dst 01:80:c2:00:00:00"),
        ] {
            assert_eq!(
                proto_expr(&strings(&[name])),
                Ok(format!("({bpf})")),
                "{name}"
            );
        }
    }

    #[test]
    fn proto_aliases() {
        let nd = proto_expr(&strings(&["nd"]));
        assert_eq!(proto_expr(&strings(&["ndp"])), nd);
        assert_eq!(proto_expr(&strings(&["ipv6-nd"])), nd);
        assert_eq!(
            proto_expr(&strings(&["netbios"])),
            proto_expr(&strings(&["nbns"]))
        );
    }

    #[test]
    fn proto_names_ignore_case() {
        assert_eq!(
            proto_expr(&strings(&["DHCP,MdNs"])),
            proto_expr(&strings(&["dhcp,mdns"]))
        );
        assert_eq!(
            proto_expr(&strings(&["NetBIOS", "IPv6-ND"])),
            proto_expr(&strings(&["nbns,nd"]))
        );
    }

    #[test]
    fn proto_duplicates_count_once_in_table_order() {
        let want = proto_expr(&strings(&["dhcp,mdns"]));
        assert_eq!(proto_expr(&strings(&["mdns,dhcp"])), want);
        assert_eq!(proto_expr(&strings(&["mdns", "dhcp,MDNS", "dhcp"])), want);
        assert_eq!(
            proto_expr(&strings(&["stp,nd,ndp,ipv6-nd,arp"])),
            Ok("(arp) or (icmp6 and ip6[40] >= 133 and ip6[40] <= 137) or (ether dst 01:80:c2:00:00:00)".to_owned())
        );
    }

    #[test]
    fn unknown_proto_names_the_known_ones() {
        assert_eq!(
            proto_expr(&strings(&["xyz"])),
            Err(format!("unknown protocol \"xyz\" {KNOWN}"))
        );
        assert_eq!(
            proto_expr(&strings(&["dhcp", "mdns,Bogus"])),
            Err(format!("unknown protocol \"Bogus\" {KNOWN}"))
        );
        assert_eq!(
            build_filter(&strings(&["xyz"]), &strings(&["udp"])),
            Err(format!("unknown protocol \"xyz\" {KNOWN}"))
        );
    }

    #[test]
    fn empty_proto_name_is_refused() {
        for v in [
            &[""][..],
            &["dhcp,"],
            &[",mdns"],
            &["dhcp,,mdns"],
            &["dhcp", ""],
        ] {
            assert_eq!(
                proto_expr(&strings(v)),
                Err(format!("empty protocol name {KNOWN}")),
                "{v:?}"
            );
        }
        assert_eq!(proto_expr(&[]), Err(format!("empty protocol name {KNOWN}")));
    }

    #[test]
    fn proto_and_user_words_narrow_every_arm() {
        assert_eq!(
            build_filter(&strings(&["dhcp"]), &strings(&["host", "192.168.1.1"])),
            Ok(arms_with(
                "((udp port 67 or udp port 68)) and (host 192.168.1.1)"
            ))
        );
    }

    #[test]
    fn filters_compile() {
        let compiles = |protos: &[&str], user: &[&str]| {
            let f = build_filter(&strings(protos), &strings(user)).expect("filter");
            check_filter(&f).unwrap_or_else(|e| panic!("{protos:?} {user:?}: {e}"));
        };
        compiles(&[], &[]);
        compiles(&[], &["host", "10.0.0.1"]);
        // Words every protocol can meet: libpcap refuses a filter that can
        // match nothing, such as nd (IPv6) with an IPv4 host.
        for name in [
            "arp", "dhcp", "nd", "mdns", "llmnr", "nbns", "ssdp", "lldp", "cdp", "stp",
        ] {
            compiles(&[name], &[]);
            compiles(&[name], &["ether", "host", "02:00:5e:10:00:01"]);
        }
        compiles(&["arp,dhcp,nd,mdns,llmnr,nbns,ssdp,lldp,cdp,stp"], &[]);
        compiles(
            &["arp,dhcp,nd,mdns,llmnr,nbns,ssdp,lldp,cdp,stp"],
            &["not", "ether", "src", "02:00:5e:10:00:01"],
        );
    }
}
