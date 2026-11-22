//! DHCP option registry data: names, value types and value checks.

use crate::Cursor;

/// How an option's value is shaped and displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptType {
    Text,
    Addr,
    Addrs,
    AddrMasks,
    Routes,
    U8,
    U16,
    U16s,
    Secs,
    SignedSecs,
    Enum,
    Hex,
    Prl,
    Fqdn,
    Relay,
    Arch,
    Ndi,
    CRoutes,
}

/// Option names transcribed from the IANA "BOOTP Vendor Extensions and DHCP
/// Options" registry, indexed by code. Where the registry lists several
/// entries for one code, the first is used. Codes the registry lists as plain
/// "Unassigned", or does not list, are `"unassigned"`; other labels such as
/// "REMOVED/Unassigned" and "Reserved (Private Use)" keep IANA's wording.
static NAMES: [&str; 256] = [
    "Pad",                                              // 0
    "Subnet Mask",                                      // 1
    "Time Offset",                                      // 2
    "Router",                                           // 3
    "Time Server",                                      // 4
    "Name Server",                                      // 5
    "Domain Server",                                    // 6
    "Log Server",                                       // 7
    "Quotes Server",                                    // 8
    "LPR Server",                                       // 9
    "Impress Server",                                   // 10
    "RLP Server",                                       // 11
    "Hostname",                                         // 12
    "Boot File Size",                                   // 13
    "Merit Dump File",                                  // 14
    "Domain Name",                                      // 15
    "Swap Server",                                      // 16
    "Root Path",                                        // 17
    "Extension File",                                   // 18
    "Forward On/Off",                                   // 19
    "SrcRte On/Off",                                    // 20
    "Policy Filter",                                    // 21
    "Max DG Assembly",                                  // 22
    "Default IP TTL",                                   // 23
    "MTU Timeout",                                      // 24
    "MTU Plateau",                                      // 25
    "MTU Interface",                                    // 26
    "MTU Subnet",                                       // 27
    "Broadcast Address",                                // 28
    "Mask Discovery",                                   // 29
    "Mask Supplier",                                    // 30
    "Router Discovery",                                 // 31
    "Router Request",                                   // 32
    "Static Route",                                     // 33
    "Trailers",                                         // 34
    "ARP Timeout",                                      // 35
    "Ethernet",                                         // 36
    "Default TCP TTL",                                  // 37
    "Keepalive Time",                                   // 38
    "Keepalive Data",                                   // 39
    "NIS Domain",                                       // 40
    "NIS Servers",                                      // 41
    "NTP Servers",                                      // 42
    "Vendor Specific",                                  // 43
    "NETBIOS Name Srv",                                 // 44
    "NETBIOS Dist Srv",                                 // 45
    "NETBIOS Node Type",                                // 46
    "NETBIOS Scope",                                    // 47
    "X Window Font",                                    // 48
    "X Window Manager",                                 // 49
    "Address Request",                                  // 50
    "Address Time",                                     // 51
    "Overload",                                         // 52
    "DHCP Msg Type",                                    // 53
    "DHCP Server Id",                                   // 54
    "Parameter List",                                   // 55
    "DHCP Message",                                     // 56
    "DHCP Max Msg Size",                                // 57
    "Renewal Time",                                     // 58
    "Rebinding Time",                                   // 59
    "Class Id",                                         // 60
    "Client Id",                                        // 61
    "NetWare/IP Domain",                                // 62
    "NetWare/IP Option",                                // 63
    "NIS-Domain-Name",                                  // 64
    "NIS-Server-Addr",                                  // 65
    "Server-Name",                                      // 66
    "Bootfile-Name",                                    // 67
    "Home-Agent-Addrs",                                 // 68
    "SMTP-Server",                                      // 69
    "POP3-Server",                                      // 70
    "NNTP-Server",                                      // 71
    "WWW-Server",                                       // 72
    "Finger-Server",                                    // 73
    "IRC-Server",                                       // 74
    "StreetTalk-Server",                                // 75
    "STDA-Server",                                      // 76
    "User-Class",                                       // 77
    "Directory Agent",                                  // 78
    "Service Scope",                                    // 79
    "Rapid Commit",                                     // 80
    "Client FQDN",                                      // 81
    "Relay Agent Information",                          // 82
    "iSNS",                                             // 83
    "REMOVED/Unassigned",                               // 84
    "NDS Servers",                                      // 85
    "NDS Tree Name",                                    // 86
    "NDS Context",                                      // 87
    "BCMCS Controller Domain Name list",                // 88
    "BCMCS Controller IPv4 address option",             // 89
    "Authentication",                                   // 90
    "client-last-transaction-time option",              // 91
    "associated-ip option",                             // 92
    "Client System",                                    // 93
    "Client NDI",                                       // 94
    "LDAP",                                             // 95
    "REMOVED/Unassigned",                               // 96
    "UUID/GUID",                                        // 97
    "User-Auth",                                        // 98
    "GEOCONF_CIVIC",                                    // 99
    "PCode",                                            // 100
    "TCode",                                            // 101
    "unassigned",                                       // 102
    "unassigned",                                       // 103
    "unassigned",                                       // 104
    "unassigned",                                       // 105
    "unassigned",                                       // 106
    "unassigned",                                       // 107
    "IPv6-Only Preferred",                              // 108
    "OPTION_DHCP4O6_S46_SADDR",                         // 109
    "REMOVED/Unassigned",                               // 110
    "unassigned",                                       // 111
    "Netinfo Address",                                  // 112
    "Netinfo Tag",                                      // 113
    "DHCP Captive-Portal",                              // 114
    "REMOVED/Unassigned",                               // 115
    "Auto-Config",                                      // 116
    "Name Service Search",                              // 117
    "Subnet Selection Option",                          // 118
    "Domain Search",                                    // 119
    "SIP Servers DHCP Option",                          // 120
    "Classless Static Route Option",                    // 121
    "CCC",                                              // 122
    "GeoConf Option",                                   // 123
    "V-I Vendor Class",                                 // 124
    "V-I Vendor-Specific Information",                  // 125
    "Removed/Unassigned",                               // 126
    "Removed/Unassigned",                               // 127
    "PXE - undefined (vendor specific)",                // 128
    "PXE - undefined (vendor specific)",                // 129
    "PXE - undefined (vendor specific)",                // 130
    "PXE - undefined (vendor specific)",                // 131
    "PXE - undefined (vendor specific)",                // 132
    "PXE - undefined (vendor specific)",                // 133
    "PXE - undefined (vendor specific)",                // 134
    "PXE - undefined (vendor specific)",                // 135
    "OPTION_PANA_AGENT",                                // 136
    "OPTION_V4_LOST",                                   // 137
    "OPTION_CAPWAP_AC_V4",                              // 138
    "OPTION-IPv4_Address-MoS",                          // 139
    "OPTION-IPv4_FQDN-MoS",                             // 140
    "SIP UA Configuration Service Domains",             // 141
    "OPTION-IPv4_Address-ANDSF",                        // 142
    "OPTION_V4_SZTP_REDIRECT",                          // 143
    "GeoLoc",                                           // 144
    "FORCERENEW_NONCE_CAPABLE",                         // 145
    "RDNSS Selection",                                  // 146
    "OPTION_V4_DOTS_RI",                                // 147
    "OPTION_V4_DOTS_ADDRESS",                           // 148
    "unassigned",                                       // 149
    "TFTP server address",                              // 150
    "status-code",                                      // 151
    "base-time",                                        // 152
    "start-time-of-state",                              // 153
    "query-start-time",                                 // 154
    "query-end-time",                                   // 155
    "dhcp-state",                                       // 156
    "data-source",                                      // 157
    "OPTION_V4_PCP_SERVER",                             // 158
    "OPTION_V4_PORTPARAMS",                             // 159
    "unassigned",                                       // 160
    "OPTION_MUD_URL_V4",                                // 161
    "OPTION_V4_DNR",                                    // 162
    "unassigned",                                       // 163
    "unassigned",                                       // 164
    "unassigned",                                       // 165
    "unassigned",                                       // 166
    "unassigned",                                       // 167
    "unassigned",                                       // 168
    "unassigned",                                       // 169
    "unassigned",                                       // 170
    "unassigned",                                       // 171
    "unassigned",                                       // 172
    "unassigned",                                       // 173
    "unassigned",                                       // 174
    "Etherboot (Tentatively Assigned - 2005-06-23)",    // 175
    "IP Telephone (Tentatively Assigned - 2005-06-23)", // 176
    "Etherboot (Tentatively Assigned - 2005-06-23)",    // 177
    "unassigned",                                       // 178
    "unassigned",                                       // 179
    "unassigned",                                       // 180
    "unassigned",                                       // 181
    "unassigned",                                       // 182
    "unassigned",                                       // 183
    "unassigned",                                       // 184
    "unassigned",                                       // 185
    "unassigned",                                       // 186
    "unassigned",                                       // 187
    "unassigned",                                       // 188
    "unassigned",                                       // 189
    "unassigned",                                       // 190
    "unassigned",                                       // 191
    "unassigned",                                       // 192
    "unassigned",                                       // 193
    "unassigned",                                       // 194
    "unassigned",                                       // 195
    "unassigned",                                       // 196
    "unassigned",                                       // 197
    "unassigned",                                       // 198
    "unassigned",                                       // 199
    "unassigned",                                       // 200
    "unassigned",                                       // 201
    "unassigned",                                       // 202
    "unassigned",                                       // 203
    "unassigned",                                       // 204
    "unassigned",                                       // 205
    "unassigned",                                       // 206
    "unassigned",                                       // 207
    "PXELINUX Magic",                                   // 208
    "Configuration File",                               // 209
    "Path Prefix",                                      // 210
    "Reboot Time",                                      // 211
    "OPTION_6RD",                                       // 212
    "OPTION_V4_ACCESS_DOMAIN",                          // 213
    "unassigned",                                       // 214
    "unassigned",                                       // 215
    "unassigned",                                       // 216
    "unassigned",                                       // 217
    "unassigned",                                       // 218
    "unassigned",                                       // 219
    "Subnet Allocation Option",                         // 220
    "Virtual Subnet Selection (VSS) Option",            // 221
    "unassigned",                                       // 222
    "unassigned",                                       // 223
    "Reserved (Private Use)",                           // 224
    "Reserved (Private Use)",                           // 225
    "Reserved (Private Use)",                           // 226
    "Reserved (Private Use)",                           // 227
    "Reserved (Private Use)",                           // 228
    "Reserved (Private Use)",                           // 229
    "Reserved (Private Use)",                           // 230
    "Reserved (Private Use)",                           // 231
    "Reserved (Private Use)",                           // 232
    "Reserved (Private Use)",                           // 233
    "Reserved (Private Use)",                           // 234
    "Reserved (Private Use)",                           // 235
    "Reserved (Private Use)",                           // 236
    "Reserved (Private Use)",                           // 237
    "Reserved (Private Use)",                           // 238
    "Reserved (Private Use)",                           // 239
    "Reserved (Private Use)",                           // 240
    "Reserved (Private Use)",                           // 241
    "Reserved (Private Use)",                           // 242
    "Reserved (Private Use)",                           // 243
    "Reserved (Private Use)",                           // 244
    "Reserved (Private Use)",                           // 245
    "Reserved (Private Use)",                           // 246
    "Reserved (Private Use)",                           // 247
    "Reserved (Private Use)",                           // 248
    "Reserved (Private Use)",                           // 249
    "Reserved (Private Use)",                           // 250
    "Reserved (Private Use)",                           // 251
    "Reserved (Private Use)",                           // 252
    "Reserved (Private Use)",                           // 253
    "Reserved (Private Use)",                           // 254
    "End",                                              // 255
];

/// The registry name of `code`.
pub fn option_name(code: u8) -> &'static str {
    NAMES
        .get(usize::from(code))
        .copied()
        .unwrap_or("unassigned")
}

pub fn option_type(code: u8) -> OptType {
    match code {
        1 | 16 | 28 | 32 | 50 | 54 | 118 => OptType::Addr,
        3..=11 | 41 | 42 | 44 | 45 | 48 | 49 | 65 | 68..=76 | 78 | 85 | 92 | 148 | 150 | 162 => {
            OptType::Addrs
        }
        21 => OptType::AddrMasks,
        33 => OptType::Routes,
        13 | 22 | 26 | 57 => OptType::U16,
        25 => OptType::U16s,
        23 | 37 | 145 => OptType::U8,
        19 | 20 | 27 | 29 | 30 | 31 | 34 | 36 | 39 | 46 | 52 | 53 | 116 => OptType::Enum,
        24 | 35 | 38 | 51 | 58 | 59 | 91 | 108 | 152..=155 | 211 => OptType::Secs,
        2 => OptType::SignedSecs,
        63 => OptType::Hex,
        55 => OptType::Prl,
        81 => OptType::Fqdn,
        82 => OptType::Relay,
        93 => OptType::Arch,
        94 => OptType::Ndi,
        121 | 249 => OptType::CRoutes,
        _ => OptType::Text,
    }
}

fn multiple(len: usize, n: usize) -> bool {
    len.checked_rem(n) == Some(0)
}

/// A value made of whole elements of `size` bytes: shorter than one element is
/// "too short", otherwise it must be a whole number of elements.
fn elements(len: usize, size: usize) -> Result<(), &'static str> {
    if len < size {
        return Err("too short");
    }
    if multiple(len, size) {
        return Ok(());
    }
    Err(match size {
        8 => "length not a multiple of 8",
        4 => "length not a multiple of 4",
        _ => "length not a multiple of 2",
    })
}

fn min_len(len: usize, min: usize) -> Result<(), &'static str> {
    if len < min { Err("too short") } else { Ok(()) }
}

/// Classless route list: width, significant destination octets, router.
fn classless_routes(data: &[u8]) -> Result<(), &'static str> {
    min_len(data.len(), 5)?;
    let mut c = Cursor::new(data);
    while let Some(width) = c.u8() {
        if width > 32 {
            return Err("bad route encoding");
        }
        let octets = usize::from(width).div_ceil(8);
        if c.skip(octets).is_none() || c.skip(4).is_none() {
            return Err("bad route encoding");
        }
    }
    Ok(())
}

/// Checks that `data` has a length and shape valid for the option's type.
/// Scalar types accept whole multiples of their size.
pub fn check(code: u8, data: &[u8]) -> Result<(), &'static str> {
    let n = data.len();
    match option_type(code) {
        OptType::Addr | OptType::Addrs | OptType::Secs | OptType::SignedSecs => elements(n, 4),
        OptType::AddrMasks | OptType::Routes => elements(n, 8),
        OptType::U16 | OptType::U16s | OptType::Arch => elements(n, 2),
        OptType::U8 | OptType::Enum | OptType::Text | OptType::Hex | OptType::Prl => min_len(n, 1),
        OptType::Fqdn => min_len(n, 3),
        OptType::Relay => min_len(n, 2),
        OptType::Ndi => min_len(n, 3),
        OptType::CRoutes => classless_routes(data),
    }
}

/// Name of an enumerated option value, where one is defined.
pub fn enum_name(code: u8, value: u8) -> Option<&'static str> {
    match code {
        53 => [
            "DISCOVER",
            "OFFER",
            "REQUEST",
            "DECLINE",
            "ACK",
            "NAK",
            "RELEASE",
            "INFORM",
            "FORCERENEW",
            "LEASEQUERY",
            "LEASEUNASSIGNED",
            "LEASEUNKNOWN",
            "LEASEACTIVE",
            "BULKLEASEQUERY",
            "LEASEQUERYDONE",
            "ACTIVELEASEQUERY",
            "LEASEQUERYSTATUS",
            "TLS",
        ]
        .get(usize::from(value).checked_sub(1)?)
        .copied(),
        52 => match value {
            1 => Some("file"),
            2 => Some("sname"),
            3 => Some("both"),
            _ => None,
        },
        46 => match value {
            1 => Some("B-node"),
            2 => Some("P-node"),
            4 => Some("M-node"),
            8 => Some("H-node"),
            _ => None,
        },
        _ => match value {
            0 => Some("disabled"),
            1 => Some("enabled"),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        assert_eq!(
            check(6, &[8, 8, 8, 8, 4, 4]),
            Err("length not a multiple of 4")
        );
        assert_eq!(check(6, &[1, 2, 3]), Err("too short"));
        assert_eq!(check(121, &[33, 10, 0, 0, 1]), Err("bad route encoding"));
        assert_eq!(check(1, &[255, 255, 255, 0]), Ok(()));
        assert_eq!(check(121, &[24, 10, 0, 1, 192, 168, 1, 1]), Ok(()));
        assert_eq!(check(121, &[0, 192, 168, 1, 1]), Ok(()));
        assert_eq!(check(121, &[24, 10, 0, 1, 192]), Err("bad route encoding"));
        assert_eq!(check(121, &[24, 10]), Err("too short"));
        assert_eq!(check(33, &[0; 12]), Err("length not a multiple of 8"));
        assert_eq!(check(25, &[0; 3]), Err("length not a multiple of 2"));
        assert_eq!(check(25, &[0]), Err("too short"));
        assert_eq!(check(12, &[]), Err("too short"));
        assert_eq!(check(53, &[1]), Ok(()));
    }

    #[test]
    fn names_and_types() {
        assert_eq!(option_name(53), "DHCP Msg Type");
        assert_eq!(option_name(0), "Pad");
        assert_eq!(option_name(121), "Classless Static Route Option");
        assert_eq!(option_name(111), "unassigned");
        assert_eq!(option_name(200), "unassigned");
        assert_eq!(option_name(255), "End");
        assert_eq!(option_type(121), OptType::CRoutes);
        assert_eq!(option_type(53), OptType::Enum);
        assert_eq!(option_type(12), OptType::Text);
        assert_eq!(option_type(3), OptType::Addrs);
        assert_eq!(option_type(155), OptType::Secs);
    }

    #[test]
    fn enum_names() {
        assert_eq!(enum_name(53, 1), Some("DISCOVER"));
        assert_eq!(enum_name(53, 18), Some("TLS"));
        assert_eq!(enum_name(53, 0), None);
        assert_eq!(enum_name(53, 19), None);
        assert_eq!(enum_name(52, 3), Some("both"));
        assert_eq!(enum_name(46, 8), Some("H-node"));
        assert_eq!(enum_name(46, 3), None);
        assert_eq!(enum_name(19, 1), Some("enabled"));
        assert_eq!(enum_name(19, 0), Some("disabled"));
        assert_eq!(enum_name(19, 2), None);
    }
}
