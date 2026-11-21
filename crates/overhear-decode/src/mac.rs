use core::fmt;

/// An Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Mac = Mac([0xff; 6]);

    pub fn is_broadcast(&self) -> bool {
        *self == Mac::BROADCAST
    }

    /// Group bit (includes broadcast).
    pub fn is_multicast(&self) -> bool {
        self.0.first().is_some_and(|b| b & 0x01 != 0)
    }

    /// Locally administered bit.
    pub fn is_local(&self) -> bool {
        self.0.first().is_some_and(|b| b & 0x02 != 0)
    }

    pub fn from_slice(b: &[u8]) -> Option<Mac> {
        let a: [u8; 6] = b.try_into().ok()?;
        Some(Mac(a))
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_and_formats() {
        let m = Mac([0x02, 0, 0x5e, 0x10, 0, 0x14]);
        assert!(m.is_local() && !m.is_multicast() && !m.is_broadcast());
        assert_eq!(m.to_string(), "02:00:5e:10:00:14");
        assert!(Mac::BROADCAST.is_broadcast() && Mac::BROADCAST.is_multicast());
        assert!(Mac([0x01, 0, 0x5e, 0, 0, 0xfb]).is_multicast());
        assert!(!Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).is_local());
        assert_eq!(Mac::from_slice(&[1, 2, 3]), None);
    }
}
