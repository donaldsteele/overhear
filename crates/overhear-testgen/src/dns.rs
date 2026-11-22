//! DNS message builder for generated test data (mDNS, LLMNR).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Record data the builder knows how to encode.
#[derive(Clone, Debug)]
pub enum RDataSpec {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    /// Priority 0, weight 0, the given port and target.
    Srv(u16, String),
    Txt(Vec<String>),
}

/// A DNS message with id 0 and the given questions and answers. Names are
/// compressed against earlier names unless `compress(false)` is set.
#[derive(Clone, Debug)]
pub struct DnsBuilder {
    id: u16,
    flags: u16,
    compress: bool,
    questions: Vec<(String, u16, u16)>,
    answers: Vec<(String, u16, u16, u32, RDataSpec)>,
}

impl DnsBuilder {
    pub fn new(flags: u16) -> Self {
        DnsBuilder {
            id: 0,
            flags,
            compress: true,
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    pub fn compress(mut self, on: bool) -> Self {
        self.compress = on;
        self
    }

    pub fn question(mut self, name: &str, qtype: u16, qclass: u16) -> Self {
        self.questions.push((name.to_string(), qtype, qclass));
        self
    }

    pub fn answer(
        mut self,
        name: &str,
        rtype: u16,
        class: u16,
        ttl: u32,
        rdata: RDataSpec,
    ) -> Self {
        self.answers
            .push((name.to_string(), rtype, class, ttl, rdata));
        self
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.id.to_be_bytes());
        o.extend_from_slice(&self.flags.to_be_bytes());
        o.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        o.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        o.extend_from_slice(&[0; 4]);
        let mut seen = HashMap::new();
        for (name, t, c) in &self.questions {
            self.put_name(&mut o, &mut seen, name);
            o.extend_from_slice(&t.to_be_bytes());
            o.extend_from_slice(&c.to_be_bytes());
        }
        for (name, t, c, ttl, rdata) in &self.answers {
            self.put_name(&mut o, &mut seen, name);
            o.extend_from_slice(&t.to_be_bytes());
            o.extend_from_slice(&c.to_be_bytes());
            o.extend_from_slice(&ttl.to_be_bytes());
            let len_at = o.len();
            o.extend_from_slice(&[0, 0]);
            match rdata {
                RDataSpec::A(a) => o.extend_from_slice(&a.octets()),
                RDataSpec::Aaaa(a) => o.extend_from_slice(&a.octets()),
                RDataSpec::Ptr(n) => self.put_name(&mut o, &mut seen, n),
                RDataSpec::Srv(port, n) => {
                    o.extend_from_slice(&[0, 0, 0, 0]);
                    o.extend_from_slice(&port.to_be_bytes());
                    self.put_name(&mut o, &mut seen, n);
                }
                RDataSpec::Txt(items) => {
                    for s in items {
                        o.push(s.len() as u8);
                        o.extend_from_slice(s.as_bytes());
                    }
                }
            }
            let n = (o.len() - len_at - 2) as u16;
            o[len_at..len_at + 2].copy_from_slice(&n.to_be_bytes());
        }
        o
    }

    fn put_name(&self, o: &mut Vec<u8>, seen: &mut HashMap<String, usize>, name: &str) {
        let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".").to_ascii_lowercase();
            if self.compress {
                if let Some(&at) = seen.get(&suffix) {
                    o.extend_from_slice(&(0xc000 | at as u16).to_be_bytes());
                    return;
                }
            }
            if o.len() < 0x3fff {
                seen.entry(suffix).or_insert(o.len());
            }
            o.push(labels[i].len() as u8);
            o.extend_from_slice(labels[i].as_bytes());
        }
        o.push(0);
    }
}
