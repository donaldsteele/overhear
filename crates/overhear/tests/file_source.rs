use std::path::PathBuf;

use overhear::file_source::FileSource;
use overhear::source::{Frame, LinkType, Next, Source, SourceError};
use overhear_testgen::{
    TFrame, write_pcap, write_pcap_linktype, write_pcap_snaplen, write_pcapng,
    write_pcapng_interfaces, write_pcapng_tsoffset,
};

fn tmp(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("file_source_{name}"))
}

fn sample() -> Vec<TFrame> {
    vec![
        TFrame {
            sec: 1795266131,
            usec: 204123,
            data: vec![0xaa; 60],
            orig_len: None,
        },
        TFrame {
            sec: 1795266132,
            usec: 0,
            data: vec![0xbb; 77],
            orig_len: None,
        },
        TFrame {
            sec: 1795266133,
            usec: 999999,
            data: vec![0xcc; 60],
            orig_len: Some(500),
        },
    ]
}

fn expect_frames(src: &mut FileSource, frames: &[TFrame]) {
    let mut f = Frame::default();
    for t in frames {
        assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
        assert_eq!(f.ts_sec, t.sec);
        assert_eq!(f.ts_usec, t.usec);
        assert_eq!(f.orig_len, t.orig_len.unwrap_or(t.data.len() as u32));
        assert_eq!(f.data, t.data);
    }
    assert!(matches!(src.next_into(&mut f), Ok(Next::End)));
}

#[test]
fn reads_pcap_frames_in_order() {
    let p = tmp("order.pcap");
    let frames = sample();
    write_pcap(&p, &frames).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    assert_eq!(src.link_type(), LinkType::Ethernet);
    expect_frames(&mut src, &frames);
}

#[test]
fn reads_pcapng() {
    let p = tmp("basic.pcapng");
    let frames = sample();
    write_pcapng(&p, &frames).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    assert_eq!(src.link_type(), LinkType::Ethernet);
    expect_frames(&mut src, &frames);
}

#[test]
fn reports_truncated_file() {
    for (name, ng) in [("trunc.pcap", false), ("trunc.pcapng", true)] {
        let p = tmp(name);
        let frames = sample();
        if ng {
            write_pcapng(&p, &frames).unwrap();
        } else {
            write_pcap(&p, &frames).unwrap();
        }
        let bytes = std::fs::read(&p).unwrap();
        std::fs::write(&p, &bytes[..bytes.len() - 5]).unwrap();
        let mut src = FileSource::open(&p).unwrap();
        let mut f = Frame::default();
        assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
        assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
        assert!(
            matches!(src.next_into(&mut f), Err(SourceError::Truncated(_))),
            "{name}"
        );
    }
}

#[test]
fn truncated_inside_record_header() {
    let p = tmp("trunc_hdr.pcap");
    let frames = sample();
    write_pcap(&p, &frames).unwrap();
    let bytes = std::fs::read(&p).unwrap();
    // cut leaves 5 bytes of the third record header
    let cut = bytes.len() - (16 + 60) + 5;
    std::fs::write(&p, &bytes[..cut]).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    let mut f = Frame::default();
    assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
    assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
    assert!(matches!(
        src.next_into(&mut f),
        Err(SourceError::Truncated(_))
    ));
}

#[test]
fn non_ethernet_link_type() {
    let p = tmp("linktype.pcap");
    write_pcap_linktype(&p, 101, &sample()).unwrap();
    let src = FileSource::open(&p).unwrap();
    assert_eq!(src.link_type(), LinkType::Other(101));
}

#[test]
fn reuses_buffer() {
    let p = tmp("reuse.pcap");
    let frames = vec![
        TFrame {
            sec: 1,
            usec: 1,
            data: vec![1; 1000],
            orig_len: None,
        },
        TFrame {
            sec: 2,
            usec: 2,
            data: vec![2; 60],
            orig_len: None,
        },
    ];
    write_pcap(&p, &frames).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    let mut f = Frame::default();
    assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
    assert_eq!(f.data.len(), 1000);
    assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
    assert_eq!(f.data.len(), 60);
    assert!(f.data.capacity() >= 1000);
}

#[test]
fn pcapng_tsoffset_is_not_applied() {
    let p = tmp("tsoffset.pcapng");
    let frames = sample();
    write_pcapng_tsoffset(&p, 3600, &frames).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    expect_frames(&mut src, &frames);
}

#[test]
fn reads_snaplen_cut_pcap() {
    let p = tmp("snaplen.pcap");
    let frames = vec![TFrame {
        sec: 5,
        usec: 6,
        data: vec![9; 96],
        orig_len: Some(1500),
    }];
    write_pcap_snaplen(&p, 96, &frames).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    let mut f = Frame::default();
    assert!(matches!(src.next_into(&mut f), Ok(Next::Frame)));
    assert_eq!(f.orig_len, 1500);
    assert_eq!(f.data.len(), 96);
    assert!(matches!(src.next_into(&mut f), Ok(Next::End)));
}

#[test]
fn pcapng_frames_on_two_interfaces() {
    let p = tmp("two_ifaces.pcapng");
    let a = TFrame {
        sec: 10,
        usec: 1,
        data: vec![1; 60],
        orig_len: None,
    };
    let b = TFrame {
        sec: 11,
        usec: 2,
        data: vec![2; 64],
        orig_len: None,
    };
    write_pcapng_interfaces(&p, 2, &[(0, a.clone()), (1, b.clone())]).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    expect_frames(&mut src, &[a, b]);
}

#[test]
fn pcapng_undefined_interface_is_an_error() {
    let p = tmp("bad_iface.pcapng");
    let a = TFrame {
        sec: 10,
        usec: 1,
        data: vec![1; 60],
        orig_len: None,
    };
    write_pcapng(&p, &[a]).unwrap();
    // SHB (28) + IDB (20), then the EPB: type, length, interface id.
    let mut bytes = std::fs::read(&p).unwrap();
    assert_eq!(bytes[48..52], 6u32.to_le_bytes());
    bytes[56..60].copy_from_slice(&3u32.to_le_bytes());
    std::fs::write(&p, bytes).unwrap();
    let mut src = FileSource::open(&p).unwrap();
    let mut f = Frame::default();
    assert!(matches!(
        src.next_into(&mut f),
        Err(SourceError::Unsupported(_))
    ));
}
