/// A bounds-checked reader over a region of a frame.
/// All positions are absolute offsets into the frame.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    frame: &'a [u8],
    start: usize,
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(frame: &'a [u8]) -> Self {
        Cursor {
            frame,
            start: 0,
            pos: 0,
            end: frame.len(),
        }
    }

    pub fn start(&self) -> usize {
        self.start
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn frame(&self) -> &'a [u8] {
        self.frame
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let next = self.pos.checked_add(n)?;
        if next > self.end {
            return None;
        }
        let s = self.frame.get(self.pos..next)?;
        self.pos = next;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub fn be16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes(b.try_into().ok()?))
    }

    pub fn be32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes(b.try_into().ok()?))
    }

    pub fn peek_u8(&self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        self.frame.get(self.pos).copied()
    }

    /// Consumes everything left.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = self.frame.get(self.pos..self.end).unwrap_or(&[]);
        self.pos = self.end;
        s
    }

    /// Child cursor over the next `n` bytes, consumed from `self`.
    pub fn sub(&mut self, n: usize) -> Option<Cursor<'a>> {
        let from = self.pos;
        let next = from.checked_add(n)?;
        if next > self.end {
            return None;
        }
        self.pos = next;
        Some(Cursor {
            frame: self.frame,
            start: from,
            pos: from,
            end: next,
        })
    }

    /// New cursor at absolute `pos` over the same region.
    pub fn at(&self, pos: usize) -> Option<Cursor<'a>> {
        if pos < self.start || pos > self.end {
            return None;
        }
        Some(Cursor {
            frame: self.frame,
            start: self.start,
            pos,
            end: self.end,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_and_tracks_absolute_positions() {
        let b = [1u8, 2, 3, 4, 5, 6, 7];
        let mut c = Cursor::new(&b);
        assert_eq!(c.u8(), Some(1));
        assert_eq!(c.be16(), Some(0x0203));
        let mut s = c.sub(3).unwrap();
        assert_eq!((s.start(), s.pos(), s.remaining()), (3, 3, 3));
        assert_eq!(s.be32(), None);
        assert_eq!(s.pos(), 3);
        assert_eq!(c.pos(), 6);
        assert_eq!(c.take(2), None);
        assert_eq!(c.rest(), &[7]);
        assert!(c.is_empty());
    }

    #[test]
    fn huge_lengths_never_panic_or_move() {
        let b = [0u8; 4];
        let mut c = Cursor::new(&b);
        assert_eq!(c.take(usize::MAX), None);
        assert_eq!(c.skip(usize::MAX), None);
        assert!(c.sub(5).is_none() && c.at(5).is_none());
        assert_eq!(c.pos(), 0);
    }

    #[test]
    fn at_stays_inside_region() {
        let b = [0u8; 10];
        let mut c = Cursor::new(&b);
        c.skip(2).unwrap();
        let s = c.sub(4).unwrap();
        assert!(s.at(1).is_none());
        assert_eq!(s.at(2).unwrap().remaining(), 4);
        assert_eq!(s.at(6).unwrap().remaining(), 0);
        assert!(s.at(7).is_none());
    }

    #[test]
    fn peek_does_not_move() {
        let b = [9u8];
        let mut c = Cursor::new(&b);
        assert_eq!(c.peek_u8(), Some(9));
        assert_eq!(c.pos(), 0);
        c.u8().unwrap();
        assert_eq!(c.peek_u8(), None);
    }
}
