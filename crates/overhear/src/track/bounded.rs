//! A list that keeps the newest `cap` distinct items.

#[derive(Debug)]
pub struct Bounded<T> {
    items: Vec<T>,
    cap: usize,
}

impl<T: PartialEq> Bounded<T> {
    pub fn new(cap: usize) -> Self {
        Bounded {
            items: Vec::new(),
            cap,
        }
    }

    /// Adds `item` as the newest. An equal item already present moves to the
    /// newest position; when full, the oldest is dropped.
    pub fn push(&mut self, item: T) {
        if let Some(i) = self.items.iter().position(|x| *x == item) {
            self.items.remove(i);
        } else if self.items.len() >= self.cap && !self.items.is_empty() {
            self.items.remove(0);
        }
        if self.cap > 0 {
            self.items.push(item);
        }
    }

    /// Oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_oldest_and_moves_repeats() {
        let mut b = Bounded::new(3);
        for i in 1..=3 {
            b.push(i);
        }
        b.push(1);
        assert_eq!(b.iter().copied().collect::<Vec<_>>(), [2, 3, 1]);
        b.push(4);
        assert_eq!(b.iter().copied().collect::<Vec<_>>(), [3, 1, 4]);
        assert_eq!(b.len(), 3);
    }
}
