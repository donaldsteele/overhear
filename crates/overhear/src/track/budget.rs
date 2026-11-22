//! The one memory budget shared by everything that grows with the network.

#[derive(Debug)]
pub struct Budget {
    limit: usize,
    used: usize,
}

impl Budget {
    pub fn new(limit: usize) -> Self {
        Budget { limit, used: 0 }
    }

    /// Records that an item's cost went from `before` to `after`.
    pub fn adjust(&mut self, before: usize, after: usize) {
        self.used = self.used.saturating_sub(before).saturating_add(after);
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn over(&self) -> bool {
        self.used > self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjusts_and_reports_over() {
        let mut b = Budget::new(100);
        b.adjust(0, 60);
        assert!(!b.over());
        b.adjust(0, 41);
        assert!(b.over());
        b.adjust(41, 10);
        assert_eq!((b.used(), b.limit(), b.over()), (70, 100, false));
    }
}
