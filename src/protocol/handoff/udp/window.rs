//! Sliding anti-replay window for native UDP channel counters.
//!
//! The construction is the RFC 6479 bitmap: the highest authenticated
//! counter plus a fixed window of earlier counters. A counter is accepted at
//! most once, counters older than the window are rejected, and reordering
//! inside the window is tolerated. [`ReplayWindow::check`] is cheap and runs
//! before AEAD open; [`ReplayWindow::commit`] runs only after the packet
//! authenticated, so a forgery can never advance or burn the window.

/// Counters tracked behind the highest accepted counter.
pub const REPLAY_WINDOW_BITS: u64 = 1024;

const WORDS: usize = (REPLAY_WINDOW_BITS / 64) as usize;

/// Per-direction receive replay state.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: [u64; WORDS],
}

impl ReplayWindow {
    /// An empty window; counter zero is never valid on the receive side.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; WORDS],
        }
    }

    /// Whether `counter` may still be accepted. Does not mutate state.
    #[must_use]
    pub fn check(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if counter > self.highest {
            return true;
        }
        let age = self.highest - counter;
        if age >= REPLAY_WINDOW_BITS {
            return false;
        }
        let (word, bit) = Self::slot(counter);
        self.bitmap[word] & (1 << bit) == 0
    }

    /// Records an authenticated counter. Returns `false` (and changes nothing)
    /// when the counter is a replay or too old.
    pub fn commit(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        if counter > self.highest {
            let advance = counter - self.highest;
            if advance >= REPLAY_WINDOW_BITS {
                self.bitmap = [0; WORDS];
            } else {
                // Clear every slot between the old and the new highest.
                let mut cleared = self.highest + 1;
                while cleared < counter {
                    let (word, bit) = Self::slot(cleared);
                    self.bitmap[word] &= !(1 << bit);
                    cleared += 1;
                }
            }
            self.highest = counter;
        }
        let (word, bit) = Self::slot(counter);
        self.bitmap[word] |= 1 << bit;
        true
    }

    /// The highest authenticated counter so far.
    #[must_use]
    pub const fn highest(&self) -> u64 {
        self.highest
    }

    const fn slot(counter: u64) -> (usize, u32) {
        let index = counter % REPLAY_WINDOW_BITS;
        ((index / 64) as usize, (index % 64) as u32)
    }
}
