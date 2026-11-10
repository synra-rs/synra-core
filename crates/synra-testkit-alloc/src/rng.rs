/// A deterministic pseudo-random source, for a fixture that must be reproducible.
///
/// Not a cryptographic generator and not pretending to be: a test failure has to be reproducible from its seed, so
/// the sequence must be a function of the seed and nothing else. A generator seeded from the clock is one whose
/// failure cannot be re-run.
#[derive(Debug, Clone)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// A generator from a seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        // A zero state is a fixed point of the mixing below, so it is replaced rather than accepted.
        Self { state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed } }
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        // splitmix64: the same mixing the reconnection jitter uses, so there is one generator in the codebase rather
        // than two that disagree about what "random" means.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A value below a bound, or zero when there is no room.
    #[must_use]
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    /// The seed this generator was built from.
    ///
    /// Reported so a failure can be re-run: a test that prints its seed is one whose failure is reproducible.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.state
    }
}
