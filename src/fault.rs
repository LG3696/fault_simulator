#[derive(Clone, Copy, Debug)]
pub enum FaultType {
    /// A fault which skips `n` instructions
    Glitch(usize),
}
