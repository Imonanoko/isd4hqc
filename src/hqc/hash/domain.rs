#[derive(Copy, Clone, Debug)]
pub(super) enum Domain {
    Xof,
    G,
    I,
    H,
    J,
}
impl Domain {
    #[inline]
    pub(super) fn label(self) -> &'static [u8] {
        match self {
            Domain::Xof => b"HQC/XOF",
            Domain::G => b"HQC/G",
            Domain::I => b"HQC/I",
            Domain::H => b"HQC/H",
            Domain::J => b"HQC/J",
        }
    }
}