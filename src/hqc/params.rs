pub trait HqcPkeParams: Clone + Copy + 'static {
    const N1: usize;
    const N2: usize;
    const N1N2: usize = Self::N1 * Self::N2;
    const N: usize;
    const K: usize;
    const W: usize;
    const W_R: usize;
    const W_E: usize;
    const SEED_BYTES: usize = 32;
}

#[derive(Clone, Copy, Debug)]
pub struct Hqc1Params;
impl HqcPkeParams for Hqc1Params {
    const N1: usize = 46;
    const N2: usize = 384;
    const N: usize = 17669;
    const K: usize = 128;
    const W: usize = 66;
    const W_R: usize = 75;
    const W_E: usize = 75;
}