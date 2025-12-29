pub trait HqcPkeParams: Clone + Copy + 'static {
    const N1: usize;
    const N2: usize;
    const N: usize;
    const K: usize;
    const W: usize;
    const W_R: usize;
    const W_E: usize;
    const SEED_BYTES: usize = 32;
    const K_BYTES: usize = Self::K / 8;
    const N_BYTES: usize = (Self::N + 7) / 8;
    const N1N2_BITS: usize = Self::N1 * Self::N2;
    const N1N2_BYTES: usize = (Self::N1N2_BITS + 7) / 8;
    const N2_BYTES: usize = Self::N2 / 8;
    const C_PKE_BYTES: usize = Self::N_BYTES + Self::N1N2_BYTES;
    const SALT_BYTES: usize = 16;
    const SHARED_KEY_BYTES: usize = 32;
    const C_KEM_BYTES: usize = Self::C_PKE_BYTES + Self::SALT_BYTES;
    const RM_MULT: usize;
    const RS_GEN_POLY: &'static [u8];
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
    const RM_MULT: usize = 3;
    const RS_GEN_POLY: &'static [u8] = crate::hqc::concatenated_codes::reed_solomon::HQC_G1_POLY;
}

#[derive(Clone, Copy, Debug)]
pub struct Hqc3Params;
impl HqcPkeParams for Hqc3Params {
    const N1: usize = 56;
    const N2: usize = 640;
    const N: usize = 35851;
    const K: usize = 192;
    const W: usize = 100;
    const W_R: usize = 114;
    const W_E: usize = 114;
    const RM_MULT: usize = 5;
    const RS_GEN_POLY: &'static [u8] = crate::hqc::concatenated_codes::reed_solomon::HQC_G2_POLY;
}

#[derive(Clone, Copy, Debug)]
pub struct Hqc5Params;
impl HqcPkeParams for Hqc5Params {
    const N1: usize = 90;
    const N2: usize = 640;
    const N: usize = 57637;
    const K: usize = 256;
    const W: usize = 131;
    const W_R: usize = 149;
    const W_E: usize = 149;
    const RM_MULT: usize = 5;
    const RS_GEN_POLY: &'static [u8] = crate::hqc::concatenated_codes::reed_solomon::HQC_G3_POLY;
}