use crate::hqc::hash::I;
use crate::hqc::hash::xof::Shake256Xof;
use crate::hqc::hqcgf2::HqcGf2;
use crate::hqc::sampling::{sample_fixed_weight_vect, sample_vect};
use crate::hqc::types::Seed32;
use super::error::{HqcParamError, HqcKeygenError};

pub struct HqcExperimentParams {
    pub n: usize,
    pub w: usize,
}
/// hqc-1 n/w = 267.7
/// hqc-3 n/w = 358.5
/// hqc-5 n/w = 440.0
impl HqcExperimentParams {
    pub fn new(n: usize, w: usize) -> Self {
        Self { n, w }
    }
    pub fn validate(&self) -> Result<(), HqcParamError> {
        if self.n < 2 { return Err(HqcParamError::InvalidN(self.n)); }
        if self.w < 1 { return Err(HqcParamError::InvalidW(self.w)); }
        if self.w >= self.n {
            return Err(HqcParamError::WeightTooLarge { n: self.n, w: self.w });
        }

        if self.n > (u32::MAX as usize) {
            return Err(HqcParamError::NTooLargeForU32(self.n));
        }

        if self.n < self.w * 10 {
            return Err(HqcParamError::TooDense { n: self.n, w: self.w });
        }

        Ok(())
    }
    pub fn sparse_parameters_hqc_1(w: usize) -> Self {
        Self {
            n: w * 2677 / 10,
            w,
        }
    }

    pub fn sparse_parameters_hqc_3(w: usize) -> Self {
        Self {
            n: w * 3585 / 10,
            w,
        }
    }
    pub fn sparse_parameters_hqc_5(w: usize) -> Self {
        Self {
            n: w * 4400 / 10,
            w,
        }
    }
    pub fn hqc_1() -> Self {
        Self::new(17669, 66)
    }
    pub fn hqc_3() -> Self {
        Self::new(35851, 100)
    }
    pub fn hqc_5() -> Self {
        Self::new(57637, 131)
    }
    pub fn keygen(&self, seed_pke: Seed32) -> Result<HqcKeyRecoveryInstance, HqcKeygenError> {
        self.validate()?;
        let i_out = I(&[seed_pke.as_slice()]);
        let mut seed_dk = [0u8; 32];
        let mut seed_ek = [0u8; 32];
        seed_dk.copy_from_slice(&i_out[..32]);
        seed_ek.copy_from_slice(&i_out[32..64]);
        let ctx_dk = Shake256Xof::new(&seed_dk);
        let y = sample_fixed_weight_vect(self.n, self.w, &ctx_dk);
        let x = sample_fixed_weight_vect(self.n, self.w, &ctx_dk);
        let ctx_ek = Shake256Xof::new(&seed_ek);
        let h = sample_vect(self.n, &ctx_ek);
        let hy = h.mul_bitpacked(&y);
        let mut s_vec = x.clone();
        s_vec.xor_in_place(&hy);
        let out = HqcKeyRecoveryInstance { y, x, h, s: s_vec };
        out.verify(self)?;
        Ok(out)
    }
}
pub struct HqcKeyRecoveryInstance {
    y: HqcGf2,
    x: HqcGf2,
    h: HqcGf2,
    s: HqcGf2,
}

impl HqcKeyRecoveryInstance {
    fn verify(&self, p: &HqcExperimentParams) -> Result<(), HqcKeygenError> {
        for (name, v) in [("x", &self.x), ("y", &self.y), ("h", &self.h), ("s", &self.s)] {
            if v.n != p.n {
                return Err(HqcKeygenError::WrongLength { name: name.to_string(), expected: p.n, got: v.n });
            }
        }
        let wx = self.x.weight() as usize;
        let wy = self.y.weight() as usize;
        if wx != p.w {
            return Err(HqcKeygenError::WrongWeight { name: "x".to_string(), expected: p.w, got: wx });
        }
        if wy != p.w {
            return Err(HqcKeygenError::WrongWeight { name: "y".to_string(), expected: p.w, got: wy });
        }
        let hy = self.h.mul_bitpacked(&self.y);
        let mut rhs = self.x.clone();
        rhs.xor_in_place(&hy);

        if rhs != self.s {
            return Err(HqcKeygenError::EquationFailed);
        }

        Ok(())
    }
    pub fn get_public_key(&self) -> (&HqcGf2, &HqcGf2) {
        (&self.h, &self.s)
    }
}