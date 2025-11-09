use super::Domain;
use sha3::{Shake256,digest::{Update,ExtendableOutput,XofReader}};

pub struct Shake256Xof(Shake256);

impl Shake256Xof {
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut s = Shake256::default();
        s.update(seed);
        s.update(Domain::Xof.label());
        Self(s)
    }
    pub(crate) fn get_bytes(&self, len:usize) -> Vec<u8> {
        let mut r = self.0.clone().finalize_xof();
        let mut out = vec![0u8; len];
        r.read(&mut out);
        out
    }
}