use sha3::{Sha3_256, Sha3_512, Digest};
use super::Domain;

pub(super) fn sha3_256_with_domain(parts: &[&[u8]], domain: Domain) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts { h.update(p); }
    h.update(domain.label());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub(super) fn sha3_512_with_domain(parts: &[&[u8]], domain: Domain) -> [u8; 64] {
    let mut h = Sha3_512::new();
    for p in parts { h.update(p); }
    h.update(domain.label());
    let out = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}
