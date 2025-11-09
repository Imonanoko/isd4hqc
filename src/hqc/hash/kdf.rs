use super::{Domain, sha3_256_with_domain,sha3_512_with_domain};

pub(crate) fn G(parts: &[&[u8]]) -> [u8; 64] {
    sha3_512_with_domain(parts, Domain::G)
}

pub(crate) fn I(parts: &[&[u8]]) -> [u8; 64] {
    sha3_512_with_domain(parts, Domain::I)
}

pub(crate) fn H(parts: &[&[u8]]) -> [u8; 32] {
    sha3_256_with_domain(parts, Domain::H)
}

pub(crate) fn J(parts: &[&[u8]]) -> [u8; 32] {
    sha3_256_with_domain(parts, Domain::J)
}
