#![allow(dead_code)]

use core::marker::PhantomData;

use super::params::HqcPkeParams;

/// Fixed-size primitives (spec-defined)
pub type Seed32 = [u8; 32];
pub type Salt16 = [u8; 16];
pub type SharedKey32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypesError {
    InvalidLength { expected: usize, got: usize },
    InvalidFormat(&'static str),
}

/// HQC-PKE encryption key: ekPKE = (seedPKE.ek, s)
/// Layout (bytes): seed_ek (32) || s (ceil(n/8))
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EkPke<P: HqcPkeParams> {
    pub seed_ek: Seed32,
    pub s: Vec<u8>, // len = P::N_BYTES
    _pd: PhantomData<P>,
}

impl<P: HqcPkeParams> EkPke<P> {
    pub fn new(seed_ek: Seed32, s: Vec<u8>) -> Result<Self, TypesError> {
        if s.len() != P::N_BYTES {
            return Err(TypesError::InvalidLength {
                expected: P::N_BYTES,
                got: s.len(),
            });
        }
        Ok(Self {
            seed_ek,
            s,
            _pd: PhantomData,
        })
    }

    pub fn len_bytes() -> usize {
        P::SEED_BYTES + P::N_BYTES
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::len_bytes());
        out.extend_from_slice(&self.seed_ek);
        out.extend_from_slice(&self.s);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, TypesError> {
        if b.len() != Self::len_bytes() {
            return Err(TypesError::InvalidLength {
                expected: Self::len_bytes(),
                got: b.len(),
            });
        }
        let mut seed_ek = [0u8; 32];
        seed_ek.copy_from_slice(&b[..32]);
        let s = b[32..].to_vec();
        Self::new(seed_ek, s)
    }
}

/// HQC-PKE decryption key: dkPKE = seedPKE.dk (32 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkPke<P: HqcPkeParams> {
    pub seed_dk: Seed32,
    _pd: PhantomData<P>,
}

impl<P: HqcPkeParams> DkPke<P> {
    pub fn new(seed_dk: Seed32) -> Self {
        Self {
            seed_dk,
            _pd: PhantomData,
        }
    }

    pub fn len_bytes() -> usize {
        P::SEED_BYTES
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.seed_dk.to_vec()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, TypesError> {
        if b.len() != 32 {
            return Err(TypesError::InvalidLength {
                expected: 32,
                got: b.len(),
            });
        }
        let mut seed_dk = [0u8; 32];
        seed_dk.copy_from_slice(b);
        Ok(Self::new(seed_dk))
    }
}

/// HQC-PKE ciphertext: cPKE = (u, v)
/// Layout (bytes): u (ceil(n/8)) || v (ceil(n1*n2/8))
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphPke<P: HqcPkeParams> {
    pub u: Vec<u8>, // len = P::N_BYTES
    pub v: Vec<u8>, // len = P::N1N2_BYTES
    _pd: PhantomData<P>,
}

impl<P: HqcPkeParams> CiphPke<P> {
    pub fn new(u: Vec<u8>, v: Vec<u8>) -> Result<Self, TypesError> {
        if u.len() != P::N_BYTES {
            return Err(TypesError::InvalidLength {
                expected: P::N_BYTES,
                got: u.len(),
            });
        }
        if v.len() != P::N1N2_BYTES {
            return Err(TypesError::InvalidLength {
                expected: P::N1N2_BYTES,
                got: v.len(),
            });
        }
        Ok(Self {
            u,
            v,
            _pd: PhantomData,
        })
    }

    pub fn len_bytes() -> usize {
        P::C_PKE_BYTES
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::len_bytes());
        out.extend_from_slice(&self.u);
        out.extend_from_slice(&self.v);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, TypesError> {
        if b.len() != Self::len_bytes() {
            return Err(TypesError::InvalidLength {
                expected: Self::len_bytes(),
                got: b.len(),
            });
        }
        let u = b[..P::N_BYTES].to_vec();
        let v = b[P::N_BYTES..].to_vec();
        Self::new(u, v)
    }
}

/// HQC-KEM ekKEM is the same as ekPKE per spec.
pub type EkKem<P> = EkPke<P>;

/// HQC-KEM ciphertext: cKEM = (cPKE, salt)
/// Layout: cPKE (P::C_PKE_BYTES) || salt (16)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphKem<P: HqcPkeParams> {
    pub c_pke: CiphPke<P>,
    pub salt: Salt16,
}

impl<P: HqcPkeParams> CiphKem<P> {
    pub fn len_bytes() -> usize {
        P::C_KEM_BYTES
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::len_bytes());
        out.extend_from_slice(&self.c_pke.to_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, TypesError> {
        if b.len() != Self::len_bytes() {
            return Err(TypesError::InvalidLength {
                expected: Self::len_bytes(),
                got: b.len(),
            });
        }
        let c_pke = CiphPke::<P>::from_bytes(&b[..P::C_PKE_BYTES])?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[P::C_PKE_BYTES..P::C_PKE_BYTES + 16]);
        Ok(Self { c_pke, salt })
    }
}

/// HQC-KEM decapsulation key supports:
/// - default format: (ekKEM, dkPKE, sigma, seedKEM)
/// - compressed: (seedKEM)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkKem<P: HqcPkeParams> {
    Full {
        ek: EkKem<P>,
        dk_pke: DkPke<P>,
        sigma: Vec<u8>, // len = P::K_BYTES
        seed_kem: Seed32,
    },
    Compressed {
        seed_kem: Seed32,
    },
}

impl<P: HqcPkeParams> DkKem<P> {
    pub fn new_full(
        ek: EkKem<P>,
        dk_pke: DkPke<P>,
        sigma: Vec<u8>,
        seed_kem: Seed32,
    ) -> Result<Self, TypesError> {
        if sigma.len() != P::K_BYTES {
            return Err(TypesError::InvalidLength {
                expected: P::K_BYTES,
                got: sigma.len(),
            });
        }
        Ok(Self::Full {
            ek,
            dk_pke,
            sigma,
            seed_kem,
        })
    }

    pub fn new_compressed(seed_kem: Seed32) -> Self {
        Self::Compressed { seed_kem }
    }

    /// Full dkKEM bytes length per spec:
    /// |dkKEM| = |ekKEM| + |dkPKE| + |sigma| + |seedKEM|
    pub fn len_bytes_full() -> usize {
        EkKem::<P>::len_bytes() + DkPke::<P>::len_bytes() + P::K_BYTES + P::SEED_BYTES
    }

    pub fn len_bytes_compressed() -> usize {
        P::SEED_BYTES
    }

    pub fn to_bytes_full(&self) -> Result<Vec<u8>, TypesError> {
        match self {
            DkKem::Full {
                ek,
                dk_pke,
                sigma,
                seed_kem,
            } => {
                let mut out = Vec::with_capacity(Self::len_bytes_full());
                out.extend_from_slice(&ek.to_bytes());
                out.extend_from_slice(&dk_pke.to_bytes());
                out.extend_from_slice(sigma);
                out.extend_from_slice(seed_kem);
                Ok(out)
            }
            DkKem::Compressed { .. } => Err(TypesError::InvalidFormat(
                "called to_bytes_full() on compressed dkKEM",
            )),
        }
    }

    pub fn to_bytes_compressed(&self) -> Result<Vec<u8>, TypesError> {
        match self {
            DkKem::Compressed { seed_kem } => Ok(seed_kem.to_vec()),
            DkKem::Full { .. } => Err(TypesError::InvalidFormat(
                "called to_bytes_compressed() on full dkKEM",
            )),
        }
    }
}

/// Constant-time-ish equality for ciphertext checks (avoid early-exit branching).
/// (Not a perfect side-channel proof, but better than == for this layer.)
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}
