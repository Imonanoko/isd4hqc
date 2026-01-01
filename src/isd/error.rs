#[derive(Debug, thiserror::Error)]
pub enum HqcParamError {
    #[error("invalid n (must be >= 2): {0}")]
    InvalidN(usize),
    #[error("invalid w (must be >= 1): {0}")]
    InvalidW(usize),
    #[error("weight must be < n, got w={w}, n={n}")]
    WeightTooLarge { n: usize, w: usize },
    #[error("n too small for meaningful ISD experiments: n={n}, w={w}")]
    TooDense { n: usize, w: usize },
    #[error("n exceeds u32 range; current rand_bits uses u32: n={0}")]
    NTooLargeForU32(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum HqcKeygenError {
    #[error("params invalid: {0}")]
    InvalidParams(#[from] HqcParamError),
    #[error("generated vector has wrong length (expected {expected}, got {got})")]
    WrongLength { expected: usize, got: usize },
    #[error("generated vector has wrong weight (expected {expected}, got {got})")]
    WrongWeight { expected: usize, got: usize },
    #[error("key equation check failed: s != x ⊕ h·y")]
    EquationFailed,
}
