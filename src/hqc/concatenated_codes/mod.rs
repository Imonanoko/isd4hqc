pub mod reed_solomon;
pub mod reed_muller;
pub use reed_solomon::*;
pub use reed_muller::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RmrsError {
    InvalidLength { expected: usize, got: usize },
    Rm(ReedMullerError),
    Rs(RsError),
}

impl From<ReedMullerError> for RmrsError {
    fn from(e: ReedMullerError) -> Self {
        Self::Rm(e)
    }
}
impl From<RsError> for RmrsError {
    fn from(e: RsError) -> Self {
        Self::Rs(e)
    }
}

/// RMRS concatenated code used by HQC:
/// - Outer: shortened RS over GF(256) (n1,k1)
/// - Inner: duplicated RM(1,7) (n2,k2=8)
///
/// Parameters follow HQC spec tables for RS-S1/S2/S3 and duplicated RM codes. :contentReference[oaicite:4]{index=4}
#[derive(Debug, Clone)]
pub struct RmrsCode {
    pub rs: ReedSolomon,
    pub rm: ReedMuller,
}

impl RmrsCode {
    pub fn new(rs: ReedSolomon, rm_multiplicity: usize) -> Self {
        Self {
            rs,
            rm: ReedMuller::new(rm_multiplicity),
        }
    }

    /// Encode message (k1 bytes) into concatenated codeword (n1*n2 bits), packed into bytes.
    pub fn encode(&self, msg: &[u8]) -> Result<Vec<u8>, &'static str> {
        let rs_cw = self.rs.encode(msg)?; // n1 bytes
        let block_bytes = self.rm.n2_bytes();

        let mut out = Vec::with_capacity(rs_cw.len() * block_bytes);
        for &sym in &rs_cw {
            out.extend_from_slice(&self.rm.encode_symbol(sym));
        }
        Ok(out)
    }

    /// Decode concatenated codeword back to message (k1 bytes).
    pub fn decode(&self, cw: &[u8]) -> Result<Vec<u8>, RmrsError> {
        let block_bytes = self.rm.n2_bytes();
        let expected = self.rs.n * block_bytes;

        if cw.len() != expected {
            return Err(RmrsError::InvalidLength {
                expected,
                got: cw.len(),
            });
        }

        // Step 1: RM decode each block -> RS symbols
        let mut rs_recv = vec![0u8; self.rs.n];
        for i in 0..self.rs.n {
            let block = &cw[i * block_bytes..(i + 1) * block_bytes];
            rs_recv[i] = self.rm.decode_symbol(block)?;
        }

        // Step 2: RS decode -> message bytes
        Ok(self.rs.decode(&rs_recv)?)
    }
}