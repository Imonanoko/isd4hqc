//! Duplicated Reed–Muller code used by HQC (internal code).
//!
//! HQC uses RM(1, 7) = [128, 8, 64] and duplicates it:
//! - HQC-1: multiplicity = 3  => [384, 8, 192]
//! - HQC-3/5: multiplicity = 5 => [640, 8, 320]
//! See HQC specifications, Section "Duplicated Reed-Muller codes". :contentReference[oaicite:1]{index=1}
//!
//! Bit packing: big-endian within each byte (bit 0 = MSB).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReedMullerError {
    InvalidLength { expected: usize, got: usize },
}

/// Duplicated RM(1,7) code. Encodes one byte into n2 bits (packed in bytes).
#[derive(Debug, Clone)]
pub struct ReedMuller {
    /// Duplication factor (3 for HQC-1, 5 for HQC-3/5).
    pub multiplicity: usize,
}

impl ReedMuller {
    pub const RM_M: usize = 7;
    pub const RM_K_BITS: usize = 8;
    pub const RM_N_BITS: usize = 1 << Self::RM_M; // 128
    pub const RM_N_BYTES: usize = Self::RM_N_BITS / 8; // 16

    pub fn new(multiplicity: usize) -> Self {
        assert!(
            multiplicity == 3 || multiplicity == 5,
            "HQC duplicated RM multiplicity must be 3 (HQC-1) or 5 (HQC-3/5)"
        );
        Self { multiplicity }
    }

    /// n2 in bits (384 or 640).
    #[inline]
    pub fn n2_bits(&self) -> usize {
        Self::RM_N_BITS * self.multiplicity
    }

    /// n2 in bytes (48 or 80).
    #[inline]
    pub fn n2_bytes(&self) -> usize {
        Self::RM_N_BYTES * self.multiplicity
    }

    /// Encode one GF(256) symbol (byte) into duplicated RM codeword (packed bytes).
    pub fn encode_symbol(&self, sym: u8) -> Vec<u8> {
        let base = encode_rm1_7(sym); // 128 bits => 16 bytes
        let mut out = vec![0u8; self.n2_bytes()];
        for t in 0..self.multiplicity {
            let dst = &mut out[t * Self::RM_N_BYTES..(t + 1) * Self::RM_N_BYTES];
            dst.copy_from_slice(&base);
        }
        out
    }

    /// Decode one duplicated RM codeword (packed bytes) back to the original byte.
    ///
    /// Implements the “duplicated RM + Hadamard transform” decoding described in the spec. :contentReference[oaicite:2]{index=2}
    pub fn decode_symbol(&self, cw: &[u8]) -> Result<u8, ReedMullerError> {
        let expected = self.n2_bytes();
        if cw.len() != expected {
            return Err(ReedMullerError::InvalidLength {
                expected,
                got: cw.len(),
            });
        }

        // Build F: for each of the 128 positions, sum (-1)^bit over multiplicity copies.
        // bit=0 => +1, bit=1 => -1
        let mut f: Vec<i16> = vec![0; Self::RM_N_BITS];
        for i in 0..Self::RM_N_BITS {
            let mut acc: i16 = 0;
            for t in 0..self.multiplicity {
                let bit_idx = t * Self::RM_N_BITS + i;
                let b = get_bit_be(cw, bit_idx);
                acc += if b == 0 { 1 } else { -1 };
            }
            f[i] = acc;
        }

        // Walsh–Hadamard transform in-place.
        hadamard_transform_i16(&mut f);

        // Find index with maximum absolute value. Tie-break by smaller index
        // (matches “smallest value in the lowest 7 bits” guidance). :contentReference[oaicite:3]{index=3}
        let mut best_idx: usize = 0;
        let mut best_abs: i32 = (f[0] as i32).abs();
        for (idx, &val) in f.iter().enumerate().skip(1) {
            let a = (val as i32).abs();
            if a > best_abs || (a == best_abs && idx < best_idx) {
                best_abs = a;
                best_idx = idx;
            }
        }

        // Sign indicates whether we must add the all-one vector (constant term a0).
        let a0: u8 = if f[best_idx] < 0 { 1 } else { 0 };

        // For RM(1,7), the remaining 7 coefficients are exactly the 7-bit index.
        // Our encoding maps:
        //   byte bits: [a0 a1 a2 a3 a4 a5 a6 a7]  (bit7..bit0)
        //   index bits: [a1..a7] as a 7-bit number (bit6..bit0)
        // Therefore decoded byte = (a0<<7) | index.
        let index7: u8 = (best_idx & 0x7F) as u8;
        Ok((a0 << 7) | index7)
    }
}

/// Encode RM(1,7) (no duplication): one byte -> 128-bit codeword packed into 16 bytes.
///
/// We treat the byte as coefficients of an affine Boolean function:
///   f(x) = a0 ⊕ (a1*x1) ⊕ ... ⊕ (a7*x7)
/// where x is enumerated by i=0..127 (7-bit vector).
///
/// Mapping:
///   a0 = bit7 (MSB), a1=bit6, ..., a7=bit0.
///   x1..x7 correspond to bits6..0 of i (MSB..LSB).
fn encode_rm1_7(sym: u8) -> [u8; ReedMuller::RM_N_BYTES] {
    let mut out = [0u8; ReedMuller::RM_N_BYTES];

    for i in 0..ReedMuller::RM_N_BITS {
        let x = i as u8;

        // a0 is sym bit7
        let mut bit = (sym >> 7) & 1;

        // add dot(a1..a7, x_bits)
        for j in 0..ReedMuller::RM_M {
            let aj = (sym >> (6 - j)) & 1;      // a1..a7
            let xj = (x >> (6 - j)) & 1;        // x1..x7
            bit ^= aj & xj;
        }

        set_bit_be(&mut out, i, bit);
    }

    out
}

#[inline]
fn get_bit_be(buf: &[u8], bit_index: usize) -> u8 {
    let byte = bit_index >> 3;
    let bit_in_byte = 7 - (bit_index & 7);
    (buf[byte] >> bit_in_byte) & 1
}

#[inline]
fn set_bit_be(buf: &mut [u8], bit_index: usize, bit: u8) {
    let byte = bit_index >> 3;
    let bit_in_byte = 7 - (bit_index & 7);
    let mask = 1u8 << bit_in_byte;
    if (bit & 1) == 1 {
        buf[byte] |= mask;
    } else {
        buf[byte] &= !mask;
    }
}

/// In-place Walsh–Hadamard transform (length must be power-of-two).
fn hadamard_transform_i16(v: &mut [i16]) {
    debug_assert!(v.len().is_power_of_two());
    let mut len = 1;
    while len < v.len() {
        let step = len << 1;
        for i in (0..v.len()).step_by(step) {
            for j in 0..len {
                let a = v[i + j];
                let b = v[i + j + len];
                v[i + j] = a + b;
                v[i + j + len] = a - b;
            }
        }
        len = step;
    }
}
