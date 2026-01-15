use crate::gf::{Gf2, Gf2Construct};
use std::fmt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HqcGf2 {
    pub n: usize,        // number of bits
    pub words: Vec<u64>, // bit-packed coefficients, LSB-first
}
impl HqcGf2 {
    #[inline]
    pub fn word_len(n: usize) -> usize {
        (n + 63) >> 6
    }
    #[inline]
    fn last_mask(n: usize) -> u64 {
        let r = n & 63; // n % 64
        if r == 0 { !0u64 } else { (1u64 << r) - 1 }
    }
    #[inline]
    pub fn mask_tail(&mut self) {
        if let Some(last) = self.words.last_mut() {
            *last &= Self::last_mask(self.n);
        }
    }
    /// Build from set indices (e.g. [0,2] -> 1 + X^2).
    pub fn from_indices(n: usize, idxs: &[usize]) -> Self {
        let m = Self::word_len(n);
        let mut words = vec![0u64; m];
        for &i in idxs {
            if i >= n {
                continue;
            }
            let w = i >> 6; // i / 64
            let b = i & 63; // i % 64
            words[w] ^= 1u64 << b;
        }
        let mut obj = Self { n, words };
        obj.mask_tail();
        obj
    }

    /// Hamming weight.
    pub fn weight(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    /// Bit get.
    #[inline]
    pub fn get(&self, i: usize) -> bool {
        if i >= self.n {
            return false;
        }
        let w = i >> 6; // i / 64
        let b = i & 63; // i % 64
        (self.words[w] >> b) & 1 == 1
    }

    /// Bit set 1.
    #[inline]
    pub fn set(&mut self, i: usize) {
        if i >= self.n {
            return;
        }
        let w = i >> 6;
        let b = i & 63;
        self.words[w] |= 1u64 << b;
    }

    /// In-place XOR.
    #[inline]
    pub fn xor_in_place(&mut self, other: &Self) {
        assert_eq!(self.n, other.n, "length mismatch");
        for (a, b) in self.words.iter_mut().zip(&other.words) {
            *a ^= *b;
        }
        self.mask_tail();
    }

    #[inline]
    fn shift_left_trunc_into(&self, sh: usize, dst: &mut [u64]) {
        // dst = self << sh  (within n bits, truncating overflow)
        let n = self.n;
        let m = Self::word_len(n);
        debug_assert_eq!(dst.len(), m);

        dst.fill(0);
        if n == 0 {
            return;
        }
        if sh >= n {
            return;
        }

        let wsh = sh >> 6;
        let bsh = sh & 63;

        for i in (0..m).rev() {
            if i < wsh {
                continue;
            }
            let si = i - wsh;

            let mut v = self.words[si] << bsh;
            if bsh != 0 && si > 0 {
                v |= self.words[si - 1] >> (64 - bsh);
            }
            dst[i] = v;
        }

        // mask tail bits
        if let Some(last) = dst.last_mut() {
            *last &= Self::last_mask(n);
        }
    }

    #[inline]
    fn shift_right_trunc_into(&self, sh: usize, dst: &mut [u64]) {
        // dst = self >> sh  (within n bits)
        let n = self.n;
        let m = Self::word_len(n);
        debug_assert_eq!(dst.len(), m);

        dst.fill(0);
        if n == 0 {
            return;
        }
        if sh >= n {
            return;
        }

        let wsh = sh >> 6;
        let bsh = sh & 63;

        for i in 0..m {
            let si = i + wsh;
            if si >= m {
                break;
            }

            let mut v = self.words[si] >> bsh;
            if bsh != 0 && (si + 1) < m {
                v |= self.words[si + 1] << (64 - bsh);
            }
            dst[i] = v;
        }

        if let Some(last) = dst.last_mut() {
            *last &= Self::last_mask(n);
        }
    }

    /// dst = rotl_n(self, sh)  (cyclic rotate on n bits) 
    /// example: n=10, self=0000001111, sh=3 -> dst=0001111000
    #[inline]
    pub fn rotate_left_into(&self, sh: usize, dst: &mut Self, tmp: &mut Vec<u64>) {
        assert_eq!(self.n, dst.n, "length mismatch");
        let n = self.n;
        let m = Self::word_len(n);
        tmp.resize(m, 0);

        if n == 0 {
            return;
        }
        let s = sh % n;
        if s == 0 {
            dst.words.copy_from_slice(&self.words);
            dst.mask_tail();
            return;
        }

        // dst = (self << s) XOR (self >> (n - s))
        self.shift_left_trunc_into(s, &mut dst.words);
        self.shift_right_trunc_into(n - s, tmp);

        for i in 0..m {
            dst.words[i] ^= tmp[i];
        }
        dst.mask_tail();
    }

    /// dst = rotr_n(self, sh) (cyclic rotate on n bits)
    #[inline]
    pub fn rotate_right_into(&self, sh: usize, dst: &mut Self, tmp: &mut Vec<u64>) {
        assert_eq!(self.n, dst.n, "length mismatch");
        let n = self.n;
        if n == 0 {
            return;
        }
        let s = sh % n;
        let left = if s == 0 { 0 } else { n - s };
        self.rotate_left_into(left, dst, tmp);
    }

    /// out ^= (self >>> shift)
    pub fn xor_with_rotated_into(
        &self,
        shift: usize,
        out: &mut Self,
        tmp_vec: &mut Vec<u64>,
        tmp_gf2: &mut Self,
    ) {
        self.rotate_right_into(shift, tmp_gf2, tmp_vec);
        for (o, t) in out.words.iter_mut().zip(tmp_gf2.words.iter()) {
            *o ^= *t;
        }
        out.mask_tail();
    }
    /// u x v = u x rot(v)^T
    pub fn mul_bitpacked(&self, other: &Self) -> Self {
        assert_eq!(self.n, other.n, "length mismatch");
        let n = self.n;
        let m = Self::word_len(n);

        let (sparse, dense) = if self.weight() <= other.weight() {
            (self, other)
        } else {
            (other, self)
        };

        let mut acc = HqcGf2::zero_with_len(n);
        let mut rot = HqcGf2::zero_with_len(n);
        let mut tmp: Vec<u64> = vec![0u64; m];

        for i in sparse.ones_indices() {
            dense.rotate_left_into(i, &mut rot, &mut tmp);
            for j in 0..m {
                acc.words[j] ^= rot.words[j];
            }
        }
        acc.mask_tail();
        acc
    }
    // use in debug
    pub fn ones_indices(&self) -> Vec<usize> {
        let mut out = Vec::new();
        for (wi, mut w) in self.words.iter().copied().enumerate() {
            while w != 0 {
                let b = w.trailing_zeros() as usize;
                let i = wi * 64 + b;
                if i < self.n {
                    out.push(i);
                }
                w &= w - 1;
            }
        }
        out
    }

    pub fn truncate(&self, n_prime: usize) -> Self {
        assert!(n_prime <= self.n, "truncate length exceeds self.n");
        let m = Self::word_len(n_prime);
        let mut words = vec![0u64; m];
        let full_words = n_prime >> 6;
        if full_words > 0 {
            words[..full_words].copy_from_slice(&self.words[..full_words]);
        }
        let rem = n_prime & 63;
        if rem > 0 {
            let mask = (1u64 << rem) - 1;
            words[full_words] = self.words[full_words] & mask;
        }
        let mut obj = Self { n: n_prime, words };
        obj.mask_tail();
        obj
    }

    pub fn to_bytes_le_bits(&self) -> Vec<u8> {
        let out_len = (self.n + 7) / 8;
        let mut out = vec![0u8; out_len];
        for i in 0..self.n {
            if self.get(i) {
                out[i >> 3] |= 1u8 << (i & 7);
            }
        }
        out
    }

    pub fn from_bytes_le_bits(n: usize, bytes: &[u8]) -> Self {
        let mut v = HqcGf2::zero_with_len(n);
        let need = (n + 7) / 8;
        let take = need.min(bytes.len());
        for bi in 0..take {
            let b = bytes[bi];
            if b == 0 {
                continue;
            }
            for j in 0..8 {
                if (b >> j) & 1 == 1 {
                    let idx = (bi << 3) + j;
                    if idx < n {
                        v.set(idx);
                    }
                }
            }
        }
        v.mask_tail();
        v
    }

    /// Flip bit i (xor with 1 at position i).
    #[inline(always)]
    pub fn toggle(&mut self, i: usize) {
        if i >= self.n {
            return;
        }
        let w = i >> 6; // i / 64
        let b = i & 63; // i % 64
        self.words[w] ^= 1u64 << b;
    }

    /// Swap two bits inside this vector.
    #[inline(always)]
    pub fn swap_bits(&mut self, i: usize, j: usize) {
        if i == j {
            return;
        }
        let bi = self.get(i);
        let bj = self.get(j);
        if bi != bj {
            self.toggle(i);
            self.toggle(j);
        }
    }

    /// Copy without realloc.
    #[inline(always)]
    pub fn copy_from_same_len(&mut self, other: &Self) {
        assert_eq!(self.n, other.n, "length mismatch");
        self.words.copy_from_slice(&other.words);
        self.mask_tail();
    }
    /// Clear all bits to zero.
    #[inline(always)]
    pub fn clear_all(&mut self) {
        self.words.fill(0);
    }

    /// Set bit i to 0.
    #[inline(always)]
    pub fn clear(&mut self, i: usize) {
        if i >= self.n {
            return;
        }
        let w = i >> 6;
        let b = i & 63;
        self.words[w] &= !(1u64 << b);
    }

    /// Set bit i to given value.
    #[inline(always)]
    pub fn set_to(&mut self, i: usize, val: bool) {
        if val { self.set(i) } else { self.clear(i) }
    }
}
impl Gf2 for HqcGf2 {
    fn add(&self, other: &Self) -> Self {
        assert_eq!(self.n, other.n, "length mismatch");
        let mut out = self.clone();
        out.xor_in_place(other);
        out
    }

    fn mul(&self, other: &Self) -> Self {
        self.mul_bitpacked(other)
    }

    fn is_zero(&self) -> bool {
        let m = Self::word_len(self.n);
        for i in 0..m.saturating_sub(1) {
            if self.words[i] != 0 {
                return false;
            }
        }
        if m == 0 {
            return true;
        }
        (self.words[m - 1] & Self::last_mask(self.n)) == 0
    }
}

impl Gf2Construct for HqcGf2 {
    /// Zero element with length n.
    fn zero_with_len(n: usize) -> Self {
        let m = Self::word_len(n);
        let mut obj = Self {
            n,
            words: vec![0u64; m],
        };
        obj.mask_tail();
        obj
    }
    /// One element with length n.
    fn one_with_len(n: usize) -> Self {
        let m = Self::word_len(n);
        let mut words = vec![0u64; m];
        if n > 0 {
            words[0] = 1u64;
        }
        let mut obj = Self { n, words };
        obj.mask_tail();
        obj
    }
}

impl fmt::Display for HqcGf2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // {:#}
        if f.alternate() {
            write!(f, "HqcGf2(n={}, words=[", self.n)?;
            for (i, w) in self.words.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{:#018x}", w)?;
            }
            return write!(f, "])");
        }

        write!(f, "HqcGf2(n={}, bits= ", self.n)?;
        for i in 0..self.n {
            let bit = if self.get(i) { '1' } else { '0' };
            f.write_str(&bit.to_string())?;
            if i % 64 == 63 && i + 1 < self.n {
                f.write_str("|")?;
            } else if i % 8 == 7 && i + 1 < self.n {
                f.write_str("_")?;
            }
        }
        write!(f, ")")
    }
}
