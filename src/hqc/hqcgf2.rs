use crate::gf2::{Gf2, Gf2Construct};
use std::fmt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HqcGf2 {
    pub n: usize,        // number of bits
    pub words: Vec<u64>, // bit-packed coefficients, LSB-first
}
impl HqcGf2 {
    #[inline]
    pub fn word_len(n: usize) -> usize {
        (n + 63) / 64
    }
    #[inline]
    fn last_mask(n: usize) -> u64 {
        let r = n & 63; // n % 64
        if r == 0 { !0u64 } else { (1u64 << r) - 1 }
    }
    #[inline]
    fn mask_tail(&mut self) {
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
            let w = i / 64;
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
        let w = i / 64;
        let b = i & 63; // i % 64
        (self.words[w] >> b) & 1 == 1
    }

    /// Bit set 1.
    #[inline]
    pub fn set(&mut self, i: usize) {
        if i >= self.n {
            return;
        }
        let w = i / 64;
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

    pub fn rotate_right_into(&self, shift: usize, out: &mut Self) {
        assert_eq!(self.n, out.n, "length mismatch");
        let n = self.n;
        if n == 0 {
            return;
        }
        let s = shift % n;
        if s == 0 {
            out.words.copy_from_slice(&self.words);
            return;
        }

        let m = Self::word_len(n);
        let whole = s / 64;
        let rem = s & 63;

        // step1: word-rotate right
        let mut tmp = vec![0u64; m];
        for i in 0..m {
            tmp[i] = self.words[(i + whole) % m];
        }

        if rem == 0 {
            out.words.copy_from_slice(&tmp);
            out.mask_tail();
            return;
        }

        // step2: bit-rotate right (一般 word)
        let lshift = 64 - rem;
        for i in 0..(m.saturating_sub(1)) {
            let cur = tmp[i];
            let next = tmp[(i + 1) % m];
            out.words[i] = (cur >> rem) | (next << lshift);
        }

        // step2': 最後一個 word 的低 r 位需要特判
        let r = n & 63;
        let last = m - 1;
        if r == 0 {
            // 最後一個 word 也是滿 64 位，走一般公式
            let cur = tmp[last];
            let next = tmp[0];
            out.words[last] = (cur >> rem) | (next << lshift);
        } else {
            let mask_r = (1u64 << r) - 1;
            let cur = tmp[last];
            let next = tmp[0];
            out.words[last] = if rem <= r {
                let a = (cur >> rem) & mask_r;
                let b = (next & ((1u64 << rem) - 1)) << (r - rem);
                (a | b) & mask_r
            } else {
                // rem > r
                (next >> (rem - r)) & mask_r
            };
        }

        out.mask_tail();
    }

    pub fn rotate_right(&self, shift: usize) -> Self {
        let mut out = HqcGf2::zero_with_len(self.n);
        self.rotate_right_into(shift, &mut out);
        out
    }

    /// out ^= (self >>> shift)
    pub fn xor_with_rotated_into(&self, shift: usize, out: &mut Self) {
        assert_eq!(self.n, out.n, "length mismatch");
        let mut tmp = HqcGf2::zero_with_len(self.n);
        self.rotate_right_into(shift, &mut tmp);
        for (o, t) in out.words.iter_mut().zip(tmp.words.into_iter()) {
            *o ^= t;
        }
        out.mask_tail();
    }
    /// u x v = u x rot(v)^T
    pub fn mul_bitpacked(&self, other: &Self) -> Self {
        assert_eq!(self.n, other.n, "length mismatch");
        let n = self.n;
        let m = Self::word_len(n);

        let mut acc = HqcGf2::zero_with_len(n);
        // for echo set bit i in u{
        //     acc ^= RightRotate(v, i);
        // }
        for wi in 0..m {
            let mut word = self.words[wi];
            while word != 0 {
                let lsb = word & word.wrapping_neg(); // word & (!word + 1);
                let bit = lsb.trailing_zeros() as usize;
                let global_bit = wi * 64 + bit;
                if global_bit < n {
                    other.xor_with_rotated_into(global_bit, &mut acc);
                }
                word ^= lsb;
            }
        }
        acc
    }
    // use un debug
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
