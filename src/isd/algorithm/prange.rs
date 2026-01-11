use super::*;
use crate::gf::gf2::Gf2Construct;
use crate::hqc::hqcgf2::HqcGf2;
use rand::{RngCore, SeedableRng};
use rand::rngs::{OsRng, StdRng};

pub struct Prange {
    pub max_iters: Option<u64>,
    pub seed: Option<u64>,
}
impl Prange {
    pub fn new(max_iters: Option<u64>, seed: Option<u64>) -> Self {
        Self { max_iters, seed }
    }
}
impl Default for Prange {
    fn default() -> Self {
        Self {
            max_iters: Some(2000000),
            seed: None,
        }
    }
}
impl Attack for Prange {
    fn name(&self) -> &'static str {
        "Prange"
    }

    fn solve(
        &self,
        n: usize,
        w: usize,
        h: &HqcGf2,
        s: &HqcGf2,
    ) -> Result<Option<HqcGf2>, AttackError> {
        if h.n != n || s.n != n {
            return Err(AttackError::InvalidParameter(
                "length mismatch: h.n or s.n != n".to_string(),
            ));
        }
        if n == 0 {
            return Ok(None);
        }

        let max_iters = self.max_iters.unwrap_or(u64::MAX);
        let seed = match self.seed {
            Some(v) => v,
            None => OsRng.next_u64(),
        };
        let mut rng = StdRng::seed_from_u64(seed);
        let mut mat_rows: Vec<HqcGf2> = (0..n).map(|_| HqcGf2::zero_with_len(n)).collect();
        let mut rhs = HqcGf2::zero_with_len(n);
        let mut col_buf = HqcGf2::zero_with_len(n);
        let mut tmp_words: Vec<u64> = vec![0u64; HqcGf2::word_len(n)];
        let mut perm: Vec<usize> = (0..2 * n).collect();

        for _ in 0..max_iters {
            sample_cols(&mut rng, &mut perm, n);
            let cols = &perm[..n];
            build_square_matrix_from_selected_columns(
                n,
                h,
                cols,
                &mut mat_rows,
                &mut col_buf,
                &mut tmp_words,
            );
            rhs.copy_from_same_len(s);
            if !gaussian_elimination_for_isd_instance(&mut mat_rows, &mut rhs) {
                continue;
            }
            let mut y = HqcGf2::zero_with_len(n);
            let mut x = HqcGf2::zero_with_len(n);

            for (k, &orig_col) in cols.iter().enumerate() {
                if rhs.get(k) {
                    if orig_col < n {
                        y.set(orig_col);
                    } else {
                        x.set(orig_col - n);
                    }
                }
            }
            if y.weight() as usize != w || x.weight() as usize != w {
                continue;
            }
            let hy = h.mul_bitpacked(&y);
            let mut lhs = x.clone();
            lhs.xor_in_place(&hy);
            if lhs != *s {
                continue;
            }

            return Ok(Some(y));
        }

        Ok(None)
    }
}
