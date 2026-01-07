use super::{Attack, AttackError};
use crate::hqc::hqcgf2::HqcGf2;

pub struct BruteForce {
    pub max_iters: Option<u64>,
}

impl BruteForce {
    pub fn new(max_iters: Option<u64>) -> Self {
        Self { max_iters }
    }
}

impl Attack for BruteForce {
    fn name(&self) -> &'static str {
        "Brute Force"
    }
    fn solve(
        &self,
        n: usize,
        w: usize,
        h: &HqcGf2,
        s: &HqcGf2,
    ) -> Result<Option<HqcGf2>, AttackError> {
        let mut iters: u64 = 0;
        let mut comb: Vec<usize> = (0..w).collect();

        loop {
            if let Some(cap) = self.max_iters {
                if iters >= cap {
                    return Ok(None);
                }
            }
            iters += 1;

            let y = HqcGf2::from_indices(n, &comb);

            let hy = y.mul_bitpacked(h);

            let mut x = s.clone();
            x.xor_in_place(&hy);

            if (x.weight() as usize) == w {
                return Ok(Some(y));
            }

            if !next_combination(&mut comb, n) {
                break;
            }
        }

        Ok(None)
    }
}

fn next_combination(comb: &mut [usize], n: usize) -> bool {
    let k = comb.len();
    if k == 0 {
        return false;
    }

    for i_rev in 0..k {
        let i = k - 1 - i_rev;
        let max_val = n - (k - i);
        if comb[i] < max_val {
            comb[i] += 1;
            for j in (i + 1)..k {
                comb[j] = comb[j - 1] + 1;
            }
            return true;
        }
    }
    false
}