use super::*;
use crate::hqc::hash::xof::Shake256Xof;
use crate::hqc::hqcgf2::HqcGf2;
use crate::hqc::sampling::rand_bits;
use std::collections::HashSet;
use std::collections::HashMap;
use std::ops::ControlFlow;
pub struct Stern {
    window_size: usize,
    bound: usize,
    window_tries: usize,
    seed: Vec<u8>,
    cap_per_key: usize,
}

impl Stern {
    pub fn new(window_size: usize, bound: usize, window_tries: usize, seed: Vec<u8>, cap_per_key: usize) -> Self {
        assert!(window_size > 0, "window_size must be positive");
        Self {
            window_size,
            bound,
            window_tries,
            seed,
            cap_per_key,
        }
    }
}

impl Default for Stern {
    fn default() -> Self {
        Self {
            window_size: 100,
            bound: 4,
            window_tries: 100,
            seed: "default_seed".as_bytes().to_vec(),
            cap_per_key: 100,
        }
    }
}

impl Attack for Stern {
    fn name(&self) -> &'static str {
        "Stern"
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
        if self.window_size == 0 || self.window_size > n - w {
            return Err(AttackError::InvalidParameter(
                "parameter window_size must be > 0 and <= n - w".to_string(),
            ));
        }
        for i in 0..self.window_tries {
            let mut seed = Vec::with_capacity(self.seed.len() + 8);
            seed.extend_from_slice(&self.seed);
            seed.extend_from_slice(&(i as u64).to_le_bytes());
            let window = select_window(n, self.window_size, &seed);
            let mid = w / 2;
            for delta in 0..=self.bound {
                for sign in [0i32, 1i32] {
                    let p1 = match sign {
                        0 => mid.saturating_add(delta),
                        _ => mid.saturating_sub(delta),
                    };
                    if p1 > w {
                        continue;
                    }
                    let p2 = w - p1;
                    let n1 = n / 2;
                    let n2 = n - n1;
                    if p1 > n1 || p2 > n2 {
                        continue;
                    }
                    if let Some(y) =
                        stern_try_once(n, w, h, s, n1, n2, p1, p2, &window, self.cap_per_key)
                    {
                        return Ok(Some(y));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Select a random integer in [0, bound)
fn rand_bounded(xof: &Shake256Xof, bound: usize) -> usize {
    debug_assert!(bound > 0);
    let b = bound as u64;
    let limit = (u64::MAX / b) * b;
    loop {
        let r = rand_bits(xof) as u64;
        if r < limit {
            return (r % b) as usize;
        }
    }
}

/// Select a random window of given size
pub fn select_window(n: usize, window_size: usize, seed: &[u8]) -> Vec<usize> {
    assert!(window_size <= n, "window_size must be <= n");
    let xof = Shake256Xof::new(seed);
    let k = window_size;
    let mut chosen: HashSet<usize> = HashSet::with_capacity(k * 2);
    for j in (n - k)..n {
        let t = rand_bounded(&xof, j + 1);
        if !chosen.insert(t) {
            chosen.insert(j);
        }
    }
    let mut window: Vec<usize> = chosen.into_iter().collect();
    window.sort_unstable();
    window
}

pub fn stern_try_once(
    n: usize,
    w: usize,
    h: &HqcGf2,
    s: &HqcGf2,
    n1: usize,
    n2: usize,
    p1: usize,
    p2: usize,
    window: &[usize],
    cap_per_key: usize,
) -> Option<HqcGf2> {
    if n1 + n2 != n {
        return None;
    }
    if p1 > n1 || p2 > n2 {
        return None;
    }
    let key_words = (window.len() + 63) / 64;
    let mut key_buf = vec![0u64; key_words];
    let mut rhs_buf = vec![0u64; key_words];
    let mut table: HashMap<Vec<u64>, Vec<Vec<usize>>> = HashMap::new();
    let _ = for_each_combination_cf(n1, p1, |support_y1| {
        let y1: Vec<usize> = support_y1.to_vec();

        h_mul_y_on_window(n, h, &y1, window, &mut key_buf);
        let key = key_buf.clone();

        let entry = table.entry(key).or_default();
        if entry.len() < cap_per_key {
            entry.push(y1);
        }

        ControlFlow::Continue(())
    });

    let mut answer: Option<HqcGf2> = None;
    let _ = for_each_combination_cf(n2, p2, |support_y2| {
        if answer.is_some() {
            return ControlFlow::Break(());
        }
        let y2: Vec<usize> = support_y2.iter().map(|&i| n1 + i).collect();
        s_xor_h_mul_y_key_on_window(n, s, h, &y2, window, &mut rhs_buf);

        if let Some(cands) = table.get(&rhs_buf) {
            for y1 in cands {
                let mut supp_y = Vec::with_capacity(y1.len() + y2.len());
                supp_y.extend_from_slice(y1);
                supp_y.extend_from_slice(&y2);
                let y = HqcGf2::from_indices(n, &supp_y);
                let hy = h.mul_bitpacked(&y);
                let mut x = s.clone();
                x.xor_in_place(&hy);
                if x.weight() == w.try_into().unwrap() {
                    answer = Some(y);
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    });
    answer
}