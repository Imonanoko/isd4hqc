use crate::gf::gf256::{self, GF256};
// This system use big endian

pub const HQC_G1_POLY: &[u8] = &[
    1, 181, 255, 82, 228, 69, 74, 110, 174, 210, 105, 118, 67, 173, 103, 
    139, 21, 210, 65, 233, 242, 233, 73, 75, 111, 117, 176, 116, 153, 69, 
    89,
];
pub const HQC_G2_POLY: &[u8] = &[
    1, 232, 29, 189, 50, 142, 246, 232, 15, 43, 82, 164, 238, 1, 158, 
    13, 119, 158, 224, 134, 227, 210, 163, 50, 107, 40, 27, 104, 253, 
    24, 239, 216, 45,
];
pub const HQC_G3_POLY: &[u8] = &[
    1, 187, 199, 48, 216, 188, 39, 47, 124, 64, 130, 178, 141, 27, 47, 
    232, 8, 144, 191, 246, 4, 141, 99, 239, 152, 219, 180, 243, 31, 12, 
    123, 217, 141, 183, 186, 210, 97, 115, 201, 71, 159, 215, 32, 101, 
    87, 123, 150, 71, 148, 63, 240, 91, 124, 121, 200, 39, 49, 167, 49,
];

#[derive(Debug, PartialEq, Eq)]
pub enum RsError {
    Uncorrectable,
    CorrectionFailed,
}
#[derive(Debug)]
pub struct ReedSolomon {
    pub n: usize,
    pub k: usize,
    pub delta: usize,
    pub gen_poly: Vec<u8>,
}
impl ReedSolomon {
    pub fn new(n: usize, k: usize, gen_poly: &[u8]) -> Self {
        let delta = (n - k) / 2;
        assert_eq!(gen_poly.len(), 2*delta + 1, "length of gen_poly is not match (n, k).");
        Self {
            n,
            k,
            delta,
            gen_poly:gen_poly.to_vec(),
        }
    }
    pub fn encode(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut u_x = vec![0u8; self.k - message.len()];
        u_x.extend_from_slice(message);
        let n_k = self.n - self.k;
        let mut dividend = u_x.clone();
        dividend.extend(vec![0u8; n_k]);
        let (_, p_x) = gf256::poly_div_rem(&dividend, &self.gen_poly);
        let mut padded_parity = vec![0u8; n_k.saturating_sub(p_x.len())];
        padded_parity.extend_from_slice(&p_x);
        let mut codeword = u_x;
        codeword.extend_from_slice(&padded_parity);
        Ok(codeword)
    }

    pub fn decode(&self, received: &[u8]) -> Result<Vec<u8>, RsError> {
        if received.len() != self.n {
            return Err(RsError::Uncorrectable);
        }

        let mut r_low = received.to_vec();
        r_low.reverse();
        let two_delta = 2 * self.delta;
        let mut syndromes = vec![0u8; two_delta];
        let mut has_error = false;

        for i in 0..two_delta {
            let alpha_pow = i + 1;
            let s_i = poly_eval_low(&r_low, GF256::pow_alpha(alpha_pow));
            syndromes[i] = s_i;
            if s_i != 0 {
                has_error = true;
            }
        }

        if !has_error {
            return Ok(received[0..self.k].to_vec());
        }
        let (sigma, l) = match berlekamp_massey_fixed(&syndromes, self.delta) {
            Ok(val) => val,
            Err(e) => return Err(e),
        };
        let error_locs_indices = chien_search_low(&sigma, self.n);
        
        if error_locs_indices.len() != l {
            return Err(RsError::Uncorrectable);
        }
        
        if l > self.delta {
            return Err(RsError::Uncorrectable);
        }
        let s_poly = &syndromes;
        
        let omega_full = poly_mul_low(s_poly, &sigma);
        let omega: Vec<u8> = omega_full.into_iter().take(l + 1).collect();
        let mut corrected_low = r_low;
        for &loc_idx in &error_locs_indices {
            let x_inv = GF256::pow_alpha(255 - (loc_idx % 255)); 
            let omega_val = poly_eval_low(&omega, x_inv);
            let sigma_prime_val = poly_eval_formal_deriv_low(&sigma, x_inv);
            
            if sigma_prime_val == 0 {
                return Err(RsError::CorrectionFailed);
            }
            let error_val = GF256::mul(omega_val, GF256::inv(sigma_prime_val));
            corrected_low[loc_idx] = GF256::add(corrected_low[loc_idx], error_val);
        }
        for i in 0..two_delta {
            let alpha_pow = i + 1;
            if poly_eval_low(&corrected_low, GF256::pow_alpha(alpha_pow)) != 0 {
                return Err(RsError::CorrectionFailed);
            }
        }

        corrected_low.reverse(); 
        Ok(corrected_low[0..self.k].to_vec())
    }
}

#[inline]
fn poly_eval_low(p: &[u8], x: u8) -> u8 {
    p.iter().rfold(0, |acc, &c| GF256::mul(acc, x) ^ c)
}

#[inline]
fn poly_eval_formal_deriv_low(p: &[u8], x: u8) -> u8 {
    let mut val = GF256::zero();
    let mut x_pow = GF256::one(); // x^0
    for i in (1..p.len()).step_by(2) {
        val ^= GF256::mul(p[i], x_pow);
        x_pow = GF256::mul(x_pow, GF256::mul(x,x)); // x^(i-1)
    }
    val
}

#[inline]
fn poly_add_low(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    let mut out = vec![0u8; n];
    for i in 0..n {
        let ai = a.get(i).unwrap_or(&0);
        let bi = b.get(i).unwrap_or(&0);
        out[i] = ai ^ bi;
    }
    while out.len() > 1 && out.last() == Some(&0) {
        out.pop();
    }
    out
}

#[inline]
fn poly_mul_low(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() || b.is_empty() || (a.len() == 1 && a[0] == 0) || (b.len() == 1 && b[0] == 0) {
        return vec![0];
    }
    let mut out = vec![0u8; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai == 0 { continue; }
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] ^= GF256::mul(ai, bj);
        }
    }
    out
}

fn berlekamp_massey_fixed(s: &[u8], delta: usize) -> Result<(Vec<u8>, usize), RsError> {
    let n = s.len();
    let mut sigma = vec![1u8];
    let mut b_poly = vec![1u8];
    let mut l: usize = 0;
    let mut m: usize = 1;
    let mut b: u8 = 1;

    for r in 0..n {
        let mut d = s[r];
        for i in 1..=l {
            if sigma.len() > i && s.len() > (r - i) {
                d ^= GF256::mul(sigma[i], s[r - i]);
            }
        }

        if d == 0 {
            m += 1;
        } else if 2 * l <= r {
            let t = sigma.clone();
            let d_inv_b = GF256::mul(d, GF256::inv(b));
            let mut correction = vec![0u8; m]; 
            correction.extend(b_poly.iter().map(|&c| GF256::mul(c, d_inv_b)));
            sigma = poly_add_low(&sigma, &correction);
            
            b_poly = t;
            l = r + 1 - l;
            b = d;
            m = 1;
        } else {
            let d_inv_b = GF256::mul(d, GF256::inv(b));
            let mut correction = vec![0u8; m]; // x^m
            correction.extend(b_poly.iter().map(|&c| GF256::mul(c, d_inv_b)));
            sigma = poly_add_low(&sigma, &correction);
            
            m += 1;
        }
    }
    
    if l > delta {
        return Err(RsError::Uncorrectable);
    }

    Ok((sigma, l))
}

fn chien_search_low(sigma: &[u8], n: usize) -> Vec<usize> {
    let mut roots = Vec::new();
    for j in 0..n {
        let x_inv = GF256::pow_alpha(255 - (j % 255));
        
        let val = poly_eval_low(sigma, x_inv);
        
        if val == 0 {
            roots.push(j);
        }
    }
    roots
}