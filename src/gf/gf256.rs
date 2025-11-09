use once_cell::sync::Lazy;
pub const PRIMITIVE_POLY: u16 = 0x11D;

pub struct Gf256Tables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

pub static GF256_TABLES: Lazy<Gf256Tables> = Lazy::new(|| {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255 {
        exp[i] = x as u8;
        log[exp[i] as usize] = i as u8;
        x <<= 1;
        if (x & 0x100) != 0 {
            x ^= PRIMITIVE_POLY;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    Gf256Tables { exp, log }
});

pub enum GF256 {}

impl GF256 {
    #[inline] pub fn zero() -> u8 { 0 }
    #[inline] pub fn one()  -> u8 { 1 }

    #[inline] pub fn add(a: u8, b: u8) -> u8 { a ^ b }
    #[inline] pub fn sub(a: u8, b: u8) -> u8 { a ^ b }

    #[inline]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 { return 0; }
        let la = GF256_TABLES.log[a as usize] as usize;
        let lb = GF256_TABLES.log[b as usize] as usize;
        GF256_TABLES.exp[la + lb]
    }

    #[inline]
    pub fn inv(a: u8) -> u8 {
        debug_assert!(a != 0);
        GF256_TABLES.exp[255 - GF256_TABLES.log[a as usize] as usize]
    }

    #[inline]
    pub fn pow_alpha(i: usize) -> u8 {
        GF256_TABLES.exp[i % 255]
    }
}

#[inline]
fn trim_leading_zeros(mut v: Vec<u8>) -> Vec<u8> {
    while v.len() > 1 && v[0] == 0 { v.remove(0); }
    v
}

#[inline]
fn deg_leading(p: &[u8]) -> Option<usize> {
    for (i, &c) in p.iter().enumerate() {
        if c != 0 { return Some(p.len() - 1 - i); }
    }
    None
}

pub fn poly_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    let mut out = vec![0u8; n];
    for i in 0..n {
        let ai = if i + a.len() >= n { a[i + a.len() - n] } else { 0 };
        let bi = if i + b.len() >= n { b[i + b.len() - n] } else { 0 };
        out[i] = ai ^ bi;
    }
    trim_leading_zeros(out)
}

pub fn poly_scale(a: &[u8], c: u8) -> Vec<u8> {
    if c == 0 { return vec![0]; }
    if c == 1 { return a.to_vec(); }
    a.iter().map(|&ai| GF256::mul(ai, c)).collect()
}

pub fn poly_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a == [0] || b == [0] { return vec![0]; }
    let mut out = vec![0u8; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai == 0 { continue; }
        for (j, &bj) in b.iter().enumerate() {
            if bj == 0 { continue; }
            out[i + j] ^= GF256::mul(ai, bj);
        }
    }
    trim_leading_zeros(out)
}

pub fn poly_div_rem(dividend: &[u8], divisor: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(divisor.iter().any(|&x| x != 0));
    let mut a = dividend.to_vec();
    while a.len() > 1 && a[0] == 0 { a.remove(0); }

    let n = a.len();
    let m = divisor.len();
    if n < m {
        return (vec![0], a);
    }

    let mut q = vec![0u8; n - m + 1];
    let mut r = a.clone();

    let lead_div = divisor[0];
    debug_assert!(lead_div != 0);

    for i in 0..=n - m {
        let rc = r[i];
        if rc == 0 { continue; }

        let coef = GF256::mul(rc, GF256::inv(lead_div));
        q[i] = coef;

        for j in 0..m {
            r[i + j] ^= GF256::mul(coef, divisor[j]);
        }
    }

    let mut rem = if m - 1 == 0 { vec![0] } else { r[n - (m - 1) ..].to_vec() };
    while rem.len() > 1 && rem[0] == 0 { rem.remove(0); }

    let mut quo = q;
    while quo.len() > 1 && quo[0] == 0 { quo.remove(0); }

    (quo, rem)
}

