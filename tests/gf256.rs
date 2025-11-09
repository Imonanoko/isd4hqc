
use isd4hqc::gf::gf256::{GF256, GF256_TABLES, poly_div_rem, poly_mul};

#[test]
fn exp_log_roundtrip() {
    // 非 0 元素要滿足 exp[log[a]] = a
    for a in 1u16..=255 {
        let a = a as u8;
        let la = GF256_TABLES.log[a as usize] as usize;
        assert_eq!(GF256_TABLES.exp[la], a);
    }
}

#[test]
fn mul_inv_is_one() {
    for a in 1u16..=255 {
        let a = a as u8;
        let inv = GF256::inv(a);
        assert_eq!(GF256::mul(a, inv), 1);
    }
}

#[test]
fn poly_div_mul_recombine() {
    // (x^4 + x + 1) / (x^2 + x) 應該能回組 dividend
    let dividend = vec![1, 0, 0, 1, 1]; // x^4 + x + 1
    let divisor = vec![1, 1, 0]; // x^2 + x
    let (q, r) = poly_div_rem(&dividend, &divisor);
    let recomb = {
        // dividend = q*divisor + r
        let t = poly_mul(&q, &divisor);
        // r 與 t 對齊（右側）
        let len = t.len().max(r.len());
        let mut rr = vec![0u8; len];
        let mut tt = vec![0u8; len];
        rr[len - r.len()..].copy_from_slice(&r);
        tt[len - t.len()..].copy_from_slice(&t);
        for i in 0..len {
            tt[i] ^= rr[i];
        }
        tt
    };
    // 去前導 0
    let mut recomb = recomb;
    while recomb.len() > 1 && recomb[0] == 0 {
        recomb.remove(0);
    }
    assert_eq!(recomb, dividend);
}
