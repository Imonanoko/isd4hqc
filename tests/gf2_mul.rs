use isd4hqc::hqc::hqcgf2::HqcGf2;
use isd4hqc::Gf2Construct;

fn mul_naive(a: &HqcGf2, b: &HqcGf2) -> HqcGf2 {
    let n = a.n;
    let mut out = HqcGf2::zero_with_len(n);
    for i in 0..n {
        if !a.get(i) { continue; }
        // left-rotate b by i: add b[k-i]
        for k in 0..n {
            let idx = (k + n - (i % n)) % n; // b_{k-i}
            if b.get(idx) {
                out.words[k / 64] ^= 1u64 << (k & 63);
            }
        }
    }
    out.mask_tail();
    out
}

#[test]
fn gf2_mul_matches_naive_small() {
    let n = 127; // small prime-ish
    let a = HqcGf2::from_indices(n, &[0, 1, 5, 63, 80, 126]);
    let b = HqcGf2::from_indices(n, &[0, 2, 7, 64, 100]);

    let x = a.mul_bitpacked(&b);
    let y = mul_naive(&a, &b);

    assert_eq!(x, y);
}

#[test]
fn gf2_mul_commutative_small() {
    let n = 127;
    let a = HqcGf2::from_indices(n, &[1, 3, 9, 70, 126]);
    let b = HqcGf2::from_indices(n, &[0, 2, 5, 80, 100]);

    assert_eq!(a.mul_bitpacked(&b), b.mul_bitpacked(&a));
}
