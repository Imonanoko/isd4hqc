use super::{HqcGf2, hash::xof::Shake256Xof};

pub(crate) fn sample_vect(n: usize, xof: &Shake256Xof) -> HqcGf2 {
    let n_bytes = (n + 7) / 8;
    let mut bytes = xof.get_bytes(n_bytes);

    let rem = n & 7;
    if rem != 0 {
        let mask = (1u8 << rem) - 1;
        if let Some(last) = bytes.last_mut() {
            *last &= mask;
        }
    }

    let m = (n + 63) / 64;
    let mut words = vec![0u64; m];
    for (wi, chunk) in bytes.chunks(8).enumerate() {
        let mut w = 0u64;
        for (j, &b) in chunk.iter().enumerate() {
            w |= (b as u64) << (8 * j);
        }
        words[wi] = w;
    }

    let mut v = HqcGf2 { n, words };
    v.mask_tail();
    v
}

#[inline]
pub fn rand_bits(xof: &Shake256Xof) -> u32 {
    let b = xof.get_bytes(4);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn rand(bound: usize, xof: &Shake256Xof) -> usize {
    debug_assert!(bound > 0);
    (rand_bits(xof) as usize) % bound
}

pub(crate) fn generate_random_support(n: usize, w: usize, xof: &Shake256Xof) -> Vec<usize> {
    assert!(w <= n, "weight cannot exceed n");
    let mut pos = vec![0usize; w];
    let mut used = vec![false; n];

    for i_rev in 0..w {
        let i = w - 1 - i_rev;
        let l = i + rand(n - i, xof);
        let chosen = if used[l] { i } else { l };
        pos[i] = chosen;
        used[chosen] = true;
    }
    pos.sort_unstable();
    pos
}

pub fn sample_fixed_weight_vect(n: usize, w: usize, xof: &Shake256Xof) -> HqcGf2 {
    let support = generate_random_support(n, w, xof);
    HqcGf2::from_indices(n, &support)
}
