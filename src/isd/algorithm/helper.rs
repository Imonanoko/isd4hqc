use crate::hqc::hqcgf2::HqcGf2;
use rand::Rng;
use crate::gf::gf2::Gf2Construct;
use std::ops::ControlFlow;
//prange
/// true if successful, false if not invertible
pub fn gaussian_elimination_for_isd_instance(mat_rows: &mut [HqcGf2], rhs: &mut HqcGf2) -> bool {
    let n = mat_rows.len();
    assert_eq!(rhs.n, n, "rhs length mismatch: rhs.n != n");
    for (i, row) in mat_rows.iter().enumerate() {
        assert_eq!(row.n, n, "matrix must be square: row {i} has row.n != n");
    }
    for col in 0..n {
        let mut pivot = None;
        for r in col..n {
            if mat_rows[r].get(col) {
                pivot = Some(r);
                break;
            }
        }
        let pivot = match pivot {
            Some(r) => r,
            None => return false,
        };

        if pivot != col {
            mat_rows.swap(pivot, col);
            rhs.swap_bits(pivot, col);
        }
        let (left, right) = mat_rows.split_at_mut(col);
        let (pivot_row_mut, right_rest) = right.split_first_mut().expect("col < n so non-empty");
        let pivot_row: &HqcGf2 = &*pivot_row_mut;
        for r in 0..col {
            if left[r].get(col) {
                left[r].xor_in_place(pivot_row);
                if rhs.get(col) {
                    rhs.toggle(r);
                }
            }
        }
        for (k, row) in right_rest.iter_mut().enumerate() {
            let r = col + 1 + k;
            if row.get(col) {
                row.xor_in_place(pivot_row);
                if rhs.get(col) {
                    rhs.toggle(r);
                }
            }
        }
    }

    true
}

#[inline]
pub fn sample_cols<R: Rng>(rng: &mut R, perm: &mut [usize], n: usize) {
    let total = 2 * n;
    debug_assert_eq!(perm.len(), total);
    for i in 0..n {
        let j = rng.gen_range(i..total);
        perm.swap(i, j);
    }
}

#[inline]
pub fn clear_matrix_rows(a_rows: &mut [HqcGf2]) {
    for r in a_rows {
        r.words.fill(0);
        r.mask_tail();
    }
}

#[inline]
pub fn hqc_column_into(h: &HqcGf2, col: usize, out_col: &mut HqcGf2, tmp_words: &mut Vec<u64>) {
    debug_assert_eq!(out_col.n, h.n);
    let n = h.n;
    // H is [h | I], so columns 0..n-1 are from h, columns n..2n-1 are identity
    if col < n {
        h.rotate_left_into(col, out_col, tmp_words);
    } else {
        out_col.words.fill(0);
        out_col.set(col - n);
        out_col.mask_tail();
    }
}
pub fn build_square_matrix_from_selected_columns(
    n: usize,
    h: &HqcGf2,
    cols: &[usize],
    mat_rows: &mut [HqcGf2],
    col_buf: &mut HqcGf2,
    tmp_words: &mut Vec<u64>,
) {
    debug_assert_eq!(cols.len(), n);
    debug_assert_eq!(mat_rows.len(), n);
    debug_assert_eq!(col_buf.n, n);
    clear_matrix_rows(mat_rows);
    for (k, &col) in cols.iter().enumerate() {
        hqc_column_into(h, col, col_buf, tmp_words);
        for (wi, mut w64) in col_buf.words.iter().copied().enumerate() {
            while w64 != 0 {
                let b = w64.trailing_zeros() as usize;
                let r = (wi << 6) + b;
                if r < n {
                    mat_rows[r].set(k);
                }
                w64 &= w64 - 1;
            }
        }
    }
}
// stern
/// calculates key = (h*y)_J
pub fn h_mul_y_on_window(
    n: usize,
    h: &HqcGf2,
    support_y: &[usize], // indices list
    window: &[usize],
    key: &mut [u64],
) {
    key.fill(0);
    for (i, &pos) in window.iter().enumerate() {
        let mut bit = false;
        for &t in support_y {
            let idx = (pos + n - (t % n)) % n;
            bit ^= h.get(idx);
        }
        if bit {
            key[i / 64] |= 1u64 << (i % 64);
        }
    }
}

/// calculates key = (s XOR h*y)_J
pub fn s_xor_h_mul_y_key_on_window(
    n: usize,
    s: &HqcGf2,
    h: &HqcGf2,
    support: &[usize],
    window: &[usize],
    key: &mut [u64],
) {
    key.fill(0);

    for (i, &pos) in window.iter().enumerate() {
        let mut bit = s.get(pos);
        for &t in support {
            let idx = (pos + n - (t % n)) % n;
            bit ^= h.get(idx);
        }
        if bit {
            key[i / 64] |= 1u64 << (i % 64);
        }
    }
}

/// Enumerate all k-combinations from [0..n),
/// calling `f` for each combination.
pub fn for_each_combination_cf(
    n: usize,
    k: usize,
    mut f: impl FnMut(&[usize]) -> ControlFlow<()>,
) -> ControlFlow<()> {
    if k == 0 {
        return f(&[]);
    }
    if k > n {
        return ControlFlow::Continue(());
    }

    let mut idx: Vec<usize> = (0..k).collect();

    loop {
        if let ControlFlow::Break(()) = f(&idx) {
            return ControlFlow::Break(());
        }

        let mut i = k;
        while i > 0 {
            i -= 1;
            if idx[i] != i + n - k {
                break;
            }
        }
        if i == 0 && idx[0] == n - k {
            break;
        }

        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }

    ControlFlow::Continue(())
}