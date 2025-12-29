use super::hash::I;
use super::hash::xof::Shake256Xof;
use super::hqcgf2::HqcGf2;
use super::params::HqcPkeParams;
use super::sampling::{sample_fixed_weight_vect, sample_vect};
use super::types::{CiphPke, DkPke, EkPke, Seed32, TypesError};

use super::concatenated_codes::reed_solomon::ReedSolomon;
use super::concatenated_codes::RmrsCode;

/// Build RMRS codec for a given parameter set P.
fn rmrs_codec<P: HqcPkeParams>() -> RmrsCode {
    let rs = ReedSolomon::new(P::N1, P::K_BYTES, P::RS_GEN_POLY);
    RmrsCode::new(rs, P::RM_MULT)
}

/// HQC-PKE.Keygen(seedPKE) -> (ekPKE, dkPKE)
pub fn keygen<P: HqcPkeParams>(seed_pke: Seed32) -> (EkPke<P>, DkPke<P>) {
    // (seed_dk, seed_ek) <- I(seed_pke)
    let i_out = I(&[&seed_pke]);
    let mut seed_dk = [0u8; 32];
    let mut seed_ek = [0u8; 32];
    seed_dk.copy_from_slice(&i_out[..32]);
    seed_ek.copy_from_slice(&i_out[32..64]);

    // ctx_dk samples y, x (both weight w)
    let ctx_dk = Shake256Xof::new(&seed_dk);
    let y = sample_fixed_weight_vect(P::N, P::W, &ctx_dk);
    let x = sample_fixed_weight_vect(P::N, P::W, &ctx_dk);

    // ctx_ek samples h (uniform)
    let ctx_ek = Shake256Xof::new(&seed_ek);
    let h = sample_vect(P::N, &ctx_ek);

    // s = x + h*y
    let hy = h.mul_bitpacked(&y);
    let mut s_vec = x;
    s_vec.xor_in_place(&hy);

    // ekPKE=(seed_ek, s_bytes), dkPKE=seed_dk
    let s_bytes = s_vec.to_bytes_le_bits(); // requires your LE packing
    let ek = EkPke::<P>::new(seed_ek, s_bytes)
        .expect("internal: s_bytes length mismatch");
    let dk = DkPke::<P>::new(seed_dk);
    (ek, dk)
}

/// HQC-PKE.Encrypt(ekPKE, m, theta) -> cPKE
pub fn encrypt<P: HqcPkeParams>(
    ek: &EkPke<P>,
    m: &[u8],
    theta: Seed32,
) -> Result<CiphPke<P>, TypesError> {
    if m.len() != P::K_BYTES {
        return Err(TypesError::InvalidLength {
            expected: P::K_BYTES,
            got: m.len(),
        });
    }

    // Reconstruct h from seed_ek
    let ctx_ek = Shake256Xof::new(&ek.seed_ek);
    let h = sample_vect(P::N, &ctx_ek);

    // Parse s from ek bytes
    let s_vec = HqcGf2::from_bytes_le_bits(P::N, &ek.s);

    // Sample r2, e, r1 from ctx(theta)
    let ctx_theta = Shake256Xof::new(&theta);
    let r2 = sample_fixed_weight_vect(P::N, P::W_R, &ctx_theta);
    let e = sample_fixed_weight_vect(P::N, P::W_E, &ctx_theta);
    let r1 = sample_fixed_weight_vect(P::N, P::W_R, &ctx_theta);

    // u = r1 + h*r2
    let hr2 = h.mul_bitpacked(&r2);
    let mut u_vec = r1;
    u_vec.xor_in_place(&hr2);

    // t = s*r2 + e
    let sr2 = s_vec.mul_bitpacked(&r2);
    let mut t_vec = sr2;
    t_vec.xor_in_place(&e);

    // Truncate(t, ell)  <=> take first n1*n2 bits
    let t_trunc = t_vec.truncate(P::N1N2_BITS);

    // v = RMRS.Encode(m) + t_trunc
    let rmrs = rmrs_codec::<P>();
    let v_code_bytes = rmrs.encode(m).map_err(|_| TypesError::InvalidFormat("rmrs.encode"))?;
    // v_code is F2^{n1*n2}
    let mut v_vec = HqcGf2::from_bytes_le_bits(P::N1N2_BITS, &v_code_bytes);
    v_vec.xor_in_place(&t_trunc);

    // Output cPKE=(u_bytes, v_bytes)
    let u_bytes = u_vec.to_bytes_le_bits();
    let v_bytes = v_vec.to_bytes_le_bits();
    CiphPke::<P>::new(u_bytes, v_bytes)
}

/// HQC-PKE.Decrypt(dkPKE, cPKE) -> m or ⊥
/// Return None for ⊥ to support KEM decapsulation logic.
pub fn decrypt<P: HqcPkeParams>(dk: &DkPke<P>, c: &CiphPke<P>) -> Option<Vec<u8>> {
    // Reconstruct y, x from seed_dk
    let ctx_dk = Shake256Xof::new(&dk.seed_dk);
    let y = sample_fixed_weight_vect(P::N, P::W, &ctx_dk);
    let _x = sample_fixed_weight_vect(P::N, P::W, &ctx_dk); // not needed for decrypt

    // Parse u, v
    let u_vec = HqcGf2::from_bytes_le_bits(P::N, &c.u);
    let v_vec = HqcGf2::from_bytes_le_bits(P::N1N2_BITS, &c.v);

    // v - Truncate(u*y, ell)  (sub = XOR in F2)
    let uy = u_vec.mul_bitpacked(&y);
    let uy_trunc = uy.truncate(P::N1N2_BITS);

    let mut v_minus = v_vec;
    v_minus.xor_in_place(&uy_trunc);

    // RMRS.Decode
    let rmrs = rmrs_codec::<P>();
    let cw_bytes = v_minus.to_bytes_le_bits();

    match rmrs.decode(&cw_bytes) {
        Ok(m) => Some(m),
        Err(_e) => None, // include RM + RS failure as ⊥
    }
}
