use super::hash::{G, H, I, J};
use super::params::HqcPkeParams;
use super::pke;
use super::types::{
    ct_eq, CiphKem, DkKem, EkKem, Salt16, Seed32, SharedKey32, TypesError,
};

#[derive(Clone, Copy, Debug)]
pub enum DkKemFormat {
    Full,
    Compressed,
}
pub fn keygen_from_seed<P: HqcPkeParams>(
    seed_kem: Seed32,
    fmt: DkKemFormat,
) -> Result<(EkKem<P>, DkKem<P>), TypesError> {
    let i_out = I(&[&seed_kem]);

    let mut seed_pke = [0u8; 32];
    seed_pke.copy_from_slice(&i_out[..32]);

    let sigma = i_out[32..32 + P::K_BYTES].to_vec();

    let (ek_pke, dk_pke) = pke::keygen::<P>(seed_pke);
    let ek_kem = ek_pke;

    let dk_kem = match fmt {
        DkKemFormat::Full => DkKem::<P>::new_full(ek_kem.clone(), dk_pke, sigma, seed_kem)?,
        DkKemFormat::Compressed => DkKem::<P>::new_compressed(seed_kem),
    };

    Ok((ek_kem, dk_kem))
}
pub fn encaps_with<P: HqcPkeParams>(
    ek: &EkKem<P>,
    m: &[u8],
    salt: Salt16,
) -> Result<(SharedKey32, CiphKem<P>), TypesError> {
    if m.len() != P::K_BYTES {
        return Err(TypesError::InvalidLength {
            expected: P::K_BYTES,
            got: m.len(),
        });
    }

    let ek_bytes = ek.to_bytes();
    let h_ek = H(&[&ek_bytes]);

    let g_out = G(&[&h_ek, m, &salt]);

    let mut k = [0u8; 32];
    let mut theta = [0u8; 32];
    k.copy_from_slice(&g_out[..32]);
    theta.copy_from_slice(&g_out[32..64]);

    let c_pke = pke::encrypt::<P>(ek, m, theta)?;

    let c_kem = CiphKem::<P> { c_pke, salt };

    Ok((k, c_kem))
}

pub fn decaps<P: HqcPkeParams>(dk: &DkKem<P>, c: &CiphKem<P>) -> SharedKey32 {
    let (ek, dk_pke, sigma) = match dk {
        DkKem::Full { ek, dk_pke, sigma, .. } => (ek.clone(), dk_pke.clone(), sigma.clone()),
        DkKem::Compressed { seed_kem } => {
            let i_out = I(&[seed_kem]);
            let mut seed_pke = [0u8; 32];
            seed_pke.copy_from_slice(&i_out[..32]);
            let sigma = i_out[32..32 + P::K_BYTES].to_vec();
            let (ek, dk_pke) = pke::keygen::<P>(seed_pke);
            (ek, dk_pke, sigma)
        }
    };

    let ek_bytes = ek.to_bytes();
    let h_ek = H(&[&ek_bytes]);
    let c_kem_bytes = c.to_bytes();
    let k_bar_arr = J(&[&h_ek, &sigma, &c_kem_bytes]);
    let mut k_bar = [0u8; 32];
    k_bar.copy_from_slice(&k_bar_arr);

    let m_opt = pke::decrypt::<P>(&dk_pke, &c.c_pke);
    let m_prime = match m_opt {
        Some(m) => m,
        None => return k_bar,
    };

    let g_out = G(&[&h_ek, &m_prime, &c.salt]);

    let mut k_p = [0u8; 32];
    let mut theta_p = [0u8; 32];
    k_p.copy_from_slice(&g_out[..32]);
    theta_p.copy_from_slice(&g_out[32..64]);

    let c_prime = match pke::encrypt::<P>(&ek, &m_prime, theta_p) {
        Ok(ct) => ct,
        Err(_) => return k_bar,
    };

    if !ct_eq(&c_prime.to_bytes(), &c.c_pke.to_bytes()) {
        return k_bar;
    }

    k_p
}
