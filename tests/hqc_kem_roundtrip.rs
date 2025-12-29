use isd4hqc::hqc::{
    kem,
    params::{Hqc1Params, Hqc3Params, Hqc5Params, HqcPkeParams},
    types::{Salt16, Seed32},
    hash::xof::Shake256Xof,
};

fn det_seed(label: &[u8]) -> Seed32 {
    let x = Shake256Xof::new(label);
    let b = x.get_bytes(32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

fn det_salt(label: &[u8]) -> Salt16 {
    let x = Shake256Xof::new(label);
    let b = x.get_bytes(16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

fn det_msg<P: HqcPkeParams>(label: &[u8]) -> Vec<u8> {
    let x = Shake256Xof::new(label);
    x.get_bytes(P::K_BYTES)
}

fn roundtrip<P: HqcPkeParams>() {
    let seed_kem = det_seed(b"kem-seed");
    let (ek, dk) = kem::keygen_from_seed::<P>(seed_kem, kem::DkKemFormat::Full).unwrap();

    let m = det_msg::<P>(b"m");
    let salt = det_salt(b"salt");

    let (k1, ct) = kem::encaps_with::<P>(&ek, &m, salt).unwrap();
    let k2 = kem::decaps::<P>(&dk, &ct);

    assert_eq!(k1, k2);

    // sanity: ciphertext size should match params-derived bytes
    assert_eq!(ct.to_bytes().len(), P::C_KEM_BYTES);
}

#[test]
fn kem_roundtrip_hqc1() { roundtrip::<Hqc1Params>(); }

#[test]
fn kem_roundtrip_hqc3() { roundtrip::<Hqc3Params>(); }

#[test]
fn kem_roundtrip_hqc5() { roundtrip::<Hqc5Params>(); }
