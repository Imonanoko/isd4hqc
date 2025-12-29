use isd4hqc::hqc::{
    pke,
    params::{Hqc1Params, Hqc3Params, Hqc5Params, HqcPkeParams},
    hash::xof::Shake256Xof,
    types::Seed32,
};

fn det_seed(label: &[u8]) -> Seed32 {
    let x = Shake256Xof::new(label);
    let b = x.get_bytes(32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

fn det_msg<P: HqcPkeParams>(label: &[u8]) -> Vec<u8> {
    let x = Shake256Xof::new(label);
    x.get_bytes(P::K_BYTES)
}

fn roundtrip<P: HqcPkeParams>() {
    let seed_pke = det_seed(b"seed-pke");
    let (ek, dk) = pke::keygen::<P>(seed_pke);

    let m = det_msg::<P>(b"m");
    let theta = det_seed(b"theta");

    let c = pke::encrypt::<P>(&ek, &m, theta).expect("encrypt");
    let m2 = pke::decrypt::<P>(&dk, &c).expect("decrypt should succeed");
    assert_eq!(m2, m);

    // deterministic check
    let c2 = pke::encrypt::<P>(&ek, &m, theta).expect("encrypt2");
    assert_eq!(c2.to_bytes(), c.to_bytes());
}

#[test] fn pke_rt_hqc1(){ roundtrip::<Hqc1Params>(); }
#[test] fn pke_rt_hqc3(){ roundtrip::<Hqc3Params>(); }
#[test] fn pke_rt_hqc5(){ roundtrip::<Hqc5Params>(); }
