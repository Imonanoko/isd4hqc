use isd4hqc::hqc::{
    hash::xof::Shake256Xof,
    kem,
    params::{Hqc1Params, Hqc3Params, Hqc5Params, HqcPkeParams},
    pke,
    types::{Salt16, Seed32},
};

fn det_seed32(label: &[u8]) -> Seed32 {
    let x = Shake256Xof::new(label);
    let b = x.get_bytes(32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

fn det_salt16(label: &[u8]) -> Salt16 {
    let x = Shake256Xof::new(label);
    let b = x.get_bytes(16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

fn msg_from_str<P: HqcPkeParams>(s: &str) -> Vec<u8> {
    let mut m = vec![0u8; P::K_BYTES];
    let raw = s.as_bytes();
    let take = raw.len().min(P::K_BYTES);
    m[..take].copy_from_slice(&raw[..take]);
    m
}

fn msg_to_string_lossy(m: &[u8]) -> String {
    let trimmed = m.iter().copied().rposition(|b| b != 0).map(|i| &m[..=i]).unwrap_or(&[]);
    String::from_utf8_lossy(trimmed).to_string()
}

fn demo_pke<P: HqcPkeParams>(label: &str, input: &str) {
    println!("=== PKE demo: {label} ===");

    let seed_pke = det_seed32(format!("seed-pke-{label}").as_bytes());
    let (ek, dk) = pke::keygen::<P>(seed_pke);

    let m = msg_from_str::<P>(input);
    let theta = det_seed32(format!("theta-{label}").as_bytes());

    let c = pke::encrypt::<P>(&ek, &m, theta).expect("encrypt");
    let m2 = pke::decrypt::<P>(&dk, &c).expect("decrypt");

    println!("K_BYTES = {}", P::K_BYTES);
    println!("plaintext (padded) hex = {}", hex::encode(&m));
    println!("ciphertext bytes       = {}", c.to_bytes().len());
    println!("decrypted hex          = {}", hex::encode(&m2));
    println!("decrypted string       = {}", msg_to_string_lossy(&m2));

    if m2 == m {
        println!("PKE roundtrip: OK\n");
    } else {
        println!("PKE roundtrip: FAIL\n");
    }
}

fn demo_kem<P: HqcPkeParams>(label: &str, input: &str) {
    println!("=== KEM demo: {label} ===");

    // Deterministic seedKEM for reproducible demo
    let seed_kem = det_seed32(format!("seed-kem-{label}").as_bytes());
    let (ek, dk) = kem::keygen_from_seed::<P>(seed_kem, kem::DkKemFormat::Full)
        .expect("kem keygen");

    // In HQC KEM, encaps internally derives theta from (H(ek), m, salt).
    // We use encaps_with for deterministic demo (m and salt fixed).
    let m = msg_from_str::<P>(input);
    let salt = det_salt16(format!("salt-{label}").as_bytes());

    let (k1, ct) = kem::encaps_with::<P>(&ek, &m, salt).expect("encaps");
    let k2 = kem::decaps::<P>(&dk, &ct);

    println!("K_BYTES = {}", P::K_BYTES);
    println!("m (padded) hex   = {}", hex::encode(&m));
    println!("cKEM bytes       = {}", ct.to_bytes().len());
    println!("shared key (enc) = {}", hex::encode(k1));
    println!("shared key (dec) = {}", hex::encode(k2));

    if k1 == k2 {
        println!("KEM decapsulation: OK\n");
    } else {
        println!("KEM decapsulation: FAIL\n");
    }
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_else(|| "Hello HQC from examples!".to_string());

    demo_pke::<Hqc1Params>("HQC-1", &input);
    demo_pke::<Hqc3Params>("HQC-3", &input);
    demo_pke::<Hqc5Params>("HQC-5", &input);

    demo_kem::<Hqc1Params>("HQC-1", &input);
    demo_kem::<Hqc3Params>("HQC-3", &input);
    demo_kem::<Hqc5Params>("HQC-5", &input);
}
