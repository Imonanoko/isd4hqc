// use crate::HqcGf2;
// use crate::hqc::params::HqcPkeParams;

// /// 明文 m（之後你可以限制長度 = K/8）
// #[derive(Clone, Debug)]
// pub struct Plaintext(pub Vec<u8>);

// /// ekPKE = (seedPKE.ek, s)
// #[derive(Clone, Debug)]
// pub struct EncryptionKey<P: HqcPkeParams> {
//     pub params: P,
//     pub seed_ek: [u8; P::SEED_BYTES],
//     /// s ∈ F_n^2
//     pub s: HqcGf2,
// }

// /// dkPKE = seedPKE.dk （x,y 都是用 seed 重建）
// #[derive(Clone, Debug)]
// pub struct DecryptionKey<P: HqcPkeParams> {
//     pub params: P,
//     pub seed_dk: [u8; P::SEED_BYTES],
// }

// /// cPKE = (u, v)
// #[derive(Clone, Debug)]
// pub struct Ciphertext<P: HqcPkeParams> {
//     pub params: P,
//     /// u ∈ F_n^2
//     pub u: HqcGf2,
//     /// v ∈ F_{n1 n2}^2 （存 truncated 的那一段）
//     pub v: HqcGf2,
// }