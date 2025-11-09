use isd4hqc::hqc::concatenated_codes::{
    ReedSolomon, RsError, HQC_G1_POLY, HQC_G2_POLY, HQC_G3_POLY,
};
use isd4hqc::gf::gf256;


const HQC_N1: usize = 46;
const HQC_K1: usize = 16;
const HQC_DELTA1: usize = 15;

const HQC_N2: usize = 56;
const HQC_K2: usize = 24;
const HQC_DELTA2: usize = 16;

const HQC_N3: usize = 90;
const HQC_K3: usize = 32;
const HQC_DELTA3: usize = 29;


fn get_sample_message_hqc1() -> Vec<u8> {
    let mut message = vec![0u8; HQC_K1];
    message[0] = 1;
    message[HQC_K1 - 1] = 123;
    message
}

#[test]
fn test_hqc1_encode_is_valid_codeword() {
    let rs_codec = ReedSolomon::new(HQC_N1, HQC_K1, HQC_G1_POLY);
    let message = get_sample_message_hqc1();
    let codeword = rs_codec.encode(&message).unwrap();
    let (_, remainder) = gf256::poly_div_rem(&codeword, &rs_codec.gen_poly);
    assert_eq!(remainder, &[0], "Encoded codeword is not divisible by gen_poly!");
}

#[test]
fn test_hqc1_rs_encode_decode_no_errors() {
    let rs_codec = ReedSolomon::new(HQC_N1, HQC_K1, HQC_G1_POLY);
    let message = get_sample_message_hqc1();

    let codeword = rs_codec.encode(&message).unwrap();
    let decoded_message = rs_codec.decode(&codeword).unwrap();

    assert_eq!(message, decoded_message, "Decoding failed with no errors!");
}

#[test]
fn test_hqc1_rs_corrects_max_errors() {
    let rs_codec = ReedSolomon::new(HQC_N1, HQC_K1, HQC_G1_POLY);
    let message = get_sample_message_hqc1();
    let codeword = rs_codec.encode(&message).unwrap();
    let mut corrupted_codeword = codeword.clone();
    for i in 0..HQC_DELTA1 {
        corrupted_codeword[i * 2] ^= 0xBA;
    }

    match rs_codec.decode(&corrupted_codeword) {
        Ok(decoded_message) => {
            assert_eq!(message, decoded_message, "Failed to decode {HQC_DELTA1} errors!");
            println!("RS (HQC-1) successfully corrected {HQC_DELTA1} errors!");
        }
        Err(e) => {
            panic!("RS (HQC-1) failed to decode {HQC_DELTA1} errors, this should not happen: {:?}", e);
        }
    }
}

#[test]
fn test_hqc1_rs_fails_on_too_many_errors() {
    let rs_codec = ReedSolomon::new(HQC_N1, HQC_K1, HQC_G1_POLY);
    let message = get_sample_message_hqc1();
    let codeword = rs_codec.encode(&message).unwrap();
    let mut corrupted_codeword = codeword.clone();
    for i in 0..(HQC_DELTA1 + 1) {
        corrupted_codeword[i * 2] ^= 0xFF;
    }

    match rs_codec.decode(&corrupted_codeword) {
        Ok(_) => {
            panic!(
                "RS (HQC-1) somehow managed to decode {} errors, this should not happen!",
                HQC_DELTA1 + 1
            );
        }
        Err(e) => {
            assert_eq!(e, RsError::Uncorrectable, "Error type was not Uncorrectable");
            println!(
                "RS (HQC-1) successfully detected {} errors and reported Uncorrectable!",
                HQC_DELTA1 + 1
            );
        }
    }
}

fn get_sample_message_hqc3() -> Vec<u8> {
    let mut message = vec![0u8; HQC_K2];
    message[0] = 42;
    message[HQC_K2 - 1] = 255;
    message
}

#[test]
fn test_hqc3_rs_corrects_max_errors() {
    let rs_codec = ReedSolomon::new(HQC_N2, HQC_K2, HQC_G2_POLY);
    let message = get_sample_message_hqc3();
    let codeword = rs_codec.encode(&message).unwrap();
    let mut corrupted_codeword = codeword.clone();

    for i in 0..HQC_DELTA2 {
        corrupted_codeword[i * 2] ^= 0xCC;
    }

    match rs_codec.decode(&corrupted_codeword) {
        Ok(decoded_message) => {
            assert_eq!(message, decoded_message, "Failed to decode {HQC_DELTA2} errors!");
            println!("RS (HQC-3) successfully corrected {HQC_DELTA2} errors!");
        }
        Err(e) => {
            panic!("RS (HQC-3) failed to decode {HQC_DELTA2} errors, this should not happen: {:?}", e);
        }
    }
}

#[test]
fn test_hqc3_rs_fails_on_too_many_errors() {
    let rs_codec = ReedSolomon::new(HQC_N2, HQC_K2, HQC_G2_POLY);
    let message = get_sample_message_hqc3();
    let codeword = rs_codec.encode(&message).unwrap();
    let mut corrupted_codeword = codeword.clone();
    for i in 0..(HQC_DELTA2 + 1) {
        corrupted_codeword[i * 2] ^= 0xDD;
    }

    match rs_codec.decode(&corrupted_codeword) {
        Ok(_) => {
            panic!(
                "RS (HQC-3) somehow managed to decode {} errors, this should not happen!",
                HQC_DELTA2 + 1
            );
        }
        Err(e) => {
            assert_eq!(e, RsError::Uncorrectable, "Error type was not Uncorrectable");
            println!(
                "RS (HQC-3) successfully detected {} errors and reported Uncorrectable!",
                HQC_DELTA2 + 1
            );
        }
    }
}

fn get_sample_message_hqc5() -> Vec<u8> {
    let mut message = vec![0u8; HQC_K3];
    message[0] = 101;
    message[HQC_K3 - 1] = 102;
    message
}

#[test]
fn test_hqc5_rs_corrects_max_errors() {
    let rs_codec = ReedSolomon::new(HQC_N3, HQC_K3, HQC_G3_POLY);
    let message = get_sample_message_hqc5();
    let codeword = rs_codec.encode(&message).unwrap();
    let mut corrupted_codeword = codeword.clone();
    for i in 0..HQC_DELTA3 {
        corrupted_codeword[i * 3] ^= 0x99;
    }

    match rs_codec.decode(&corrupted_codeword) {
        Ok(decoded_message) => {
            assert_eq!(message, decoded_message, "Failed to decode {HQC_DELTA3} errors!");
            println!("RS (HQC-5) successfully corrected {HQC_DELTA3} errors!");
        }
        Err(e) => {
            panic!("RS (HQC-5) failed to decode {HQC_DELTA3} errors, this should not happen: {:?}", e);
        }
    }
}

#[test]
fn test_hqc5_rs_fails_on_too_many_errors() {
    let rs_codec = ReedSolomon::new(HQC_N3, HQC_K3, HQC_G3_POLY);
    let message = get_sample_message_hqc5();
    let codeword = rs_codec.encode(&message).unwrap();
    let mut corrupted_codeword = codeword.clone();
    for i in 0..(HQC_DELTA3 + 1) {
        corrupted_codeword[i * 2] ^= 0xEE;
    }
    match rs_codec.decode(&corrupted_codeword) {
        Ok(_) => {
            panic!(
                "RS (HQC-5) somehow managed to decode {} errors, this should not happen!",
                HQC_DELTA3 + 1
            );
        }
        Err(e) => {
            assert_eq!(e, RsError::Uncorrectable, "Error type was not Uncorrectable");
            println!(
                "RS (HQC-5) successfully detected {} errors and reported Uncorrectable!",
                HQC_DELTA3 + 1
            );
        }
    }
}