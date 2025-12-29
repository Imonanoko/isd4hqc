use isd4hqc::hqc::concatenated_codes::{ReedMuller, ReedSolomon, RmrsCode};
use isd4hqc::hqc::concatenated_codes::reed_solomon::{HQC_G1_POLY, HQC_G2_POLY, HQC_G3_POLY};

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&x, &y)| x ^ y).collect()
}

fn blocks_are_identical(buf: &[u8], block_len: usize) -> bool {
    assert!(block_len > 0);
    assert_eq!(buf.len() % block_len, 0);
    let first = &buf[0..block_len];
    buf.chunks(block_len).all(|c| c == first)
}

#[test]
fn rm_encode_known_vectors() {
    // multiplicity doesn't matter for base pattern; we just check the first 16 bytes (RM(1,7))
    let rm = ReedMuller::new(3);

    // sym=0x00 => all coefficients 0 => all-zero codeword
    let cw0 = rm.encode_symbol(0x00);
    assert_eq!(cw0.len(), rm.n2_bytes());
    assert!(cw0.iter().all(|&b| b == 0));

    // sym=0x80 => a0=1 constant term => all-ones codeword
    let cw_const1 = rm.encode_symbol(0x80);
    assert!(cw_const1.iter().all(|&b| b == 0xFF));

    // sym=0x01 => only a7 = 1 (x7 term, which is LSB of index)
    // For i=0..7, x7 = 0,1,0,1,0,1,0,1 => bits = 01010101 => 0x55 in big-endian packing.
    let cw_x7 = rm.encode_symbol(0x01);
    assert_eq!(cw_x7[0], 0x55);
}

#[test]
fn rm_is_linear_over_gf2_for_symbols() {
    // RM(1,7) is a linear binary code; with our mapping:
    // encode(a xor b) == encode(a) xor encode(b)
    let rm = ReedMuller::new(5);

    let pairs = [
        (0x00u8, 0x00u8),
        (0x12u8, 0x34u8),
        (0x80u8, 0x01u8),
        (0xABu8, 0xCDu8),
        (0xFFu8, 0x0Fu8),
    ];

    for (a, b) in pairs {
        let ea = rm.encode_symbol(a);
        let eb = rm.encode_symbol(b);
        let eab = rm.encode_symbol(a ^ b);

        let x = xor_bytes(&ea, &eb);
        assert_eq!(x, eab, "linearity failed at a={:#04x}, b={:#04x}", a, b);
    }
}

#[test]
fn rm_duplicate_blocks_are_identical() {
    for mult in [3usize, 5usize] {
        let rm = ReedMuller::new(mult);
        let cw = rm.encode_symbol(0xA7);

        // Each 16-byte base RM(1,7) block should be identical due to duplication
        assert!(blocks_are_identical(&cw, ReedMuller::RM_N_BYTES));
    }
}

#[test]
fn rm_roundtrip_all_symbols_no_noise() {
    for mult in [3usize, 5usize] {
        let rm = ReedMuller::new(mult);

        for sym in 0u16..=255 {
            let sym = sym as u8;
            let cw = rm.encode_symbol(sym);
            let dec = rm.decode_symbol(&cw).expect("decode should succeed");
            assert_eq!(dec, sym, "RM roundtrip failed (mult={mult}) for sym={:#04x}", sym);
        }
    }
}

fn make_msg(len: usize, seed: u8) -> Vec<u8> {
    // deterministic nontrivial pattern
    (0..len).map(|i| seed.wrapping_add(i as u8).rotate_left((i % 7) as u32)).collect()
}

#[test]
fn rmrs_roundtrip_hqc1_hqc3_hqc5_no_noise() {
    // HQC-1: RS-S1 [46,16], RM duplicated x3
    let rs1 = ReedSolomon::new(46, 16, HQC_G1_POLY);
    let c1 = RmrsCode::new(rs1, 3);
    let m1 = make_msg(c1.rs.k, 0x11);
    let cw1 = c1.encode(&m1).expect("encode ok");
    let dec1 = c1.decode(&cw1).expect("decode ok");
    assert_eq!(dec1, m1);

    // HQC-3: RS-S2 [56,24], RM duplicated x5
    let rs2 = ReedSolomon::new(56, 24, HQC_G2_POLY);
    let c3 = RmrsCode::new(rs2, 5);
    let m3 = make_msg(c3.rs.k, 0x22);
    let cw3 = c3.encode(&m3).expect("encode ok");
    let dec3 = c3.decode(&cw3).expect("decode ok");
    assert_eq!(dec3, m3);

    // HQC-5: RS-S3 [90,32], RM duplicated x5
    let rs3 = ReedSolomon::new(90, 32, HQC_G3_POLY);
    let c5 = RmrsCode::new(rs3, 5);
    let m5 = make_msg(c5.rs.k, 0x33);
    let cw5 = c5.encode(&m5).expect("encode ok");
    let dec5 = c5.decode(&cw5).expect("decode ok");
    assert_eq!(dec5, m5);
}

#[test]
fn rmrs_rs_symbol_error_correction_with_block_replacement() {
    // 這個測試很關鍵：我們用「替換整個 RM block」的方式，
    // 讓 RM 一定解出錯的 symbol，從而測 RS 是否真的能修到 delta 個 symbol errors。

    // Use HQC-1 parameters: RS-S1 [46,16], delta=(46-16)/2=15
    let rs = ReedSolomon::new(46, 16, HQC_G1_POLY);
    let code = RmrsCode::new(rs, 3);

    let msg = make_msg(code.rs.k, 0x5A);
    let rs_cw = code.rs.encode(&msg).expect("rs encode ok");
    let mut cw = code.encode(&msg).expect("rmrs encode ok");

    let block_bytes = code.rm.n2_bytes();
    let delta = code.rs.delta;

    // Corrupt <= delta symbols deterministically by replacing their RM blocks with a wrong symbol encoding.
    // Pick 10 indices well within correction capability.
    let corrupt_count = 10usize;
    assert!(corrupt_count <= delta);

    for i in 0..corrupt_count {
        let wrong_sym = rs_cw[i] ^ 0xA5; // guaranteed different unless rs_cw[i]==0xA5; but xor makes it different anyway
        let wrong_block = code.rm.encode_symbol(wrong_sym);

        let start = i * block_bytes;
        let end = start + block_bytes;
        cw[start..end].copy_from_slice(&wrong_block);
    }

    let dec = code.decode(&cw).expect("should be correctable");
    assert_eq!(dec, msg);
}

#[test]
fn rmrs_uncorrectable_when_more_than_delta_symbols_wrong() {
    let rs = ReedSolomon::new(46, 16, HQC_G1_POLY);
    let code = RmrsCode::new(rs, 3);

    let msg = make_msg(code.rs.k, 0xC3);
    let rs_cw = code.rs.encode(&msg).expect("rs encode ok");
    let mut cw = code.encode(&msg).expect("rmrs encode ok");

    let block_bytes = code.rm.n2_bytes();
    let delta = code.rs.delta;

    // corrupt delta+1 blocks => RS should fail
    for i in 0..(delta + 1) {
        let wrong_sym = rs_cw[i] ^ 0x3C;
        let wrong_block = code.rm.encode_symbol(wrong_sym);

        let start = i * block_bytes;
        let end = start + block_bytes;
        cw[start..end].copy_from_slice(&wrong_block);
    }

    let res = code.decode(&cw);
    assert!(res.is_err(), "expected uncorrectable but got ok");
}
