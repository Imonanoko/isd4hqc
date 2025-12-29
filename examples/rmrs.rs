use std::env;

use isd4hqc::hqc::concatenated_codes::{ReedSolomon, RmrsCode};
use isd4hqc::hqc::concatenated_codes::reed_solomon::{HQC_G1_POLY, HQC_G2_POLY, HQC_G3_POLY};

fn usage() -> ! {
    eprintln!(
        "Usage:
  cargo run --example rmrs -- <hqc1|hqc3|hqc5> <message_string>

Example:
  cargo run --example rmrs -- hqc1 \"hello\"
  cargo run --example rmrs -- hqc3 \"attack at dawn\"

Notes:
- message_string is UTF-8; it will be used as raw bytes.
- If message length > k1, this example will reject (you can change to truncate if you prefer)."
    );
    std::process::exit(2);
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn make_rmrs(instance: &str) -> RmrsCode {
    match instance.to_ascii_lowercase().as_str() {
        "hqc1" | "hqc-1" | "1" => {
            // RS-S1: [46,16], RM duplicated x3
            let rs = ReedSolomon::new(46, 16, HQC_G1_POLY);
            RmrsCode::new(rs, 3)
        }
        "hqc3" | "hqc-3" | "3" => {
            // RS-S2: [56,24], RM duplicated x5
            let rs = ReedSolomon::new(56, 24, HQC_G2_POLY);
            RmrsCode::new(rs, 5)
        }
        "hqc5" | "hqc-5" | "5" => {
            // RS-S3: [90,32], RM duplicated x5
            let rs = ReedSolomon::new(90, 32, HQC_G3_POLY);
            RmrsCode::new(rs, 5)
        }
        _ => {
            eprintln!("Unknown instance: {instance}");
            usage();
        }
    }
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        usage();
    }

    let instance = args.remove(0);
    let msg_str = args.remove(0);

    let rmrs = make_rmrs(&instance);

    let msg = msg_str.as_bytes().to_vec();
    if msg.len() > rmrs.rs.k {
        eprintln!(
            "Input message too long for {instance}: got {} bytes, but k1 = {} bytes.",
            msg.len(),
            rmrs.rs.k
        );
        eprintln!("Tip: shorten input, or modify this example to truncate/hash the input.");
        std::process::exit(1);
    }

    // Encode (RS encoder in your implementation left-pads zeros to length k1)
    let cw = rmrs.encode(&msg).expect("RMRS encode failed");

    // Decode back
    let dec = rmrs.decode(&cw).expect("RMRS decode failed");

    // RS decoder returns k1 bytes; because RS encode left-pads zeros, recovered message is zero-padded too.
    // Extract the suffix equal to original message length for a fair round-trip check.
    let recovered_suffix = if msg.is_empty() {
        Vec::new()
    } else {
        dec[dec.len() - msg.len()..].to_vec()
    };

    println!("=== RMRS demo ===");
    println!("Instance      : {instance}");
    println!("RS (n1,k1,δ)   : ({},{},{})", rmrs.rs.n, rmrs.rs.k, rmrs.rs.delta);
    println!("RM multiplicity: {}", rmrs.rm.multiplicity);
    println!("RM n2 bytes    : {}", rmrs.rm.n2_bytes());
    println!("Codeword bytes : {}", cw.len());
    println!();

    println!("Input string   : {msg_str:?}");
    println!("Input bytes    : {} ({})", hex_encode(&msg), msg.len());
    println!();

    // Warning: this can be long (HQC-5 codeword is 90*80=7200 bytes => 14400 hex chars).
    println!("Encoded hex    : {}", hex_encode(&cw));
    println!();

    println!("Decoded (k1)   : {} ({} bytes)", hex_encode(&dec), dec.len());
    println!(
        "Recovered tail : {} ({} bytes)",
        hex_encode(&recovered_suffix),
        recovered_suffix.len()
    );

    if recovered_suffix == msg {
        println!("Result         : OK (round-trip matches input bytes)");
    } else {
        println!("Result         : MISMATCH (check bit order / RMRS wiring)");
        std::process::exit(1);
    }
}
