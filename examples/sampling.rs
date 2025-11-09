use isd4hqc::sampling::sample_fixed_weight_vect;
use isd4hqc::hash::xof::Shake256Xof;
fn main() {
    let xof = Shake256Xof::new(b"sampling");
    let fixed_weight_vect = sample_fixed_weight_vect(66, 10, &xof);
    println!("{:?}",fixed_weight_vect.ones_indices());
}