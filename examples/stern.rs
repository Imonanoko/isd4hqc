use isd4hqc::isd::attack::Attack;
use isd4hqc::isd::{
    Stern,
    params::HqcExperimentParams,
};
use isd4hqc::hqc::types::Seed32;
fn main() {
    let seed_pke:Seed32 = [0u8; 32].into();
    let params = HqcExperimentParams::sparse_parameters_hqc_3(3);
    let instance = params.keygen(seed_pke).unwrap();
    let attack = Stern::default();
    println!("Using attack: {}", attack.name());
    let (h, s) = instance.get_public_key();
    let (y, x) = instance.get_secret_key();
    match attack.solve(params.n, params.w, &h, &s) {
        Ok(Some(solution_y)) => {
            println!("Solution found y: {:?}", solution_y);
            println!("Original y: {:?}", y);
            println!("Match y: {}", &solution_y == y);
            let hy = solution_y.mul_bitpacked(&h);
            let mut solution_x = s.clone();
            solution_x.xor_in_place(&hy);
            println!("Computed x from solution y: {:?}", solution_x);
            println!("Original x: {:?}", x);
            println!("Match x: {}", &solution_x == x);
        }
        Ok(None) => {
            println!("No solution found within all combinations.");
        }
        Err(e) => {
            println!("Error during attack: {}", e);
        }
    }
}