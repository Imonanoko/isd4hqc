use isd4hqc::hqcgf2::HqcGf2;
use isd4hqc::{Gf2Construct,Gf2};
#[test]
fn rotate_right_n66_by1() {
    let n = 66;
    let v = HqcGf2::from_indices(n, &[0, 1, 64, 65]);
    let out = {
        let mut o = HqcGf2::zero_with_len(n);
        v.rotate_right_into(1, &mut o);
        o
    };
    let debug_str = format!("{}, {:#}, {:?}",out,out,out.ones_indices());
    assert_eq!(out.ones_indices(), vec![0, 63, 64, 65],"{}",debug_str);
}
#[test]
fn rotate_right_n128_by64() {
    let n = 128;
    let v = HqcGf2::from_indices(n, &[1, 64]);
    let out = {
        let mut o = HqcGf2::zero_with_len(n);
        v.rotate_right_into(64, &mut o);
        o
    };
    let debug_str = format!("{}, {:#}, {:?}",out,out,out.ones_indices());
    assert_eq!(out.ones_indices(), vec![0,65],"{}",debug_str);
}
#[test]
fn add() {
    let n = 66;
    let u = HqcGf2::from_indices(n, &[0, 2, 7]);
    let v = HqcGf2::from_indices(n, &[0, 1, 64]);
    let s = u.add(&v);
    assert_eq!(s.ones_indices(),vec![1,2,7,64]);
    assert_eq!(s.weight(), 4);
}
#[test]
fn mul() {
    let n = 8;
    let u = HqcGf2::from_indices(n, &[0,2,3,5]);
    let v = HqcGf2::from_indices(n, &[0,5]);
    let s = u.mul(&v);
    assert_eq!(s.ones_indices(),vec![2,6]);
}

#[test]
fn truncate() {
    let src = HqcGf2::from_indices(130, &[0, 1, 2, 63, 64, 65,66,100,127]);
    let got = src.truncate(66);
    assert_eq!(got.ones_indices(),vec![0, 1, 2, 63, 64, 65]);
    assert!(!got.get(66) && !got.get(100) && !got.get(127));
}