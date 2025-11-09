
pub trait Gf2: Sized + Clone + PartialEq + Eq {
    fn add(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self {
        self.add(other)
    }
    fn inv(&self) -> Option<Self> {
        None
    }
    fn is_zero(&self) -> bool;
}
pub trait Gf2InPlace: Gf2 {
    fn add_in_place(&mut self, other: &Self);
    fn mul_in_place(&mut self, other: &Self);
}

pub trait Gf2Construct {
    fn zero_with_len(n: usize) -> Self;
    fn one_with_len(n: usize) -> Self;
}