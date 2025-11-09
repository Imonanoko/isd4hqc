use super::Domain;
use sha3::{Shake256,digest::{Update,ExtendableOutput,XofReader}};
use std::cell::RefCell;
pub struct Shake256Xof{
    reader: RefCell<Box<dyn XofReader>>,
}

impl Shake256Xof {
    pub fn new(seed: &[u8]) -> Self {
        let mut s = Shake256::default();
        s.update(seed);
        s.update(Domain::Xof.label());
        let reader = s.finalize_xof();
        Self{
            reader: RefCell::new(Box::new(reader))
        }
    }
    pub fn get_bytes(&self, len:usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.reader.borrow_mut().read(&mut out);
        out
    }
}