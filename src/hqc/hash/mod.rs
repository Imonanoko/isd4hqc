mod domain;
pub mod xof;
mod sha3;
pub(crate) mod kdf;

use domain::Domain;
use sha3::{sha3_256_with_domain,sha3_512_with_domain};
pub(crate) use kdf::{G,H,J,I};