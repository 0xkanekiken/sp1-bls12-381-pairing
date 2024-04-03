extern crate snowbridge_amcl;
#[cfg(feature = "std")]
extern crate hex;
extern crate rand;

use crate::BLSCurve;

use BLSCurve::bls381::proof_of_possession::DST_G2;
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;

pub use snowbridge_amcl::errors::AmclError;
pub use BLSCurve::big::Big;
pub use BLSCurve::bls381::proof_of_possession::{G1_BYTES, G2_BYTES, SECRET_KEY_BYTES};
pub use BLSCurve::bls381::utils::{
    self, deserialize_g1, deserialize_g2, serialize_g1, serialize_g2, subgroup_check_g1,
    
};
pub use BLSCurve::pair::{g1mul, g2mul};
pub use BLSCurve::rom::CURVE_ORDER;

pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;

#[cfg(feature = "std")]
lazy_static! {
    pub static ref GENERATORG1: GroupG1 = GroupG1::generator();
    pub static ref GENERATORG2: GroupG2 = GroupG2::generator();
}

// Take given message convert it to GroupG2 point
pub fn hash_to_curve_g2(msg: &[u8]) -> GroupG2 {
    utils::hash_to_curve_g2(msg, DST_G2)
}

// Take a GroupG1 point (x, y) and compress it to a 384 bit array.
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn compress_g1(g1: &GroupG1) -> [u8; G1_BYTES] {
    serialize_g1(g1)
}

// Take a 384 bit array and convert to GroupG1 point (x, y)
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn decompress_g1(g1_bytes: &[u8]) -> Result<GroupG1, AmclError> {
    // Ensure it is compressed
    if g1_bytes.len() != G1_BYTES {
        return Err(AmclError::InvalidG1Size);
    }
    deserialize_g1(g1_bytes)
}

// Take a GroupG2 point (x, y) and compress it to a 384*2 bit array.
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn compress_g2(g2: &GroupG2) -> [u8; G2_BYTES] {
    serialize_g2(g2)
}

// Take a 384*2 bit array and convert to GroupG2 point (x, y)
// See https://github.com/zkcrypto/pairing/blob/master/src/bls12_381/README.md#serialization
pub fn decompress_g2(g2_bytes: &[u8]) -> Result<GroupG2, AmclError> {
    // Ensure it is compressed
    if g2_bytes.len() != G2_BYTES {
        return Err(AmclError::InvalidG2Size);
    }
    deserialize_g2(g2_bytes)
}