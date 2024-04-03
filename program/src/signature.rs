extern crate snowbridge_amcl;

use super::amcl_utils::{
    compress_g2, decompress_g2, g2mul, hash_to_curve_g2,
    AmclError, GroupG2, G2_BYTES,
};
use super::keys::SecretKey;

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Signature {
    pub point: GroupG2,
}

impl Signature {
    /// Instantiate a new Signature from a message and a SecretKey.
    pub fn new(msg: &[u8], sk: &SecretKey) -> Self {
        let hash_point = hash_to_curve_g2(msg);
        let sig = g2mul(&hash_point, sk.as_raw());
        Self { point: sig }
    }

    /// Instantiate a Signature from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, AmclError> {
        let point = decompress_g2(bytes)?;
        Ok(Self { point })
    }

    /// Compress the Signature as bytes.
    pub fn as_bytes(&self) -> [u8; G2_BYTES] {
        compress_g2(&self.point)
    }
}