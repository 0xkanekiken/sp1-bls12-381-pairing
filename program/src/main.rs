//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

// extern crate snowbridge_milagro_bls;
extern crate snowbridge_amcl;
mod amcl_utils;
pub mod keys;
mod signature;

use keys::{PublicKey, SecretKey};
use signature::Signature;
pub use snowbridge_amcl::bls381 as BLSCurve;
// use BLSCurve::bls381::proof_of_possession::DST_G2;
use amcl_utils::hash_to_curve_g2;
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::fp12::FP12;
use BLSCurve::pair::{ate2, fexp};
// use snowbridge_amcl::bls381::rom;

// use snowbridge_amcl::bls381::bls381::utils::{
//     serialize_uncompressed_g1, serialize_uncompressed_g2,
// };
// use snowbridge_amcl::rand::RAND;
// use BLSCurve::big::Big;
// use BLSCurve::pair::{ate, g1mul, g2mul, gtpow};

pub fn main() {
    helios_sig_verification();
}

// fn pairing_check() -> bool {
//     // let mut g1_point = ECP::generator();

//     // let g2_point = ECP::generator();
//     // let multiplier: [u8; 48] = [
//     //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//     //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
//     // ];
//     // let multiplier = Big::from_byte_array(&multiplier, 0);

//     // println!("cycle-tracker-start: bls12381_mul");
//     // let g2_point = g2_point.mul(&multiplier);
//     // println!("cycle-tracker-start: bls12381_mul");

//     // // println!("g2_point: {:?}", serialize_uncompressed_g1(&g2_point));

//     // println!("cycle-tracker-start: bls12381_add");
//     // g1_point.add(&g2_point);
//     // println!("cycle-tracker-start: bls12381_add");

//     // // println!("g1_point: {:?}", serialize_uncompressed_g1(&g1_point));

//     // g2_point
// }

fn helios_sig_verification() {
    let sk_bytes = vec![
        78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194,
        233, 117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111,
    ];
    let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&sk);

    let message = "succinct labs".as_bytes();
    println!("cycle-tracker-start: signing");
    let signature = Signature::new(&message, &sk);
    println!("cycle-tracker-end: signing");
    assert!(verify(&signature, &message, &pk));
}

pub fn verify(sign: &Signature, msg: &[u8], pk: &PublicKey) -> bool {
    println!("cycle-tracker-start: hashing_to_curve_g2");
    let mut msg_hash_point = hash_to_curve_g2(msg);
    msg_hash_point.affine();
    println!("cycle-tracker-end: hashing_to_curve_g2");

    // Faster ate2 evaualtion checks e(S, -G1) * e(H, PK) == 1
    let mut generator_g1_negative = ECP::generator();
    println!("cycle-tracker-start: neg");
    generator_g1_negative.neg();
    println!("cycle-tracker-end: neg");

    println!("cycle-tracker-start: ate2_evaluation");
    let eval = ate2_evaluation(
        &sign.point,
        &generator_g1_negative,
        &msg_hash_point,
        &pk.point,
    );
    println!("cycle-tracker-end: ate2_evaluation");

    eval
}

// Evaluation of e(A, B) * e(C, D) == 1
pub fn ate2_evaluation(a: &ECP2, b: &ECP, c: &ECP2, d: &ECP) -> bool {
    let mut pairing = ate2(a, b, c, d);
    pairing = fexp(&pairing);
    FP12::new_int(1).equals(&pairing)
}
