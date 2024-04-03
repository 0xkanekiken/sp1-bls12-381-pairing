//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate snowbridge_amcl;

pub use snowbridge_amcl::bls381 as BLSCurve;
use snowbridge_amcl::bls381::rom;

use crate::BLSCurve::pair::fexp;
use snowbridge_amcl::bls381::bls381::utils::{
    serialize_uncompressed_g1, serialize_uncompressed_g2,
};
use snowbridge_amcl::rand::RAND;
use BLSCurve::big::Big;
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::pair::{ate, g1mul, g2mul, gtpow};

#[sp1_derive::cycle_tracker]
pub fn main() {
    pairing_check();
}

fn pairing_check() -> bool {
    let mut rng = create_rng();

    // Generate random points in G1 and G2
    let P = ECP::generator();
    let Q = ECP2::generator();

    // Generate random scalars
    let a = Big::randomnum(&Big::new_ints(&rom::CURVE_ORDER), &mut rng);
    let b = Big::randomnum(&Big::new_ints(&rom::CURVE_ORDER), &mut rng);

    // Multiply points by scalars
    println!("cycle-tracker-start: g1_mul");
    let P_a = g1mul(&P, &a); // aP in G1
    println!("cycle-tracker-start: g1_mul");

    println!("cycle-tracker-start: g2_mul");
    let Q_b = g2mul(&Q, &b); // bQ in G2
    println!("cycle-tracker-start: g2_mul");

    // Step 3: Compute pairings
    println!("cycle-tracker-start: ate_Q_Pa");
    let e1 = ate(&Q, &P_a); // e(aP, Q)
    println!("cycle-tracker-start: ate_Q_Pa");

    println!("cycle-tracker-start: ate_P_bQ");
    let e2 = ate(&Q_b, &P); // e(P, bQ)
    println!("cycle-tracker-start: ate_P_bQ");

    println!("cycle-tracker-start: ate_P_Q");
    let e3 = ate(&Q, &P); // e(P, Q)
    println!("cycle-tracker-start: ate_P_Q");

    println!("cycle-tracker-start: gtpow");
    let e3_ab = gtpow(&e3, &(Big::smul(&a, &b))); // (e(P, Q))^(ab)
    println!("cycle-tracker-start: gtpow");

    // Step 4: Check bilinearity property
    fexp(&e1).eq(&fexp(&e2)) && fexp(&e1).eq(&fexp(&e3_ab))

    // let mut g1_point = ECP::generator();

    // let g2_point = ECP::generator();
    // let multiplier: [u8; 48] = [
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
    // ];
    // let multiplier = Big::from_byte_array(&multiplier, 0);

    // println!("cycle-tracker-start: bls12381_mul");
    // let g2_point = g2_point.mul(&multiplier);
    // println!("cycle-tracker-start: bls12381_mul");

    // // println!("g2_point: {:?}", serialize_uncompressed_g1(&g2_point));

    // println!("cycle-tracker-start: bls12381_add");
    // g1_point.add(&g2_point);
    // println!("cycle-tracker-start: bls12381_add");

    // // println!("g1_point: {:?}", serialize_uncompressed_g1(&g1_point));

    // g2_point
}

fn create_rng() -> RAND {
    let mut raw: [u8; 100] = [0; 100];

    let mut rng = RAND::new();
    rng.clean();
    for i in 0..100 {
        raw[i] = i as u8
    }

    rng.seed(100, &raw);
    rng
}