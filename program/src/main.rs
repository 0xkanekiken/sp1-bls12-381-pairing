//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate snowbridge_amcl;

pub use self::snowbridge_amcl::bls381 as BLSCurve;

use snowbridge_amcl::bls381::bls381::utils::{serialize_uncompressed_g1, serialize_uncompressed_g2};
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::pair;

#[sp1_derive::cycle_tracker]
pub fn main() {
    pairing_check();
}

fn pairing_check() -> bool {
    let g1_point = ECP::generator();
    let g2_point = ECP2::generator();
    let mut r = pair::initmp();

    println!("cycle-tracker-start: pair_another_start");
    pair::another(&mut r, &g2_point, &g1_point);
    println!("cycle-tracker-start: pair_another_end");

    println!("cycle-tracker-start: miller_start");
    let mut v = pair::miller(&r);
    println!("cycle-tracker-start: miller_end");

    println!("cycle-tracker-start: fexp_start");
    v = pair::fexp(&v);
    println!("cycle-tracker-start: fexp_end");

    v.is_unity()
}