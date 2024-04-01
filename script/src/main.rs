//! A simple script to generate and verify the proof of a given program.

use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier, utils};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    utils::setup_logger();
    let stdin = SP1Stdin::new();
    let proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
