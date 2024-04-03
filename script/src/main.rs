use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

const BLS_PAIRING: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    utils::setup_logger();
    let stdin = SP1Stdin::new();
    let proof = SP1Prover::prove(BLS_PAIRING, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(BLS_PAIRING, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
