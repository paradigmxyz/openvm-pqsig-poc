#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

use openvm_pqsig::software::{
    vectors::{TEST_TINY_EPOCH, TEST_TINY_MESSAGE, TEST_TINY_PK, TEST_TINY_SIG},
    verify_tiny_poseidon_signature,
};

openvm::entry!(main);

pub fn main() {
    assert!(verify_tiny_poseidon_signature(
        &TEST_TINY_PK,
        &TEST_TINY_SIG,
        TEST_TINY_EPOCH,
        &TEST_TINY_MESSAGE,
    ));

    let mut tampered = TEST_TINY_SIG;
    tampered[64] ^= 1;
    assert!(!verify_tiny_poseidon_signature(
        &TEST_TINY_PK,
        &tampered,
        TEST_TINY_EPOCH,
        &TEST_TINY_MESSAGE,
    ));
}
