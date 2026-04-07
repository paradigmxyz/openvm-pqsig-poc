#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

use openvm_pqsig::software::{
    vectors::{
        TEST_TINY_A_EPOCH, TEST_TINY_A_MESSAGE, TEST_TINY_A_PK, TEST_TINY_A_SIG,
        TEST_TINY_B_EPOCH, TEST_TINY_B_MESSAGE, TEST_TINY_B_PK, TEST_TINY_B_SIG,
    },
    verify_tiny_poseidon_batch, verify_tiny_poseidon_batch_with_summary,
};

openvm::entry!(main);

pub fn main() {
    assert_eq!(TEST_TINY_A_EPOCH, TEST_TINY_B_EPOCH);
    assert_eq!(TEST_TINY_A_MESSAGE, TEST_TINY_B_MESSAGE);

    let batch = [
        (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
        (&TEST_TINY_B_PK[..], &TEST_TINY_B_SIG[..]),
    ];
    let reverse_batch = [
        (&TEST_TINY_B_PK[..], &TEST_TINY_B_SIG[..]),
        (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
    ];
    let duplicate_batch = [
        (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
        (&TEST_TINY_B_PK[..], &TEST_TINY_B_SIG[..]),
        (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
    ];

    let summary = verify_tiny_poseidon_batch_with_summary(
        &batch,
        TEST_TINY_A_EPOCH,
        &TEST_TINY_A_MESSAGE,
    )
    .expect("valid tiny batch should verify");
    assert!(verify_tiny_poseidon_batch(
        &batch,
        TEST_TINY_A_EPOCH,
        &TEST_TINY_A_MESSAGE,
    ));
    assert_eq!(summary.signer_count, 2);
    assert_eq!(
        summary,
        verify_tiny_poseidon_batch_with_summary(
            &reverse_batch,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        )
        .expect("reordered batch should preserve the signer-set commitment"),
    );
    assert_eq!(
        summary,
        verify_tiny_poseidon_batch_with_summary(
            &duplicate_batch,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        )
        .expect("duplicate signer entries should fold into the same signer set"),
    );

    let mut tampered = TEST_TINY_B_SIG;
    tampered[80] ^= 1;
    let invalid_batch = [
        (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
        (&TEST_TINY_B_PK[..], &tampered[..]),
    ];
    assert!(verify_tiny_poseidon_batch_with_summary(
        &invalid_batch,
        TEST_TINY_A_EPOCH,
        &TEST_TINY_A_MESSAGE,
    )
    .is_none());
}
