#![cfg_attr(target_os = "zkvm", no_std)]

#[cfg(target_os = "zkvm")]
extern crate alloc;

pub use openvm_pqsig_guest::{LeanSigSchemeId as SchemeId, LeanSigVerifyRequest as VerifyRequest};
use openvm_pqsig_guest::{LeanSigSchemeId, LEANSIG_MESSAGE_LENGTH};
#[cfg(target_os = "zkvm")]
use openvm_pqsig_guest::{LeanSigVerifyRequest, LEANSIG_VERIFY_REQUEST_LEN};
use sha2::{Digest, Sha256};

#[cfg(target_os = "zkvm")]
use alloc::vec::Vec;
#[cfg(not(target_os = "zkvm"))]
use std::vec::Vec;

#[cfg(any(test, feature = "software"))]
pub mod software;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchVerificationResult {
    pub verified_count: usize,
    pub first_invalid_index: Option<usize>,
}

impl BatchVerificationResult {
    #[inline(always)]
    pub const fn all_valid(self) -> bool {
        self.first_invalid_index.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchVerificationStatement {
    pub scheme: LeanSigSchemeId,
    pub epoch: u32,
    pub message: [u8; LEANSIG_MESSAGE_LENGTH],
    pub signer_count: usize,
    pub signer_set_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchVerificationOutcome {
    pub result: BatchVerificationResult,
    pub statement: Option<BatchVerificationStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSetWitness {
    pub public_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchVerificationLeaf {
    pub statement: BatchVerificationStatement,
    pub signer_set: SignerSetWitness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveAggregationNode {
    pub statement: BatchVerificationStatement,
    pub child_statement_digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveAggregationEnvelope {
    pub node: RecursiveAggregationNode,
    pub signer_set: SignerSetWitness,
    pub child_statements: Vec<BatchVerificationStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursiveAggregationInput {
    Leaf(BatchVerificationLeaf),
    Envelope(RecursiveAggregationEnvelope),
}

#[inline(always)]
pub fn verify_leansig_bytes(
    scheme: LeanSigSchemeId,
    epoch: u32,
    message: &[u8; LEANSIG_MESSAGE_LENGTH],
    public_key_ssz: &[u8],
    signature_ssz: &[u8],
) -> bool {
    #[cfg(not(target_os = "zkvm"))]
    {
        native::verify_leansig_bytes_native(scheme, epoch, message, public_key_ssz, signature_ssz)
    }

    #[cfg(target_os = "zkvm")]
    {
        let request = LeanSigVerifyRequest {
            scheme_id: scheme as u32,
            epoch,
            message_ptr: message.as_ptr() as usize as u32,
            public_key_ptr: public_key_ssz.as_ptr() as usize as u32,
            public_key_len: public_key_ssz.len() as u32,
            signature_ptr: signature_ssz.as_ptr() as usize as u32,
            signature_len: signature_ssz.len() as u32,
        }
        .to_le_bytes();
        let mut output = [0u8; 4];

        openvm_pqsig_guest::zkvm_leansig_verify_impl(
            request.as_ptr(),
            LEANSIG_VERIFY_REQUEST_LEN,
            output.as_mut_ptr(),
        );

        u32::from_le_bytes(output) != 0
    }
}

#[inline(always)]
pub fn verify_leansig_batch_bytes(
    scheme: LeanSigSchemeId,
    epoch: u32,
    message: &[u8; LEANSIG_MESSAGE_LENGTH],
    batch: &[(&[u8], &[u8])],
) -> bool {
    verify_leansig_batch_bytes_detailed(scheme, epoch, message, batch).all_valid()
}

#[inline(always)]
pub fn verify_leansig_batch_bytes_detailed(
    scheme: LeanSigSchemeId,
    epoch: u32,
    message: &[u8; LEANSIG_MESSAGE_LENGTH],
    batch: &[(&[u8], &[u8])],
) -> BatchVerificationResult {
    verify_leansig_batch_bytes_with_statement(scheme, epoch, message, batch).result
}

#[inline(always)]
pub fn verify_leansig_batch_bytes_with_statement(
    scheme: LeanSigSchemeId,
    epoch: u32,
    message: &[u8; LEANSIG_MESSAGE_LENGTH],
    batch: &[(&[u8], &[u8])],
) -> BatchVerificationOutcome {
    if batch.is_empty() {
        return BatchVerificationOutcome {
            result: BatchVerificationResult {
                verified_count: 0,
                first_invalid_index: Some(0),
            },
            statement: None,
        };
    }

    let result = {
        #[cfg(not(target_os = "zkvm"))]
        {
            native::verify_leansig_batch_bytes_native(scheme, epoch, message, batch)
        }

        #[cfg(target_os = "zkvm")]
        {
            let mut result = BatchVerificationResult {
                verified_count: batch.len(),
                first_invalid_index: None,
            };

            for (index, (public_key, signature)) in batch.iter().enumerate() {
                if !verify_leansig_bytes(scheme, epoch, message, public_key, signature) {
                    result = BatchVerificationResult {
                        verified_count: index,
                        first_invalid_index: Some(index),
                    };
                    break;
                }
            }

            result
        }
    };

    let statement = result
        .first_invalid_index
        .is_none()
        .then(|| BatchVerificationStatement {
            scheme,
            epoch,
            message: *message,
            signer_count: count_unique_public_keys(batch),
            signer_set_digest: hash_signer_set(batch),
        });

    BatchVerificationOutcome { result, statement }
}

fn count_unique_public_keys(batch: &[(&[u8], &[u8])]) -> usize {
    dedup_sorted_public_keys(batch).len()
}

fn hash_signer_set(batch: &[(&[u8], &[u8])]) -> [u8; 32] {
    let sorted = dedup_sorted_public_keys(batch);
    hash_sorted_public_keys(&sorted)
}

fn hash_sorted_public_keys(sorted: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((sorted.len() as u64).to_le_bytes());
    for public_key in sorted {
        hasher.update((public_key.len() as u64).to_le_bytes());
        hasher.update(public_key);
    }
    hasher.finalize().into()
}

fn dedup_sorted_public_keys<'a>(batch: &'a [(&'a [u8], &'a [u8])]) -> Vec<&'a [u8]> {
    let mut public_keys = batch
        .iter()
        .map(|(public_key, _)| *public_key)
        .collect::<Vec<_>>();
    public_keys.sort_unstable();
    public_keys.dedup();
    public_keys
}

impl SignerSetWitness {
    pub fn new(mut public_keys: Vec<Vec<u8>>) -> Self {
        public_keys.sort_unstable();
        public_keys.dedup();
        Self { public_keys }
    }

    pub fn from_batch(batch: &[(&[u8], &[u8])]) -> Self {
        let public_keys = dedup_sorted_public_keys(batch)
            .into_iter()
            .map(|public_key| public_key.to_vec())
            .collect();
        Self { public_keys }
    }

    pub fn signer_count(&self) -> usize {
        self.public_keys.len()
    }

    pub fn digest(&self) -> [u8; 32] {
        let refs = self
            .public_keys
            .iter()
            .map(|public_key| public_key.as_slice())
            .collect::<Vec<_>>();
        hash_sorted_public_keys(&refs)
    }
}

impl BatchVerificationStatement {
    pub fn has_same_context_as(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.epoch == other.epoch && self.message == other.message
    }

    pub fn matches_signer_set(&self, signer_set: &SignerSetWitness) -> bool {
        self.signer_count == signer_set.signer_count()
            && self.signer_set_digest == signer_set.digest()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.scheme as u8]);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.message);
        hasher.update((self.signer_count as u64).to_le_bytes());
        hasher.update(self.signer_set_digest);
        hasher.finalize().into()
    }
}

impl RecursiveAggregationEnvelope {
    pub fn statement(&self) -> &BatchVerificationStatement {
        &self.node.statement
    }

    pub fn digest(&self) -> [u8; 32] {
        self.statement().digest()
    }
}

impl RecursiveAggregationInput {
    fn statement(&self) -> &BatchVerificationStatement {
        match self {
            Self::Leaf(leaf) => &leaf.statement,
            Self::Envelope(envelope) => envelope.statement(),
        }
    }

    fn signer_set(&self) -> &SignerSetWitness {
        match self {
            Self::Leaf(leaf) => &leaf.signer_set,
            Self::Envelope(envelope) => &envelope.signer_set,
        }
    }

    fn digest(&self) -> [u8; 32] {
        self.statement().digest()
    }
}

impl BatchVerificationLeaf {
    pub fn digest(&self) -> [u8; 32] {
        self.statement.digest()
    }
}

pub fn build_batch_verification_leaf(
    scheme: LeanSigSchemeId,
    epoch: u32,
    message: &[u8; LEANSIG_MESSAGE_LENGTH],
    batch: &[(&[u8], &[u8])],
) -> Option<BatchVerificationLeaf> {
    let signer_set = SignerSetWitness::from_batch(batch);
    let outcome = verify_leansig_batch_bytes_with_statement(scheme, epoch, message, batch);
    let statement = outcome.statement?;
    Some(BatchVerificationLeaf {
        statement,
        signer_set,
    })
}

pub fn build_recursive_aggregation_envelope(
    inputs: &[RecursiveAggregationInput],
) -> Option<RecursiveAggregationEnvelope> {
    if inputs.is_empty() {
        return None;
    }

    let first = inputs.first()?;
    let mut union = Vec::<Vec<u8>>::new();
    let mut child_statements = Vec::with_capacity(inputs.len());
    let mut child_statement_digests = Vec::with_capacity(inputs.len());

    for input in inputs {
        let statement = input.statement();
        let signer_set = input.signer_set();

        if !statement.has_same_context_as(first.statement()) {
            return None;
        }
        if !statement.matches_signer_set(signer_set) {
            return None;
        }

        child_statements.push(statement.clone());
        child_statement_digests.push(input.digest());
        union.extend(signer_set.public_keys.iter().cloned());
    }

    let signer_set = SignerSetWitness::new(union);
    Some(RecursiveAggregationEnvelope {
        node: RecursiveAggregationNode {
            statement: BatchVerificationStatement {
                scheme: first.statement().scheme,
                epoch: first.statement().epoch,
                message: first.statement().message,
                signer_count: signer_set.signer_count(),
                signer_set_digest: signer_set.digest(),
            },
            child_statement_digests,
        },
        signer_set,
        child_statements,
    })
}

pub fn aggregate_batch_verification_leaves(
    leaves: &[BatchVerificationLeaf],
) -> Option<RecursiveAggregationNode> {
    let inputs = leaves
        .iter()
        .cloned()
        .map(RecursiveAggregationInput::Leaf)
        .collect::<Vec<_>>();
    Some(build_recursive_aggregation_envelope(&inputs)?.node)
}

#[cfg(test)]
mod tests {
    use leansig::{
        serialization::Serializable,
        signature::{
            generalized_xmss::instantiations_aborting::lifetime_2_to_the_6::SIGAbortingTargetSumLifetime6Dim46Base8,
            SignatureScheme, SignatureSchemeSecretKey,
        },
    };

    use super::*;

    fn sample_signature() -> (Vec<u8>, Vec<u8>, [u8; LEANSIG_MESSAGE_LENGTH], u32) {
        let mut rng = rand::rng();
        let epoch = 2;
        let message = [7u8; LEANSIG_MESSAGE_LENGTH];
        let (public_key, mut secret_key) = SIGAbortingTargetSumLifetime6Dim46Base8::key_gen(
            &mut rng,
            0,
            SIGAbortingTargetSumLifetime6Dim46Base8::LIFETIME as usize,
        );
        while !secret_key.get_prepared_interval().contains(&(epoch as u64)) {
            secret_key.advance_preparation();
        }
        let signature = SIGAbortingTargetSumLifetime6Dim46Base8::sign(&secret_key, epoch, &message)
            .expect("sample signature should sign successfully");

        (public_key.to_bytes(), signature.to_bytes(), message, epoch)
    }

    #[test]
    fn native_verifier_accepts_real_signature_and_rejects_tampering() {
        let (public_key, mut signature, message, epoch) = sample_signature();
        assert!(verify_leansig_bytes(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &public_key,
            &signature,
        ));

        signature[0] ^= 1;
        assert!(!verify_leansig_bytes(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &public_key,
            &signature,
        ));
    }

    #[test]
    fn native_verifier_rejects_malformed_serialization_for_all_schemes() {
        for scheme in LeanSigSchemeId::ALL {
            assert!(!verify_leansig_bytes(
                scheme,
                0,
                &[0u8; LEANSIG_MESSAGE_LENGTH],
                &[1, 2, 3],
                &[4, 5, 6],
            ));
        }
    }

    #[test]
    fn native_batch_verifier_accepts_multiple_real_signatures() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let batch = [(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])];

        assert!(verify_leansig_batch_bytes(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &batch,
        ));
    }

    #[test]
    fn native_batch_verifier_rejects_empty_batch() {
        let (_pk, _sig, message, epoch) = sample_signature();

        assert_eq!(
            verify_leansig_batch_bytes_detailed(
                LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
                epoch,
                &message,
                &[],
            ),
            BatchVerificationResult {
                verified_count: 0,
                first_invalid_index: Some(0),
            }
        );
        assert!(!verify_leansig_batch_bytes(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[],
        ));
    }

    #[test]
    fn native_batch_verifier_rejects_invalid_member() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, mut sig2, _, _) = sample_signature();
        sig2[0] ^= 1;
        let batch = [(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])];

        assert!(!verify_leansig_batch_bytes(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &batch,
        ));
    }

    #[test]
    fn native_batch_verifier_reports_first_invalid_index() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, mut sig2, _, _) = sample_signature();
        sig2[0] ^= 1;
        let batch = [(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])];

        let result = verify_leansig_batch_bytes_detailed(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &batch,
        );

        assert_eq!(
            result,
            BatchVerificationResult {
                verified_count: 1,
                first_invalid_index: Some(1),
            }
        );
    }

    #[test]
    fn native_batch_verifier_rejects_malformed_member_serialization() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let batch = [(&pk1[..], &sig1[..]), (&[1u8, 2, 3][..], &[4u8, 5, 6][..])];

        assert_eq!(
            verify_leansig_batch_bytes_detailed(
                LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
                epoch,
                &message,
                &batch,
            ),
            BatchVerificationResult {
                verified_count: 1,
                first_invalid_index: Some(1),
            }
        );
    }

    #[test]
    fn batch_statement_is_order_independent_and_deduplicated() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let ordered = [
            (&pk1[..], &sig1[..]),
            (&pk2[..], &sig2[..]),
            (&pk1[..], &sig1[..]),
        ];
        let reversed = [(&pk2[..], &sig2[..]), (&pk1[..], &sig1[..])];

        let ordered_outcome = verify_leansig_batch_bytes_with_statement(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &ordered,
        );
        let reversed_outcome = verify_leansig_batch_bytes_with_statement(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &reversed,
        );

        assert_eq!(ordered_outcome.result.verified_count, 3);
        assert_eq!(ordered_outcome.result.first_invalid_index, None);
        assert_eq!(ordered_outcome.statement, reversed_outcome.statement);
        assert_eq!(ordered_outcome.statement.unwrap().signer_count, 2);
    }

    #[test]
    fn batch_statement_is_absent_for_invalid_batch() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, mut sig2, _, _) = sample_signature();
        sig2[0] ^= 1;
        let batch = [(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])];

        let outcome = verify_leansig_batch_bytes_with_statement(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &batch,
        );

        assert_eq!(outcome.result.verified_count, 1);
        assert_eq!(outcome.result.first_invalid_index, Some(1));
        assert!(outcome.statement.is_none());
    }

    #[test]
    fn builds_batch_leaf_with_deduplicated_signer_set() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let batch = [
            (&pk1[..], &sig1[..]),
            (&pk2[..], &sig2[..]),
            (&pk1[..], &sig1[..]),
        ];

        let leaf = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &batch,
        )
        .expect("valid batch should build an aggregation leaf");

        assert_eq!(leaf.statement.signer_count, 2);
        assert_eq!(leaf.signer_set.signer_count(), 2);
        assert_eq!(leaf.statement.signer_set_digest, leaf.signer_set.digest());
    }

    #[test]
    fn aggregates_multiple_batch_leaves() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let (pk3, sig3, _, _) = sample_signature();

        let left = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])],
        )
        .expect("left leaf should build");
        let right = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk2[..], &sig2[..]), (&pk3[..], &sig3[..])],
        )
        .expect("right leaf should build");

        let parent = aggregate_batch_verification_leaves(&[left.clone(), right.clone()])
            .expect("matching leaves should aggregate");

        assert_eq!(parent.statement.scheme, left.statement.scheme);
        assert_eq!(parent.statement.epoch, epoch);
        assert_eq!(parent.statement.message, message);
        assert_eq!(parent.statement.signer_count, 3);
        assert_eq!(parent.child_statement_digests.len(), 2);
    }

    #[test]
    fn builds_recursive_envelope_from_mixed_inputs() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let (pk3, sig3, _, _) = sample_signature();
        let (pk4, sig4, _, _) = sample_signature();

        let leaf_a = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])],
        )
        .expect("first leaf should build");
        let leaf_b = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk2[..], &sig2[..]), (&pk3[..], &sig3[..])],
        )
        .expect("second leaf should build");
        let parent = build_recursive_aggregation_envelope(&[
            RecursiveAggregationInput::Leaf(leaf_a.clone()),
            RecursiveAggregationInput::Leaf(leaf_b.clone()),
        ])
        .expect("parent envelope should build");
        let leaf_c = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk3[..], &sig3[..]), (&pk4[..], &sig4[..])],
        )
        .expect("third leaf should build");

        let root = build_recursive_aggregation_envelope(&[
            RecursiveAggregationInput::Envelope(parent.clone()),
            RecursiveAggregationInput::Leaf(leaf_c.clone()),
        ])
        .expect("root envelope should build");

        assert_eq!(parent.statement().signer_count, 3);
        assert_eq!(parent.child_statements.len(), 2);
        assert_eq!(parent.node.child_statement_digests.len(), 2);
        assert_eq!(root.statement().signer_count, 4);
        assert_eq!(root.child_statements.len(), 2);
        assert_eq!(root.node.child_statement_digests.len(), 2);
        assert_eq!(
            root.node.child_statement_digests,
            vec![parent.digest(), leaf_c.statement.digest()]
        );
    }

    #[test]
    fn rejects_aggregation_when_leaf_context_mismatches() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let left = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk1[..], &sig1[..])],
        )
        .expect("left leaf should build");
        let mut right = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk2[..], &sig2[..])],
        )
        .expect("right leaf should build");
        right.statement.epoch += 1;

        assert!(aggregate_batch_verification_leaves(&[left, right]).is_none());
    }

    #[test]
    fn rejects_recursive_envelope_when_child_witness_is_inconsistent() {
        let (pk1, sig1, message, epoch) = sample_signature();
        let (pk2, sig2, _, _) = sample_signature();
        let mut leaf = build_batch_verification_leaf(
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8,
            epoch,
            &message,
            &[(&pk1[..], &sig1[..]), (&pk2[..], &sig2[..])],
        )
        .expect("leaf should build");
        leaf.signer_set.public_keys.reverse();

        assert!(
            build_recursive_aggregation_envelope(&[RecursiveAggregationInput::Leaf(leaf)])
                .is_none()
        );
    }
}

#[cfg(not(target_os = "zkvm"))]
mod native {
    use leansig::{
        serialization::Serializable,
        signature::{
            generalized_xmss::{
                instantiations_aborting::lifetime_2_to_the_6::SIGAbortingTargetSumLifetime6Dim46Base8,
                instantiations_poseidon::{
                    lifetime_2_to_the_18::target_sum::{
                        SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W2NoOff,
                        SIGTargetSumLifetime18W4NoOff, SIGTargetSumLifetime18W8NoOff,
                    },
                    lifetime_2_to_the_20::target_sum::{
                        SIGTargetSumLifetime20W1NoOff, SIGTargetSumLifetime20W2NoOff,
                        SIGTargetSumLifetime20W4NoOff, SIGTargetSumLifetime20W8NoOff,
                    },
                },
            },
            SignatureScheme,
        },
    };

    use super::*;

    pub(super) fn verify_leansig_bytes_native(
        scheme: LeanSigSchemeId,
        epoch: u32,
        message: &[u8; LEANSIG_MESSAGE_LENGTH],
        public_key_ssz: &[u8],
        signature_ssz: &[u8],
    ) -> bool {
        match scheme {
            LeanSigSchemeId::TargetSumLifetime18W1NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime18W1NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime18W2NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime18W2NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime18W4NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime18W4NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime18W8NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime18W8NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime20W1NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime20W1NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime20W2NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime20W2NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime20W4NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime20W4NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::TargetSumLifetime20W8NoOff => {
                verify_with_scheme::<SIGTargetSumLifetime20W8NoOff>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8 => {
                verify_with_scheme::<SIGAbortingTargetSumLifetime6Dim46Base8>(
                    epoch,
                    message,
                    public_key_ssz,
                    signature_ssz,
                )
            }
        }
    }

    pub(super) fn verify_leansig_batch_bytes_native(
        scheme: LeanSigSchemeId,
        epoch: u32,
        message: &[u8; LEANSIG_MESSAGE_LENGTH],
        batch: &[(&[u8], &[u8])],
    ) -> BatchVerificationResult {
        match scheme {
            LeanSigSchemeId::TargetSumLifetime18W1NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime18W1NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime18W2NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime18W2NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime18W4NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime18W4NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime18W8NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime18W8NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime20W1NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime20W1NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime20W2NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime20W2NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime20W4NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime20W4NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::TargetSumLifetime20W8NoOff => {
                verify_batch_with_scheme::<SIGTargetSumLifetime20W8NoOff>(epoch, message, batch)
            }
            LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8 => {
                verify_batch_with_scheme::<SIGAbortingTargetSumLifetime6Dim46Base8>(
                    epoch, message, batch,
                )
            }
        }
    }

    fn verify_with_scheme<S>(
        epoch: u32,
        message: &[u8; LEANSIG_MESSAGE_LENGTH],
        public_key_ssz: &[u8],
        signature_ssz: &[u8],
    ) -> bool
    where
        S: SignatureScheme,
    {
        let Ok(public_key) = <S::PublicKey as Serializable>::from_bytes(public_key_ssz) else {
            return false;
        };
        let Ok(signature) = <S::Signature as Serializable>::from_bytes(signature_ssz) else {
            return false;
        };

        S::verify(&public_key, epoch, message, &signature)
    }

    fn verify_batch_with_scheme<S>(
        epoch: u32,
        message: &[u8; LEANSIG_MESSAGE_LENGTH],
        batch: &[(&[u8], &[u8])],
    ) -> BatchVerificationResult
    where
        S: SignatureScheme,
    {
        for (index, (public_key, signature)) in batch.iter().enumerate() {
            if !verify_with_scheme::<S>(epoch, message, public_key, signature) {
                return BatchVerificationResult {
                    verified_count: index,
                    first_invalid_index: Some(index),
                };
            }
        }

        BatchVerificationResult {
            verified_count: batch.len(),
            first_invalid_index: None,
        }
    }
}
