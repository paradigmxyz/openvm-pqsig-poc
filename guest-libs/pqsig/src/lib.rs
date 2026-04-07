#![cfg_attr(target_os = "zkvm", no_std)]

pub use openvm_pqsig_guest::{LeanSigSchemeId as SchemeId, LeanSigVerifyRequest as VerifyRequest};
use openvm_pqsig_guest::{LeanSigSchemeId, LEANSIG_MESSAGE_LENGTH};
#[cfg(target_os = "zkvm")]
use openvm_pqsig_guest::{LeanSigVerifyRequest, LEANSIG_VERIFY_REQUEST_LEN};

#[cfg(any(test, feature = "software"))]
pub mod software;

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
}
