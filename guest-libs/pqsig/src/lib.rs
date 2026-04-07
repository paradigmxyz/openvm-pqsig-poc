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
        };
        let mut output = [0u8; 4];

        debug_assert_eq!(
            core::mem::size_of::<LeanSigVerifyRequest>(),
            LEANSIG_VERIFY_REQUEST_LEN
        );
        openvm_pqsig_guest::zkvm_leansig_verify_impl(
            (&request as *const LeanSigVerifyRequest).cast::<u8>(),
            LEANSIG_VERIFY_REQUEST_LEN,
            output.as_mut_ptr(),
        );

        u32::from_le_bytes(output) != 0
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
