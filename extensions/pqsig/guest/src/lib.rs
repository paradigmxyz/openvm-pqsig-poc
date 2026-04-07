#![no_std]

pub const OPCODE: u8 = 0x0b;
pub const PQSIG_FUNCT3: u8 = 0b100;
pub const LEANSIG_VERIFY_FUNCT7: u8 = 0x2;

pub const LEANSIG_MESSAGE_LENGTH: usize = 32;
pub const LEANSIG_VERIFY_REQUEST_WORDS: usize = 7;
pub const LEANSIG_VERIFY_REQUEST_LEN: usize = LEANSIG_VERIFY_REQUEST_WORDS * 4;

const _: [(); LEANSIG_VERIFY_REQUEST_LEN] = [(); core::mem::size_of::<LeanSigVerifyRequest>()];

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LeanSigSchemeId {
    #[default]
    TargetSumLifetime18W1NoOff = 0,
    TargetSumLifetime18W2NoOff = 1,
    TargetSumLifetime18W4NoOff = 2,
    TargetSumLifetime18W8NoOff = 3,
    TargetSumLifetime20W1NoOff = 4,
    TargetSumLifetime20W2NoOff = 5,
    TargetSumLifetime20W4NoOff = 6,
    TargetSumLifetime20W8NoOff = 7,
    AbortingTargetSumLifetime6Dim46Base8 = 8,
    TinyPoseidonTestOnly = 9,
}

impl LeanSigSchemeId {
    pub const ALL: [Self; 10] = [
        Self::TargetSumLifetime18W1NoOff,
        Self::TargetSumLifetime18W2NoOff,
        Self::TargetSumLifetime18W4NoOff,
        Self::TargetSumLifetime18W8NoOff,
        Self::TargetSumLifetime20W1NoOff,
        Self::TargetSumLifetime20W2NoOff,
        Self::TargetSumLifetime20W4NoOff,
        Self::TargetSumLifetime20W8NoOff,
        Self::AbortingTargetSumLifetime6Dim46Base8,
        Self::TinyPoseidonTestOnly,
    ];

    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::TargetSumLifetime18W1NoOff),
            1 => Some(Self::TargetSumLifetime18W2NoOff),
            2 => Some(Self::TargetSumLifetime18W4NoOff),
            3 => Some(Self::TargetSumLifetime18W8NoOff),
            4 => Some(Self::TargetSumLifetime20W1NoOff),
            5 => Some(Self::TargetSumLifetime20W2NoOff),
            6 => Some(Self::TargetSumLifetime20W4NoOff),
            7 => Some(Self::TargetSumLifetime20W8NoOff),
            8 => Some(Self::AbortingTargetSumLifetime6Dim46Base8),
            9 => Some(Self::TinyPoseidonTestOnly),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeanSigVerifyRequest {
    pub scheme_id: u32,
    pub epoch: u32,
    pub message_ptr: u32,
    pub public_key_ptr: u32,
    pub public_key_len: u32,
    pub signature_ptr: u32,
    pub signature_len: u32,
}

impl LeanSigVerifyRequest {
    #[inline(always)]
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LEANSIG_VERIFY_REQUEST_LEN {
            return None;
        }

        Some(Self {
            scheme_id: read_u32_word(bytes, 0)?,
            epoch: read_u32_word(bytes, 1)?,
            message_ptr: read_u32_word(bytes, 2)?,
            public_key_ptr: read_u32_word(bytes, 3)?,
            public_key_len: read_u32_word(bytes, 4)?,
            signature_ptr: read_u32_word(bytes, 5)?,
            signature_len: read_u32_word(bytes, 6)?,
        })
    }

    #[inline(always)]
    pub fn to_le_bytes(self) -> [u8; LEANSIG_VERIFY_REQUEST_LEN] {
        let mut bytes = [0u8; LEANSIG_VERIFY_REQUEST_LEN];
        bytes[0..4].copy_from_slice(&self.scheme_id.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.message_ptr.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.public_key_ptr.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.public_key_len.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.signature_ptr.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.signature_len.to_le_bytes());
        bytes
    }
}

#[inline(always)]
fn read_u32_word(bytes: &[u8], word_index: usize) -> Option<u32> {
    let start = word_index.checked_mul(4)?;
    Some(u32::from_le_bytes(
        bytes.get(start..start + 4)?.try_into().ok()?,
    ))
}

#[cfg(target_os = "zkvm")]
#[inline(always)]
pub fn zkvm_leansig_verify_impl(request: *const u8, request_len: usize, output: *mut u8) {
    openvm_platform::custom_insn_r!(
        opcode = OPCODE,
        funct3 = PQSIG_FUNCT3,
        funct7 = LEANSIG_VERIFY_FUNCT7,
        rd = In output,
        rs1 = In request,
        rs2 = In request_len,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_ids_round_trip() {
        for (value, scheme) in LeanSigSchemeId::ALL.into_iter().enumerate() {
            assert_eq!(LeanSigSchemeId::from_u32(value as u32), Some(scheme));
        }
        assert_eq!(
            LeanSigSchemeId::from_u32(LeanSigSchemeId::ALL.len() as u32),
            None
        );
    }

    #[test]
    fn request_round_trips_through_little_endian_bytes() {
        let request = LeanSigVerifyRequest {
            scheme_id: LeanSigSchemeId::TargetSumLifetime20W4NoOff as u32,
            epoch: 7,
            message_ptr: 0x100,
            public_key_ptr: 0x200,
            public_key_len: 96,
            signature_ptr: 0x400,
            signature_len: 512,
        };

        let bytes = request.to_le_bytes();
        assert_eq!(LeanSigVerifyRequest::from_le_bytes(&bytes), Some(request));
    }

    #[test]
    fn request_rejects_wrong_length() {
        let bytes = [0u8; LEANSIG_VERIFY_REQUEST_LEN - 1];
        assert_eq!(LeanSigVerifyRequest::from_le_bytes(&bytes), None);
    }
}
