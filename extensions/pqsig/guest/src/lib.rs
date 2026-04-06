#![no_std]

pub const OPCODE: u8 = 0x0b;
pub const PQSIG_FUNCT3: u8 = 0b100;
pub const LEANSIG_VERIFY_FUNCT7: u8 = 0x2;

pub const LEANSIG_MESSAGE_LENGTH: usize = 32;
pub const LEANSIG_VERIFY_REQUEST_WORDS: usize = 7;
pub const LEANSIG_VERIFY_REQUEST_LEN: usize = LEANSIG_VERIFY_REQUEST_WORDS * 4;

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
}

impl LeanSigSchemeId {
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
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LEANSIG_VERIFY_REQUEST_LEN {
            return None;
        }

        Some(Self {
            scheme_id: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            epoch: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            message_ptr: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            public_key_ptr: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
            public_key_len: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            signature_ptr: u32::from_le_bytes(bytes[20..24].try_into().ok()?),
            signature_len: u32::from_le_bytes(bytes[24..28].try_into().ok()?),
        })
    }
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
