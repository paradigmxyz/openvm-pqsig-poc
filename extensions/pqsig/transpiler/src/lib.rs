use openvm_instructions::{riscv::RV32_MEMORY_AS, LocalOpcode};
use openvm_instructions_derive::LocalOpcode;
use openvm_pqsig_guest::{LEANSIG_VERIFY_FUNCT7, OPCODE, PQSIG_FUNCT3};
use openvm_stark_backend::p3_field::PrimeField32;
use openvm_transpiler::{util::from_r_type, TranspilerExtension, TranspilerOutput};
use rrs_lib::instruction_formats::RType;
use strum::{EnumCount, EnumIter, FromRepr};

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, EnumCount, EnumIter, FromRepr, LocalOpcode,
)]
#[opcode_offset = 0x800]
#[repr(usize)]
pub enum Rv32PqSigOpcode {
    LeanSigVerify,
}

#[derive(Default)]
pub struct PqSigTranspilerExtension;

impl<F: PrimeField32> TranspilerExtension<F> for PqSigTranspilerExtension {
    fn process_custom(&self, instruction_stream: &[u32]) -> Option<TranspilerOutput<F>> {
        if instruction_stream.is_empty() {
            return None;
        }

        let instruction_u32 = instruction_stream[0];
        let opcode = (instruction_u32 & 0x7f) as u8;
        let funct3 = ((instruction_u32 >> 12) & 0b111) as u8;

        if (opcode, funct3) != (OPCODE, PQSIG_FUNCT3) {
            return None;
        }

        let decoded = RType::new(instruction_u32);
        if decoded.funct7 != LEANSIG_VERIFY_FUNCT7 as u32 {
            return None;
        }

        let instruction = from_r_type(
            Rv32PqSigOpcode::LeanSigVerify.global_opcode().as_usize(),
            RV32_MEMORY_AS as usize,
            &decoded,
            true,
        );
        Some(TranspilerOutput::one_to_one(instruction))
    }
}

#[cfg(test)]
mod tests {
    use openvm_stark_backend::p3_field::PrimeField32;

    use super::*;

    fn encode_r_type(rd: u8, rs1: u8, rs2: u8) -> u32 {
        ((LEANSIG_VERIFY_FUNCT7 as u32) << 25)
            | ((rs2 as u32) << 20)
            | ((rs1 as u32) << 15)
            | ((PQSIG_FUNCT3 as u32) << 12)
            | ((rd as u32) << 7)
            | (OPCODE as u32)
    }

    #[test]
    fn transpiles_leansig_verify_instruction() {
        let word = encode_r_type(10, 11, 12);
        let output = PqSigTranspilerExtension
            .process_custom(&[word])
            .expect("custom instruction should transpile");

        assert_eq!(output.used_u32s, 1);
        let instruction = output.instructions[0]
            .as_ref()
            .expect("one-to-one transpilation should emit an instruction");

        assert_eq!(
            instruction.opcode,
            Rv32PqSigOpcode::LeanSigVerify.global_opcode()
        );
        assert_eq!(instruction.a.as_canonical_u32(), 40);
        assert_eq!(instruction.b.as_canonical_u32(), 44);
        assert_eq!(instruction.c.as_canonical_u32(), 48);
    }
}
