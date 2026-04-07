use openvm_circuit::{arch::*, system::memory::online::GuestMemory};
use openvm_instructions::{
    instruction::Instruction,
    program::DEFAULT_PC_STEP,
    riscv::{RV32_MEMORY_AS, RV32_REGISTER_AS},
    LocalOpcode,
};
use openvm_pqsig::{verify_leansig_bytes, SchemeId};
use openvm_pqsig_guest::{LeanSigSchemeId, LeanSigVerifyRequest, LEANSIG_MESSAGE_LENGTH};
use openvm_pqsig_transpiler::Rv32PqSigOpcode;
use openvm_stark_backend::p3_field::PrimeField32;

#[derive(Clone, Copy, Debug, Default)]
pub struct LeanSigVerifyExecutor;

impl<F: PrimeField32> InterpreterExecutor<F> for LeanSigVerifyExecutor {
    #[cfg(feature = "tco")]
    fn handler<Ctx>(
        &self,
        pc: u32,
        inst: &Instruction<F>,
        data: &mut [u8],
    ) -> Result<Handler<F, Ctx>, StaticProgramError>
    where
        Ctx: ExecutionCtxTrait,
    {
        self.pre_compute_impl(pc, inst, &mut data[..3])?;
        Ok(execute_e1_handler::<_, _>)
    }

    fn pre_compute_size(&self) -> usize {
        3
    }

    #[cfg(not(feature = "tco"))]
    fn pre_compute<Ctx>(
        &self,
        pc: u32,
        inst: &Instruction<F>,
        data: &mut [u8],
    ) -> Result<ExecuteFunc<F, Ctx>, StaticProgramError>
    where
        Ctx: ExecutionCtxTrait,
    {
        self.pre_compute_impl(pc, inst, &mut data[..3])?;
        Ok(execute_e1_impl::<_, _>)
    }
}

#[cfg(feature = "aot")]
impl<F: PrimeField32> AotExecutor<F> for LeanSigVerifyExecutor {}

impl<F: PrimeField32> InterpreterMeteredExecutor<F> for LeanSigVerifyExecutor {
    fn metered_pre_compute_size(&self) -> usize {
        7
    }

    #[cfg(not(feature = "tco"))]
    fn metered_pre_compute<Ctx>(
        &self,
        chip_idx: usize,
        pc: u32,
        inst: &Instruction<F>,
        data: &mut [u8],
    ) -> Result<ExecuteFunc<F, Ctx>, StaticProgramError>
    where
        Ctx: MeteredExecutionCtxTrait,
    {
        data[..4].copy_from_slice(&(chip_idx as u32).to_le_bytes());
        self.pre_compute_impl(pc, inst, &mut data[4..7])?;
        Ok(execute_e2_impl::<_, _>)
    }

    #[cfg(feature = "tco")]
    fn metered_handler<Ctx>(
        &self,
        chip_idx: usize,
        pc: u32,
        inst: &Instruction<F>,
        data: &mut [u8],
    ) -> Result<Handler<F, Ctx>, StaticProgramError>
    where
        Ctx: MeteredExecutionCtxTrait,
    {
        data[..4].copy_from_slice(&(chip_idx as u32).to_le_bytes());
        self.pre_compute_impl(pc, inst, &mut data[4..7])?;
        Ok(execute_e2_handler::<_, _>)
    }
}

#[cfg(feature = "aot")]
impl<F: PrimeField32> AotMeteredExecutor<F> for LeanSigVerifyExecutor {}

#[inline(always)]
fn parse_request(bytes: &[u8]) -> Option<LeanSigVerifyRequest> {
    LeanSigVerifyRequest::from_le_bytes(bytes)
}

#[inline(always)]
unsafe fn execute_e12_impl<F: PrimeField32, CTX: ExecutionCtxTrait>(
    pre_compute: &[u8; 3],
    exec_state: &mut VmExecState<F, GuestMemory, CTX>,
) -> u32 {
    let dst = exec_state.vm_read(RV32_REGISTER_AS, pre_compute[0] as u32);
    let src = exec_state.vm_read(RV32_REGISTER_AS, pre_compute[1] as u32);
    let len = exec_state.vm_read(RV32_REGISTER_AS, pre_compute[2] as u32);
    let dst_u32 = u32::from_le_bytes(dst);
    let src_u32 = u32::from_le_bytes(src);
    let len_u32 = u32::from_le_bytes(len);

    let request_bytes = exec_state.vm_read_slice(RV32_MEMORY_AS, src_u32, len_u32 as usize);
    let result = parse_request(request_bytes)
        .and_then(|request| {
            let scheme = LeanSigSchemeId::from_u32(request.scheme_id)?;
            let scheme: SchemeId = scheme;
            let message: &[u8; LEANSIG_MESSAGE_LENGTH] = exec_state
                .vm_read_slice(RV32_MEMORY_AS, request.message_ptr, LEANSIG_MESSAGE_LENGTH)
                .try_into()
                .ok()?;
            let message = *message;
            let public_key = exec_state
                .vm_read_slice(
                    RV32_MEMORY_AS,
                    request.public_key_ptr,
                    request.public_key_len as usize,
                )
                .to_vec();
            let signature = exec_state
                .vm_read_slice(
                    RV32_MEMORY_AS,
                    request.signature_ptr,
                    request.signature_len as usize,
                )
                .to_vec();
            Some(verify_leansig_bytes(
                scheme,
                request.epoch,
                &message,
                &public_key,
                &signature,
            ))
        })
        .unwrap_or(false);

    exec_state.vm_write(RV32_MEMORY_AS, dst_u32, &u32::from(result).to_le_bytes());
    let pc = exec_state.pc();
    exec_state.set_pc(pc.wrapping_add(DEFAULT_PC_STEP));

    0
}

#[create_handler]
#[inline(always)]
unsafe fn execute_e1_impl<F: PrimeField32, CTX: ExecutionCtxTrait>(
    pre_compute: *const u8,
    exec_state: &mut VmExecState<F, GuestMemory, CTX>,
) {
    let pre_compute = std::slice::from_raw_parts(pre_compute, 3);
    let pre_compute: &[u8; 3] = pre_compute.try_into().expect("fixed precompute size");
    execute_e12_impl::<F, CTX>(pre_compute, exec_state);
}

#[create_handler]
#[inline(always)]
unsafe fn execute_e2_impl<F: PrimeField32, CTX: MeteredExecutionCtxTrait>(
    pre_compute: *const u8,
    exec_state: &mut VmExecState<F, GuestMemory, CTX>,
) {
    let pre_compute = std::slice::from_raw_parts(pre_compute, 7);
    let chip_idx = u32::from_le_bytes(pre_compute[..4].try_into().expect("chip index size"));
    let data: &[u8; 3] = pre_compute[4..7].try_into().expect("fixed precompute size");
    let height = execute_e12_impl::<F, CTX>(data, exec_state);
    exec_state.ctx.on_height_change(chip_idx as usize, height);
}

impl LeanSigVerifyExecutor {
    fn pre_compute_impl<F: PrimeField32>(
        &self,
        pc: u32,
        inst: &Instruction<F>,
        data: &mut [u8],
    ) -> Result<(), StaticProgramError> {
        let Instruction {
            opcode,
            a,
            b,
            c,
            d,
            e,
            ..
        } = inst;

        if d.as_canonical_u32() != RV32_REGISTER_AS || e.as_canonical_u32() != RV32_MEMORY_AS {
            return Err(StaticProgramError::InvalidInstruction(pc));
        }
        if c.as_canonical_u32() == 0 || a.as_canonical_u32() == 0 || b.as_canonical_u32() == 0 {
            return Err(StaticProgramError::InvalidInstruction(pc));
        }
        if inst.c.as_canonical_u32() > u8::MAX as u32
            || inst.b.as_canonical_u32() > u8::MAX as u32
            || inst.a.as_canonical_u32() > u8::MAX as u32
        {
            return Err(StaticProgramError::InvalidInstruction(pc));
        }

        data.copy_from_slice(&[
            a.as_canonical_u32() as u8,
            b.as_canonical_u32() as u8,
            c.as_canonical_u32() as u8,
        ]);
        assert_eq!(&Rv32PqSigOpcode::LeanSigVerify.global_opcode(), opcode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use leansig::{
        serialization::Serializable,
        signature::{
            generalized_xmss::instantiations_aborting::lifetime_2_to_the_6::SIGAbortingTargetSumLifetime6Dim46Base8,
            SignatureScheme, SignatureSchemeSecretKey,
        },
    };
    use openvm_circuit::arch::VmExecutor;
    use openvm_instructions::{
        exe::VmExe,
        instruction::Instruction,
        program::Program,
        riscv::{RV32_MEMORY_AS, RV32_REGISTER_AS},
        LocalOpcode, SystemOpcode,
    };
    use openvm_pqsig_guest::{
        LeanSigSchemeId, LeanSigVerifyRequest, LEANSIG_VERIFY_FUNCT7, LEANSIG_VERIFY_REQUEST_LEN,
        OPCODE, PQSIG_FUNCT3,
    };
    use openvm_pqsig_transpiler::PqSigTranspilerExtension;
    use openvm_stark_sdk::p3_baby_bear::BabyBear;
    use openvm_transpiler::TranspilerExtension;

    use crate::PqSigRv32Config;

    fn encode_r_type(rd: u8, rs1: u8, rs2: u8) -> u32 {
        ((LEANSIG_VERIFY_FUNCT7 as u32) << 25)
            | ((rs2 as u32) << 20)
            | ((rs1 as u32) << 15)
            | ((PQSIG_FUNCT3 as u32) << 12)
            | ((rd as u32) << 7)
            | (OPCODE as u32)
    }

    fn write_bytes(memory: &mut BTreeMap<(u32, u32), u8>, addr_space: u32, ptr: u32, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            memory.insert((addr_space, ptr + offset as u32), byte);
        }
    }

    fn write_u32(memory: &mut BTreeMap<(u32, u32), u8>, addr_space: u32, ptr: u32, value: u32) {
        write_bytes(memory, addr_space, ptr, &value.to_le_bytes());
    }

    fn sample_signature() -> (Vec<u8>, Vec<u8>, [u8; 32], u32) {
        let mut rng = rand::rng();
        let epoch = 2;
        let message = [7u8; 32];
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

    fn run_verification(message: [u8; 32], tamper_signature: bool) -> bool {
        let (public_key, mut signature, signed_message, epoch) = sample_signature();
        let message = if message == [0u8; 32] {
            signed_message
        } else {
            message
        };
        if tamper_signature {
            signature[0] ^= 1;
        }

        let request_ptr = 0x100;
        let message_ptr = 0x200;
        let public_key_ptr = 0x300;
        let signature_ptr = 0x800;
        let output_ptr = 0x1000;

        let request = LeanSigVerifyRequest {
            scheme_id: LeanSigSchemeId::AbortingTargetSumLifetime6Dim46Base8 as u32,
            epoch,
            message_ptr,
            public_key_ptr,
            public_key_len: public_key.len() as u32,
            signature_ptr,
            signature_len: signature.len() as u32,
        };

        let custom_instruction = PqSigTranspilerExtension
            .process_custom(&[encode_r_type(10, 11, 12)])
            .expect("custom instruction should transpile")
            .instructions
            .into_iter()
            .next()
            .flatten()
            .expect("instruction should exist");

        let program = Program::from_instructions(&[
            custom_instruction,
            Instruction::from_isize(SystemOpcode::TERMINATE.global_opcode(), 0, 0, 0, 0, 0),
        ]);

        let mut init_memory = BTreeMap::new();
        write_bytes(&mut init_memory, RV32_MEMORY_AS, request_ptr, unsafe {
            std::slice::from_raw_parts(
                (&request as *const LeanSigVerifyRequest).cast::<u8>(),
                LEANSIG_VERIFY_REQUEST_LEN,
            )
        });
        write_bytes(&mut init_memory, RV32_MEMORY_AS, message_ptr, &message);
        write_bytes(
            &mut init_memory,
            RV32_MEMORY_AS,
            public_key_ptr,
            &public_key,
        );
        write_bytes(&mut init_memory, RV32_MEMORY_AS, signature_ptr, &signature);
        write_u32(&mut init_memory, RV32_REGISTER_AS, 4 * 10, output_ptr);
        write_u32(&mut init_memory, RV32_REGISTER_AS, 4 * 11, request_ptr);
        write_u32(
            &mut init_memory,
            RV32_REGISTER_AS,
            4 * 12,
            LEANSIG_VERIFY_REQUEST_LEN as u32,
        );

        let executor = VmExecutor::<BabyBear, _>::new(PqSigRv32Config::default())
            .expect("executor config should be valid");
        let exe = VmExe::new(program).with_init_memory(init_memory);
        let interpreter = executor
            .instance(&exe)
            .expect("program should preprocess successfully");
        let final_state = interpreter
            .execute(Vec::<Vec<BabyBear>>::new(), None)
            .expect("program should execute successfully");
        let output = unsafe { final_state.memory.read::<u8, 4>(RV32_MEMORY_AS, output_ptr) };
        u32::from_le_bytes(output) != 0
    }

    #[test]
    fn executes_leansig_verification_and_rejects_tampering() {
        assert!(run_verification([0u8; 32], false));
        assert!(!run_verification([9u8; 32], false));
        assert!(!run_verification([0u8; 32], true));
    }
}
