use std::path::PathBuf;

use openvm_circuit::arch::VmExecutor;
use openvm_circuit::utils::air_test_with_min_segments;
use openvm_instructions::exe::VmExe;
use openvm_rv32im_circuit::{Rv32ImBuilder, Rv32ImConfig};
use openvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use openvm_toolchain_tests::build_example_program_at_path;
use openvm_transpiler::{transpiler::Transpiler, FromElf};

fn build_tiny_poseidon_exe(example: &str, config: &Rv32ImConfig) -> VmExe<BabyBear> {
    let programs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/programs");
    let elf = build_example_program_at_path(programs_dir, example, config)
        .expect("guest program should build");
    VmExe::from_elf(
        elf,
        Transpiler::<BabyBear>::default()
            .with_extension(Rv32ITranspilerExtension)
            .with_extension(Rv32IoTranspilerExtension)
            .with_extension(Rv32MTranspilerExtension),
    )
    .expect("guest ELF should transpile")
}

#[test]
fn executes_tiny_poseidon_batch_verifier_in_openvm() {
    let config = Rv32ImConfig::default();
    let exe = build_tiny_poseidon_exe("tiny_poseidon_batch_verify", &config);
    let executor = VmExecutor::<BabyBear, _>::new(config).expect("executor config should be valid");
    let instance = executor
        .instance(&exe)
        .expect("guest program should preprocess successfully");
    instance
        .execute(vec![], None)
        .expect("guest program should execute successfully");
}

#[test]
#[ignore = "Full RV32 proof of the tiny software verifier still exceeds default runner budgets."]
fn proves_tiny_poseidon_verifier_in_openvm() {
    let config = Rv32ImConfig::default();
    let exe = build_tiny_poseidon_exe("tiny_poseidon_verify", &config);

    air_test_with_min_segments(Rv32ImBuilder, config, exe, vec![], 1);
}

#[test]
#[ignore = "Full RV32 proof of the tiny batched software verifier still exceeds default runner budgets."]
fn proves_tiny_poseidon_batch_verifier_in_openvm() {
    let config = Rv32ImConfig::default();
    let exe = build_tiny_poseidon_exe("tiny_poseidon_batch_verify", &config);

    air_test_with_min_segments(Rv32ImBuilder, config, exe, vec![], 1);
}
