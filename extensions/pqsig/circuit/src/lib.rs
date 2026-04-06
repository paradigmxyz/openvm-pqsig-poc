#![cfg_attr(feature = "tco", allow(incomplete_features))]
#![cfg_attr(feature = "tco", feature(explicit_tail_calls))]
#![cfg_attr(feature = "tco", allow(internal_features))]
#![cfg_attr(feature = "tco", feature(core_intrinsics))]

use std::result::Result;

use derive_more::derive::From;
use openvm_circuit::{
    arch::{
        AirInventory, AirInventoryError, ChipInventory, ChipInventoryError,
        ExecutorInventoryBuilder, ExecutorInventoryError, InitFileGenerator, MatrixRecordArena,
        RowMajorMatrixArena, SystemConfig, VmBuilder, VmChipComplex, VmCircuitExtension,
        VmExecutionExtension, VmField, VmProverExtension,
    },
    system::{SystemChipInventory, SystemCpuBuilder, SystemExecutor},
};
use openvm_circuit_derive::{AnyEnum, Executor, MeteredExecutor, PreflightExecutor, VmConfig};
use openvm_instructions::LocalOpcode;
use openvm_pqsig_transpiler::Rv32PqSigOpcode;
use openvm_rv32im_circuit::{
    Rv32I, Rv32IExecutor, Rv32ImCpuProverExt, Rv32Io, Rv32IoExecutor, Rv32M, Rv32MExecutor,
};
use openvm_stark_backend::{
    config::{StarkGenericConfig, Val},
    prover::cpu::{CpuBackend, CpuDevice},
};
use openvm_stark_sdk::engine::StarkEngine;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

mod executor;
pub use executor::LeanSigVerifyExecutor;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct PqSig;

#[derive(Clone, From, AnyEnum, Executor, MeteredExecutor, PreflightExecutor)]
#[cfg_attr(
    feature = "aot",
    derive(
        openvm_circuit_derive::AotExecutor,
        openvm_circuit_derive::AotMeteredExecutor
    )
)]
pub enum PqSigExecutor {
    LeanSig(LeanSigVerifyExecutor),
}

impl<F> VmExecutionExtension<F> for PqSig {
    type Executor = PqSigExecutor;

    fn extend_execution(
        &self,
        inventory: &mut ExecutorInventoryBuilder<F, PqSigExecutor>,
    ) -> Result<(), ExecutorInventoryError> {
        inventory.add_executor(
            LeanSigVerifyExecutor,
            Rv32PqSigOpcode::iter().map(|opcode| opcode.global_opcode()),
        )?;
        Ok(())
    }
}

impl<SC: StarkGenericConfig> VmCircuitExtension<SC> for PqSig {
    fn extend_circuit(&self, _inventory: &mut AirInventory<SC>) -> Result<(), AirInventoryError> {
        Ok(())
    }
}

pub struct PqSigCpuProverExt;

impl<E, SC, RA> VmProverExtension<E, RA, PqSig> for PqSigCpuProverExt
where
    SC: StarkGenericConfig,
    E: StarkEngine<SC = SC, PB = CpuBackend<SC>, PD = CpuDevice<SC>>,
    RA: RowMajorMatrixArena<Val<SC>>,
{
    fn extend_prover(
        &self,
        _: &PqSig,
        _inventory: &mut ChipInventory<SC, RA, CpuBackend<SC>>,
    ) -> Result<(), ChipInventoryError> {
        Ok(())
    }
}

#[derive(Clone, Debug, VmConfig, derive_new::new, Serialize, Deserialize)]
pub struct PqSigRv32Config {
    #[config(executor = "SystemExecutor<F>")]
    pub system: SystemConfig,
    #[extension]
    pub rv32i: Rv32I,
    #[extension]
    pub rv32m: Rv32M,
    #[extension]
    pub io: Rv32Io,
    #[extension]
    pub pqsig: PqSig,
}

impl Default for PqSigRv32Config {
    fn default() -> Self {
        Self {
            system: SystemConfig::default(),
            rv32i: Rv32I,
            rv32m: Rv32M::default(),
            io: Rv32Io,
            pqsig: PqSig,
        }
    }
}

impl InitFileGenerator for PqSigRv32Config {}

#[derive(Clone)]
pub struct PqSigRv32CpuBuilder;

impl<E, SC> VmBuilder<E> for PqSigRv32CpuBuilder
where
    SC: StarkGenericConfig,
    E: StarkEngine<SC = SC, PB = CpuBackend<SC>, PD = CpuDevice<SC>>,
    Val<SC>: VmField,
{
    type VmConfig = PqSigRv32Config;
    type SystemChipInventory = SystemChipInventory<SC>;
    type RecordArena = MatrixRecordArena<Val<SC>>;

    fn create_chip_complex(
        &self,
        config: &PqSigRv32Config,
        circuit: AirInventory<SC>,
    ) -> Result<
        VmChipComplex<SC, Self::RecordArena, E::PB, Self::SystemChipInventory>,
        ChipInventoryError,
    > {
        let mut chip_complex =
            VmBuilder::<E>::create_chip_complex(&SystemCpuBuilder, &config.system, circuit)?;
        let inventory = &mut chip_complex.inventory;
        VmProverExtension::<E, _, _>::extend_prover(&Rv32ImCpuProverExt, &config.rv32i, inventory)?;
        VmProverExtension::<E, _, _>::extend_prover(&Rv32ImCpuProverExt, &config.rv32m, inventory)?;
        VmProverExtension::<E, _, _>::extend_prover(&Rv32ImCpuProverExt, &config.io, inventory)?;
        VmProverExtension::<E, _, _>::extend_prover(&PqSigCpuProverExt, &config.pqsig, inventory)?;
        Ok(chip_complex)
    }
}
