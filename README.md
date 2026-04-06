# openvm-pqsig-poc

A proof-of-concept OpenVM extension for post-quantum signature verification, starting with [leanSig](https://github.com/leanEthereum/leanSig).

## Scope

This repository provides:

- a custom OpenVM guest instruction for `leanSig` verification
- a transpiler extension for the custom opcode
- a guest-facing Rust library with native fallback verification
- an execution-only OpenVM extension and test harness

Current limitation:

- the `pqsig` opcode is wired for execution, but the proving-side AIR is still a placeholder
- this is an integration PoC, not yet a sound proving extension for KoalaBear/Poseidon verification

## Crates

- `extensions/pqsig/guest`: guest instruction and request ABI
- `extensions/pqsig/transpiler`: RISC-V custom instruction to OpenVM opcode mapping
- `guest-libs/pqsig`: ergonomic verification API with native `leanSig` fallback
- `extensions/pqsig/circuit`: execution extension and focused tests

## Supported leanSig schemes

The PoC currently supports these `leanSig` instantiations:

- `SIGTargetSumLifetime18W1NoOff`
- `SIGTargetSumLifetime18W2NoOff`
- `SIGTargetSumLifetime18W4NoOff`
- `SIGTargetSumLifetime18W8NoOff`
- `SIGTargetSumLifetime20W1NoOff`
- `SIGTargetSumLifetime20W2NoOff`
- `SIGTargetSumLifetime20W4NoOff`
- `SIGTargetSumLifetime20W8NoOff`
- `SIGAbortingTargetSumLifetime6Dim46Base8`

## Development

```bash
cargo fmt --all
cargo test --workspace --all-targets
```

## Aggregation roadmap

The strongest reference design so far is [leanMultisig](https://github.com/leanEthereum/leanMultisig), which shows how to move from individual hash-based signature verification to recursive aggregation.

Two promising directions from current research:

- recursive aggregation trees that verify child proofs plus a partitioned signer set
- STARK/FRI packing between recursive layers to reduce verifier and witness size before recursion

More detailed notes live in [`docs/aggregation-notes.md`](docs/aggregation-notes.md).
