# Aggregation Notes

## Primary reference: leanMultisig

[leanMultisig](https://github.com/leanEthereum/leanMultisig) is the most relevant design reference for taking `leanSig`-style hash-based signatures toward aggregation.

What is most reusable conceptually:

- aggregate over a sorted and deduplicated public-key set
- expose a compact public input containing signer count, message, slot, and a commitment to the signer set
- recursively verify child aggregation proofs while directly verifying raw signatures at the leaves
- reduce recursive proof claims so each aggregation layer emits a constant-size claim

Why it matters here:

- the current PoC already defines a stable guest ABI for single-signature verification
- the next step is to lift that ABI into a guest program that verifies many signatures and emits a signer-set commitment

## Practical aggregation directions

### 1. Recursive signature tree

Inspired by `leanMultisig`:

- leaf jobs verify raw `leanSig` signatures
- parent jobs verify child proofs plus optionally some raw signatures
- each parent proves the union of participant sets and a shared message/slot context
- the root proof becomes the aggregate signature object

Best fit when:

- you want explicit signer accounting
- recursion is the long-term architecture anyway

### 2. STARK packing before recursion

Inspired by Nethermind's STARKPack work:

- batch many similar verification traces into one FRI low-degree test
- reduce first-stage proof size and verifier cost before feeding proofs into recursion
- use packing between recursive layers to shrink witnesses and child-verifier cost

Best fit when:

- the single-signature verifier is already stable
- the bottleneck becomes recursive verifier size rather than individual verification logic

## Suggested roadmap for this repo

1. Keep the current single-signature custom instruction as the low-level primitive.
2. Add a guest program that verifies `N` signatures against one message and one slot.
3. Commit to the signer set with a hash or Merkle root as public output.
4. Replace the placeholder `VmCircuitExtension` with a real proving path.
5. Add recursive aggregation for batches of child proofs.
6. Evaluate whether packing helps before recursive composition.

## Useful external references

- [leanMultisig](https://github.com/leanEthereum/leanMultisig)
- [Technical Note: LeanSig for Post-Quantum Ethereum](https://eprint.iacr.org/2025/1332)
- [Aggregating and thresholdizing hash-based signatures using STARKs](https://eprint.iacr.org/2021/1048.pdf)
- [STARKPack: Aggregating STARKs for shorter proofs and faster verification](https://www.nethermind.io/blog/starkpack-aggregating-starks-for-shorter-proofs-and-faster-verification)
