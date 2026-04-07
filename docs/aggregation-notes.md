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

Current repository status:

- the tiny Poseidon software path now has a real batched verifier summary that returns `signer_count` plus a Poseidon-based commitment to the sorted, deduplicated signer set
- the matching OpenVM guest example executes today as a real batch-verification leaf job
- proving is still blocked because [`extensions/pqsig/circuit/src/lib.rs`](../extensions/pqsig/circuit/src/lib.rs) does not yet add any AIR or prover logic for `PqSig`, so the only proof path is plain RV32 interpretation of the software verifier
- on a real run of the ignored batch-proof test, that plain-RV32 path reached about `5.1B` retired instructions across `544` segments, repeatedly tripped the `4,194,304` height ceiling and `1.2B`-cell cap, and then died with `SIGKILL` during trace generation

## Practical aggregation directions

One important design takeaway from the STARK aggregation literature is that simple hash-based signatures are often better aggregation targets than more optimized many-time schemes. The reason is that in proof-based aggregation, verifier hash count dominates, while raw signature size is only witness data.

That creates a useful split for this repo:

- `leanSig` remains the compatibility target and long-term integration goal
- simpler schemes like Lamport, WOTS, or small XMSS-style gadgets may be the right first fully proved aggregation pipeline inside OpenVM

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

The next feasible proving move is not “prove bigger leanSig on RV32.” It is:

1. keep the tiny batch leaf honest and small
2. expose the signer-set commitment as the future public-value boundary
3. either add a dedicated Poseidon/KoalaBear proving chip for that leaf or swap in an even simpler hash-based leaf verifier before attempting recursive aggregation

## Useful external references

- [leanMultisig](https://github.com/leanEthereum/leanMultisig)
- [Technical Note: LeanSig for Post-Quantum Ethereum](https://eprint.iacr.org/2025/1332)
- [Aggregating and thresholdizing hash-based signatures using STARKs](https://eprint.iacr.org/2021/1048.pdf)
- [STARKPack: Aggregating STARKs for shorter proofs and faster verification](https://www.nethermind.io/blog/starkpack-aggregating-starks-for-shorter-proofs-and-faster-verification)
