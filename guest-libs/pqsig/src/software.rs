use core::array;

use p3_field::{PrimeCharacteristicRing, PrimeField32, PrimeField64};
use p3_koala_bear::{
    default_koalabear_poseidon1_16, default_koalabear_poseidon1_24, KoalaBear, Poseidon1KoalaBear,
};
use p3_symmetric::CryptographicPermutation;
#[cfg(not(target_os = "zkvm"))]
use std::sync::OnceLock;

pub mod vectors {
    include!("software_vectors.rs");
}

type F = KoalaBear;
type Poseidon16 = Poseidon1KoalaBear<16>;
type Poseidon24 = Poseidon1KoalaBear<24>;

const MESSAGE_LEN: usize = 32;
const DOMAIN_LEN: usize = 1;
const PARAMETER_LEN: usize = 1;
const TWEAK_LEN: usize = 2;
const RANDOMNESS_LEN: usize = 1;
const MESSAGE_HASH_LEN: usize = 1;
const MESSAGE_LEN_FE: usize = 9;
const NUM_CHAINS: usize = 31;
const TARGET_SUM: usize = 15;
const TREE_DEPTH: usize = 4;
const PK_LEN: usize = (DOMAIN_LEN + PARAMETER_LEN) * 4;
const HASH_BYTES: usize = DOMAIN_LEN * 4;
const PATH_CONTAINER_OFFSET: usize = 12;
const PATH_CONTAINER_LEN: usize = 4 + TREE_DEPTH * HASH_BYTES;
const HASHES_OFFSET: usize = PATH_CONTAINER_OFFSET + PATH_CONTAINER_LEN;
const SIG_LEN: usize = HASHES_OFFSET + NUM_CHAINS * HASH_BYTES;
const TREE_SEPARATOR: u8 = 0x01;
const CHAIN_SEPARATOR: u8 = 0x00;
const MESSAGE_SEPARATOR: u8 = 0x02;
const LEAF_INPUT_LEN: usize = PARAMETER_LEN + TWEAK_LEN + NUM_CHAINS * DOMAIN_LEN;
const CAPACITY_LEN: usize = 4;

#[derive(Clone, Copy)]
struct PublicKey {
    root: [F; DOMAIN_LEN],
    parameter: [F; PARAMETER_LEN],
}

#[derive(Clone, Copy)]
struct Signature {
    rho: [F; RANDOMNESS_LEN],
    path: [[F; DOMAIN_LEN]; TREE_DEPTH],
    hashes: [[F; DOMAIN_LEN]; NUM_CHAINS],
}

pub fn verify_tiny_poseidon_signature(
    public_key_ssz: &[u8],
    signature_ssz: &[u8],
    epoch: u32,
    message: &[u8; MESSAGE_LEN],
) -> bool {
    if epoch >= (1u32 << TREE_DEPTH) {
        return false;
    }

    let Some(public_key) = parse_public_key(public_key_ssz) else {
        return false;
    };
    let Some(signature) = parse_signature(signature_ssz) else {
        return false;
    };
    let Some(codeword) = encode_target_sum(&public_key.parameter, epoch, &signature.rho, message)
    else {
        return false;
    };

    let mut chain_ends = [[F::ZERO; DOMAIN_LEN]; NUM_CHAINS];
    for (chain_index, chain_end) in chain_ends.iter_mut().enumerate() {
        let start = &signature.hashes[chain_index];
        let start_pos = codeword[chain_index];
        let steps = usize::from(start_pos == 0);
        *chain_end = walk_chain(
            &public_key.parameter,
            epoch,
            chain_index as u8,
            start_pos,
            steps,
            start,
        );
    }

    verify_merkle_path(
        &public_key.parameter,
        &public_key.root,
        epoch,
        &chain_ends,
        &signature.path,
    )
}

pub fn verify_tiny_poseidon_batch(
    batch: &[(&[u8], &[u8])],
    epoch: u32,
    message: &[u8; MESSAGE_LEN],
) -> bool {
    batch.iter().all(|(public_key, signature)| {
        verify_tiny_poseidon_signature(public_key, signature, epoch, message)
    })
}

fn parse_public_key(bytes: &[u8]) -> Option<PublicKey> {
    if bytes.len() != PK_LEN {
        return None;
    }

    Some(PublicKey {
        root: decode_fe_array::<DOMAIN_LEN>(&bytes[..HASH_BYTES])?,
        parameter: decode_fe_array::<PARAMETER_LEN>(&bytes[HASH_BYTES..])?,
    })
}

fn parse_signature(bytes: &[u8]) -> Option<Signature> {
    if bytes.len() != SIG_LEN {
        return None;
    }
    if read_u32(bytes, 0)? as usize != PATH_CONTAINER_OFFSET {
        return None;
    }
    if read_u32(bytes, 8)? as usize != HASHES_OFFSET {
        return None;
    }

    let rho = decode_fe_array::<RANDOMNESS_LEN>(&bytes[4..8])?;

    let path_container = &bytes[PATH_CONTAINER_OFFSET..HASHES_OFFSET];
    if path_container.len() != PATH_CONTAINER_LEN {
        return None;
    }
    if read_u32(path_container, 0)? != 4 {
        return None;
    }
    let path = decode_domain_matrix::<TREE_DEPTH>(&path_container[4..])?;
    let hashes = decode_domain_matrix::<NUM_CHAINS>(&bytes[HASHES_OFFSET..])?;

    Some(Signature { rho, path, hashes })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn decode_fe(value: u32) -> Option<F> {
    (value < F::ORDER_U32).then_some(F::new(value))
}

fn decode_fe_array<const N: usize>(bytes: &[u8]) -> Option<[F; N]> {
    if bytes.len() != N * 4 {
        return None;
    }

    let mut out = [F::ZERO; N];
    for (i, item) in out.iter_mut().enumerate() {
        let start = i * 4;
        *item = decode_fe(read_u32(bytes, start)?)?;
    }
    Some(out)
}

fn decode_domain_matrix<const N: usize>(bytes: &[u8]) -> Option<[[F; DOMAIN_LEN]; N]> {
    if bytes.len() != N * HASH_BYTES {
        return None;
    }

    let mut out = [[F::ZERO; DOMAIN_LEN]; N];
    for (index, domain) in out.iter_mut().enumerate() {
        let start = index * HASH_BYTES;
        *domain = decode_fe_array::<DOMAIN_LEN>(&bytes[start..start + HASH_BYTES])?;
    }
    Some(out)
}

fn encode_target_sum(
    parameter: &[F; PARAMETER_LEN],
    epoch: u32,
    randomness: &[F; RANDOMNESS_LEN],
    message: &[u8; MESSAGE_LEN],
) -> Option<[u8; NUM_CHAINS]> {
    let hash = message_hash(parameter, epoch, randomness, message);
    let chunks = decode_hash_chunks(&hash);
    let sum: usize = chunks.iter().map(|&x| x as usize).sum();
    (sum == TARGET_SUM).then_some(chunks)
}

fn message_hash(
    parameter: &[F; PARAMETER_LEN],
    epoch: u32,
    randomness: &[F; RANDOMNESS_LEN],
    message: &[u8; MESSAGE_LEN],
) -> [F; MESSAGE_HASH_LEN] {
    let mut input = [F::ZERO; 24];
    let epoch_fe = encode_epoch(epoch);
    let message_fe = encode_message(message);

    input[..RANDOMNESS_LEN].copy_from_slice(randomness);
    input[RANDOMNESS_LEN..RANDOMNESS_LEN + PARAMETER_LEN].copy_from_slice(parameter);
    input[RANDOMNESS_LEN + PARAMETER_LEN..RANDOMNESS_LEN + PARAMETER_LEN + TWEAK_LEN]
        .copy_from_slice(&epoch_fe);
    input[RANDOMNESS_LEN + PARAMETER_LEN + TWEAK_LEN
        ..RANDOMNESS_LEN + PARAMETER_LEN + TWEAK_LEN + MESSAGE_LEN_FE]
        .copy_from_slice(&message_fe);

    poseidon_compress::<24, MESSAGE_HASH_LEN>(&poseidon1_24(), &input)
}

fn encode_epoch(epoch: u32) -> [F; TWEAK_LEN] {
    let mut acc = ((epoch as u64) << 8) | MESSAGE_SEPARATOR as u64;
    array::from_fn(|_| {
        let digit = acc % F::ORDER_U64;
        acc /= F::ORDER_U64;
        F::from_u64(digit)
    })
}

fn encode_message(message: &[u8; MESSAGE_LEN]) -> [F; MESSAGE_LEN_FE] {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        *limb = u64::from_le_bytes(message[start..start + 8].try_into().unwrap());
    }

    array::from_fn(|_| {
        let digit = div_rem_u256_by_u64(&mut limbs, F::ORDER_U64);
        F::from_u64(digit)
    })
}

fn div_rem_u256_by_u64(limbs: &mut [u64; 4], divisor: u64) -> u64 {
    let mut remainder = 0u128;
    for limb in limbs.iter_mut().rev() {
        let value = (remainder << 64) | (*limb as u128);
        *limb = (value / divisor as u128) as u64;
        remainder = value % divisor as u128;
    }
    remainder as u64
}

fn decode_hash_chunks(hash: &[F; MESSAGE_HASH_LEN]) -> [u8; NUM_CHAINS] {
    let mut digits = [0u64; MESSAGE_HASH_LEN];
    for (index, digit) in digits.iter_mut().enumerate() {
        *digit = hash[index].as_canonical_u32() as u64;
    }

    array::from_fn(|_| div_rem_base_p_by_two(&mut digits))
}

fn div_rem_base_p_by_two(digits: &mut [u64; MESSAGE_HASH_LEN]) -> u8 {
    let mut remainder = 0u64;
    for digit in digits.iter_mut() {
        let value = remainder * F::ORDER_U64 + *digit;
        *digit = value / 2;
        remainder = value % 2;
    }
    remainder as u8
}

fn walk_chain(
    parameter: &[F; PARAMETER_LEN],
    epoch: u32,
    chain_index: u8,
    start_pos: u8,
    steps: usize,
    start: &[F; DOMAIN_LEN],
) -> [F; DOMAIN_LEN] {
    let mut current = *start;
    for step in 0..steps {
        let tweak = encode_chain_tweak(epoch, chain_index, start_pos + step as u8 + 1);
        current = hash_one(parameter, &tweak, &current);
    }
    current
}

fn verify_merkle_path(
    parameter: &[F; PARAMETER_LEN],
    root: &[F; DOMAIN_LEN],
    position: u32,
    leaf: &[[F; DOMAIN_LEN]; NUM_CHAINS],
    path: &[[F; DOMAIN_LEN]; TREE_DEPTH],
) -> bool {
    let mut current_node = hash_many(parameter, &encode_tree_tweak(0, position), leaf);
    let mut current_position = position;

    for (level, sibling) in path.iter().enumerate() {
        let children = if current_position.is_multiple_of(2) {
            [current_node, *sibling]
        } else {
            [*sibling, current_node]
        };
        current_position >>= 1;
        current_node = hash_pair(
            parameter,
            &encode_tree_tweak((level + 1) as u8, current_position),
            &children[0],
            &children[1],
        );
    }

    current_node == *root
}

fn encode_tree_tweak(level: u8, pos_in_level: u32) -> [F; TWEAK_LEN] {
    let mut acc = ((level as u128) << 40) | ((pos_in_level as u128) << 8) | TREE_SEPARATOR as u128;
    array::from_fn(|_| {
        let digit = (acc % F::ORDER_U64 as u128) as u64;
        acc /= F::ORDER_U64 as u128;
        F::from_u64(digit)
    })
}

fn encode_chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> [F; TWEAK_LEN] {
    let mut acc = ((epoch as u128) << 24)
        | ((chain_index as u128) << 16)
        | ((pos_in_chain as u128) << 8)
        | CHAIN_SEPARATOR as u128;
    array::from_fn(|_| {
        let digit = (acc % F::ORDER_U64 as u128) as u64;
        acc /= F::ORDER_U64 as u128;
        F::from_u64(digit)
    })
}

fn hash_one(
    parameter: &[F; PARAMETER_LEN],
    tweak: &[F; TWEAK_LEN],
    input: &[F; DOMAIN_LEN],
) -> [F; DOMAIN_LEN] {
    let mut state = [F::ZERO; 16];
    state[..PARAMETER_LEN].copy_from_slice(parameter);
    state[PARAMETER_LEN..PARAMETER_LEN + TWEAK_LEN].copy_from_slice(tweak);
    state[PARAMETER_LEN + TWEAK_LEN..PARAMETER_LEN + TWEAK_LEN + DOMAIN_LEN].copy_from_slice(input);
    poseidon_compress::<16, DOMAIN_LEN>(&poseidon1_16(), &state)
}

fn hash_pair(
    parameter: &[F; PARAMETER_LEN],
    tweak: &[F; TWEAK_LEN],
    left: &[F; DOMAIN_LEN],
    right: &[F; DOMAIN_LEN],
) -> [F; DOMAIN_LEN] {
    let mut state = [F::ZERO; 24];
    state[..PARAMETER_LEN].copy_from_slice(parameter);
    state[PARAMETER_LEN..PARAMETER_LEN + TWEAK_LEN].copy_from_slice(tweak);
    state[PARAMETER_LEN + TWEAK_LEN..PARAMETER_LEN + TWEAK_LEN + DOMAIN_LEN].copy_from_slice(left);
    state[PARAMETER_LEN + TWEAK_LEN + DOMAIN_LEN..PARAMETER_LEN + TWEAK_LEN + 2 * DOMAIN_LEN]
        .copy_from_slice(right);
    poseidon_compress::<24, DOMAIN_LEN>(&poseidon1_24(), &state)
}

fn hash_many(
    parameter: &[F; PARAMETER_LEN],
    tweak: &[F; TWEAK_LEN],
    inputs: &[[F; DOMAIN_LEN]; NUM_CHAINS],
) -> [F; DOMAIN_LEN] {
    let mut combined_input = [F::ZERO; LEAF_INPUT_LEN];
    combined_input[..PARAMETER_LEN].copy_from_slice(parameter);
    combined_input[PARAMETER_LEN..PARAMETER_LEN + TWEAK_LEN].copy_from_slice(tweak);
    for (index, input) in inputs.iter().enumerate() {
        let start = PARAMETER_LEN + TWEAK_LEN + index * DOMAIN_LEN;
        combined_input[start..start + DOMAIN_LEN].copy_from_slice(input);
    }

    let capacity = domain_separator();
    poseidon_sponge::<24, DOMAIN_LEN>(&poseidon1_24(), &capacity, &combined_input)
}

fn domain_separator() -> [F; CAPACITY_LEN] {
    #[cfg(not(target_os = "zkvm"))]
    {
        static DOMAIN_SEPARATOR: OnceLock<[F; CAPACITY_LEN]> = OnceLock::new();
        return *DOMAIN_SEPARATOR.get_or_init(compute_domain_separator);
    }

    #[cfg(target_os = "zkvm")]
    {
        compute_domain_separator()
    }
}

fn compute_domain_separator() -> [F; CAPACITY_LEN] {
    let lengths = [
        PARAMETER_LEN as u32,
        TWEAK_LEN as u32,
        NUM_CHAINS as u32,
        DOMAIN_LEN as u32,
    ];
    let mut acc = 0u128;
    for &param in &lengths {
        acc = (acc << 32) | param as u128;
    }

    let input = array::from_fn(|_| {
        let digit = (acc % F::ORDER_U64 as u128) as u64;
        acc /= F::ORDER_U64 as u128;
        F::from_u64(digit)
    });

    poseidon_compress::<24, CAPACITY_LEN>(&poseidon1_24(), &input)
}

#[cfg(not(target_os = "zkvm"))]
fn poseidon1_16() -> Poseidon16 {
    static PERM: OnceLock<Poseidon16> = OnceLock::new();
    PERM.get_or_init(default_koalabear_poseidon1_16).clone()
}

#[cfg(target_os = "zkvm")]
fn poseidon1_16() -> Poseidon16 {
    default_koalabear_poseidon1_16()
}

#[cfg(not(target_os = "zkvm"))]
fn poseidon1_24() -> Poseidon24 {
    static PERM: OnceLock<Poseidon24> = OnceLock::new();
    PERM.get_or_init(default_koalabear_poseidon1_24).clone()
}

#[cfg(target_os = "zkvm")]
fn poseidon1_24() -> Poseidon24 {
    default_koalabear_poseidon1_24()
}

fn poseidon_compress<const WIDTH: usize, const OUT_LEN: usize>(
    perm: &impl CryptographicPermutation<[F; WIDTH]>,
    input: &[F; WIDTH],
) -> [F; OUT_LEN] {
    let mut state = *input;
    perm.permute_mut(&mut state);
    for (state_elem, input_elem) in state.iter_mut().zip(input.iter()) {
        *state_elem += *input_elem;
    }
    state[..OUT_LEN].try_into().expect("output length fits")
}

fn poseidon_sponge<const WIDTH: usize, const OUT_LEN: usize>(
    perm: &impl CryptographicPermutation<[F; WIDTH]>,
    capacity: &[F; CAPACITY_LEN],
    input: &[F; LEAF_INPUT_LEN],
) -> [F; OUT_LEN] {
    let rate = WIDTH - CAPACITY_LEN;
    let mut state = [F::ZERO; WIDTH];
    state[rate..].copy_from_slice(capacity);

    let mut chunks = input.chunks_exact(rate);
    for chunk in &mut chunks {
        for (state_elem, input_elem) in state.iter_mut().take(rate).zip(chunk.iter()) {
            *state_elem += *input_elem;
        }
        perm.permute_mut(&mut state);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        for (state_elem, input_elem) in state.iter_mut().take(remainder.len()).zip(remainder.iter())
        {
            *state_elem += *input_elem;
        }
        perm.permute_mut(&mut state);
    }

    let mut out = [F::ZERO; OUT_LEN];
    let mut out_index = 0;
    while out_index < OUT_LEN {
        let chunk_size = (OUT_LEN - out_index).min(rate);
        out[out_index..out_index + chunk_size].copy_from_slice(&state[..chunk_size]);
        out_index += chunk_size;
        if out_index < OUT_LEN {
            perm.permute_mut(&mut state);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField32;

    use super::{
        vectors::{
            TEST_TINY_A_EPOCH, TEST_TINY_A_MESSAGE, TEST_TINY_A_PK, TEST_TINY_A_SIG,
            TEST_TINY_B_EPOCH, TEST_TINY_B_MESSAGE, TEST_TINY_B_PK, TEST_TINY_B_SIG,
        },
        verify_tiny_poseidon_batch, verify_tiny_poseidon_signature,
    };

    #[test]
    fn verifies_reference_vector() {
        assert!(verify_tiny_poseidon_signature(
            &TEST_TINY_A_PK,
            &TEST_TINY_A_SIG,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        ));
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut tampered = TEST_TINY_A_SIG;
        tampered[64] ^= 1;
        assert!(!verify_tiny_poseidon_signature(
            &TEST_TINY_A_PK,
            &tampered,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        ));
    }

    #[test]
    fn rejects_non_canonical_public_key_field_encoding() {
        let mut tampered = TEST_TINY_A_PK;
        tampered[..4].copy_from_slice(&super::F::ORDER_U32.to_le_bytes());
        assert!(!verify_tiny_poseidon_signature(
            &tampered,
            &TEST_TINY_A_SIG,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        ));
    }

    #[test]
    fn rejects_out_of_range_epoch() {
        assert!(!verify_tiny_poseidon_signature(
            &TEST_TINY_A_PK,
            &TEST_TINY_A_SIG,
            1 << super::TREE_DEPTH,
            &TEST_TINY_A_MESSAGE,
        ));
    }

    #[test]
    fn rejects_malformed_signature_offsets() {
        let mut tampered = TEST_TINY_A_SIG;
        tampered[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(!verify_tiny_poseidon_signature(
            &TEST_TINY_A_PK,
            &tampered,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        ));
    }

    #[test]
    fn verifies_batch_of_real_signatures() {
        assert_eq!(TEST_TINY_A_EPOCH, TEST_TINY_B_EPOCH);
        assert_eq!(TEST_TINY_A_MESSAGE, TEST_TINY_B_MESSAGE);

        let batch = [
            (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
            (&TEST_TINY_B_PK[..], &TEST_TINY_B_SIG[..]),
        ];
        assert!(verify_tiny_poseidon_batch(
            &batch,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        ));
    }

    #[test]
    fn batch_rejects_any_tampered_signature() {
        let mut tampered = TEST_TINY_B_SIG;
        tampered[80] ^= 1;
        let batch = [
            (&TEST_TINY_A_PK[..], &TEST_TINY_A_SIG[..]),
            (&TEST_TINY_B_PK[..], &tampered[..]),
        ];
        assert!(!verify_tiny_poseidon_batch(
            &batch,
            TEST_TINY_A_EPOCH,
            &TEST_TINY_A_MESSAGE,
        ));
    }
}
