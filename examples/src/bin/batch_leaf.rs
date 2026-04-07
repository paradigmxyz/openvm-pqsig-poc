use openvm_pqsig::{
    build_batch_verification_leaf, software::generate_tiny_poseidon_fixture, SchemeId,
};

fn main() {
    let fixtures = (0..8u64)
        .map(generate_tiny_poseidon_fixture)
        .collect::<Vec<_>>();
    let epoch = fixtures[0].epoch;
    let message = fixtures[0].message;
    let batch = fixtures
        .iter()
        .map(|fixture| (&fixture.public_key[..], &fixture.signature[..]))
        .collect::<Vec<_>>();

    let leaf =
        build_batch_verification_leaf(SchemeId::TinyPoseidonTestOnly, epoch, &message, &batch)
            .expect("batch leaf should verify");

    println!("leaf statement digest: {:02x?}", leaf.digest());
    println!("leaf signer count: {}", leaf.statement.signer_count);
    println!(
        "leaf signer set digest: {:02x?}",
        leaf.statement.signer_set_digest
    );
}
