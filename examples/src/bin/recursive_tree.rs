use openvm_pqsig::{
    build_batch_verification_leaf, build_recursive_aggregation_tree,
    software::generate_tiny_poseidon_fixture, SchemeId,
};

fn main() {
    let fixtures = (0..16u64)
        .map(generate_tiny_poseidon_fixture)
        .collect::<Vec<_>>();
    let epoch = fixtures[0].epoch;
    let message = fixtures[0].message;

    let leaves = fixtures
        .chunks(4)
        .map(|chunk| {
            let batch = chunk
                .iter()
                .map(|fixture| (&fixture.public_key[..], &fixture.signature[..]))
                .collect::<Vec<_>>();
            build_batch_verification_leaf(SchemeId::TinyPoseidonTestOnly, epoch, &message, &batch)
                .expect("leaf should verify")
        })
        .collect::<Vec<_>>();

    let tree = build_recursive_aggregation_tree(&leaves, 2).expect("tree should build");
    let root = tree.root().expect("tree should have a root");

    println!("fanout: {}", tree.fanout);
    println!("leaf count: {}", tree.leaves.len());
    println!("levels: {}", tree.levels.len());
    println!("root statement digest: {:02x?}", root.digest());
    println!("root signer count: {}", root.statement().signer_count);
    println!(
        "root signer set digest: {:02x?}",
        root.statement().signer_set_digest
    );
}
