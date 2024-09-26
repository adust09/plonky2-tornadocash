use crate::proof::TornadoCashProofSystem;
use crate::types::{Digest, F};
use anyhow::Result;
use plonky2::plonk::config::Hasher;
use plonky2::{hash::merkle_tree::MerkleTree, hash::poseidon::PoseidonHash};
use rand::rngs::OsRng;

pub fn test_withdraw() -> Result<()> {
    let n = 16; // 2^4
    let tree_height = 4;

    let mut rng = OsRng;
    let mut identity_commitments: Vec<Digest> = Vec::new();
    let mut secret_keys: Vec<Digest> = Vec::new();

    for _ in 0..n {
        let mut secret_key = [F::ZERO; 4];
        for i in 0..4 {
            secret_key[i] = F::rand();
        }
        secret_keys.push(secret_key);

        let commitment = PoseidonHash::hash_no_pad(&secret_key.to_vec()).elements;
        identity_commitments.push(commitment);
    }

    let merkle_tree = MerkleTree::new(identity_commitments.clone(), 0);
    let proof_system = TornadoCashProofSystem::new(identity_commitments.clone(), tree_height);

    let user_index = 5;
    let user_secret_key = secret_keys[user_index];
    let user_commitment = identity_commitments[user_index];

    let nullifier = PoseidonHash::hash_no_pad(&user_secret_key.to_vec()).elements;

    let merkle_proof = merkle_tree.prove(user_index).unwrap();
    let siblings = merkle_proof.siblings;

    let path_indices = merkle_proof
        .path_indices
        .iter()
        .map(|&x| F::from_canonical_u8(x as u8))
        .collect::<Vec<F>>();

    let merkle_root = merkle_tree.root();

    let proof = proof_system.generate_withdraw_proof(
        user_commitment,
        nullifier,
        user_index,
        merkle_root,
        siblings,
        path_indices,
    )?;

    proof_system.verify_withdraw_proof(proof)?;

    println!("Withdraw proof verified successfully.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tornado_cash_withdraw() {
        assert!(test_withdraw().is_ok());
    }
}
