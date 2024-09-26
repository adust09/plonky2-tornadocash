use anyhow::Result;
use rand::rngs::OsRng;

use crate::proof::TornadoCashProofSystem;
use crate::types::{Digest, F};
use plonky2::{
    field::types::Sample,
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    plonk::config::Hasher,
};

pub fn test_withdraw() -> Result<()> {
    let n = 16; // 2^4
    let tree_height = 4;

    let mut rng = OsRng;
    let mut note_commitments: Vec<Digest> = Vec::new();
    let mut secret_keys: Vec<Digest> = Vec::new();

    for _ in 0..n {
        let mut secret_key = [F::ZERO; 4];
        for i in 0..4 {
            secret_key[i] = F::rand();
        }
        secret_keys.push(secret_key);

        // Note Commitmentの計算: Poseidon(secret_key)
        let commitment = PoseidonHash::hash_no_pad(&secret_key.to_vec()).elements;
        note_commitments.push(commitment);
    }

    let merkle_tree = MerkleTree::new(note_commitments.clone(), 0);
    let proof_system = TornadoCashProofSystem::new(note_commitments.clone(), tree_height);

    let user_index = 5;
    let user_secret_key = secret_keys[user_index];
    let user_commitment = note_commitments[user_index];

    // Nullifierの計算: Poseidon(secret_key)
    let nullifier = PoseidonHash::hash_no_pad(&user_secret_key.to_vec()).elements;

    // Merkle Proofの生成
    let merkle_proof = merkle_tree.prove(user_index).unwrap();
    let siblings = merkle_proof.siblings; // Vec<Digest>

    // Merkle Rootの取得
    let merkle_root = merkle_tree.root();

    // ウィズドロー証明の生成
    let proof = proof_system.generate_withdraw_proof(
        user_commitment,
        nullifier,
        user_index,
        merkle_root,
        siblings,
    )?;

    // 証明の検証
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
