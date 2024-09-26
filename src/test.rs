use crate::proof::TornadoCashProofSystem;
use crate::types::{Digest, PlonkyProof, F};
use anyhow::Result;
use plonky2::{
    field::types::{Field, Sample},
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use rand::rngs::OsRng;

/// ウィズドロー機能のテスト関数
pub fn test_withdraw() -> Result<()> {
    // Merkleツリーの葉の数（2のべき乗）
    let n = 16; // 2^4
    let tree_height = 4;

    // ランダムなNote Commitmentsの生成
    let mut rng = OsRng;
    let mut note_commitments: Vec<Digest> = Vec::new();
    let mut secret_keys: Vec<Digest> = Vec::new();

    for _ in 0..n {
        // 秘密鍵の生成（4つのフィールド要素）
        let mut secret_key = [F::ZERO; 4];
        for i in 0..4 {
            secret_key[i] = F::rand();
        }
        secret_keys.push(secret_key);

        // Note Commitmentの計算: Poseidon(secret_key)
        let commitment = PoseidonHash::hash_no_pad(&secret_key.to_vec()).elements;
        note_commitments.push(commitment);
    }

    // Merkleツリーの構築
    let merkle_tree = MerkleTree::new(note_commitments.clone(), 0);
    let proof_system = TornadoCashProofSystem::new(note_commitments.clone(), tree_height);

    // ウィズドロー対象ユーザーの選択
    let user_index = 5;
    let user_secret_key = secret_keys[user_index];
    let user_commitment = note_commitments[user_index];

    // Nullifierの計算: Poseidon(secret_key)
    let nullifier = PoseidonHash::hash_no_pad(&user_secret_key.to_vec()).elements;

    // Merkle Proofの生成
    let merkle_proof = merkle_tree.prove(user_index);
    let siblings = merkle_proof.siblings; // Vec<Digest>

    // Merkle Rootの取得
    let merkle_root = merkle_tree.root();

    // ウィズドロー証明の生成
    let proof: PlonkyProof =
        proof_system.generate_withdraw_proof(user_commitment, nullifier, merkle_root, siblings)?;

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
