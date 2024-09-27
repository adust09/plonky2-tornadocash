use crate::circuit::{WithdrawCircuit, WithdrawCircuitTargets};
use crate::types::{Digest, PlonkyProof, C, F};
use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

pub struct TornadoCashProofSystem {
    pub circuit: WithdrawCircuit,
    pub circuit_data: CircuitData<F, C, 2>,
    pub verifier_data: VerifierCircuitData<F, C, 2>,
    pub targets: WithdrawCircuitTargets,
}

impl TornadoCashProofSystem {
    pub fn to_verifier_data(circuit_data: &CircuitData<F, C, 2>) -> VerifierCircuitData<F, C, 2> {
        VerifierCircuitData {
            verifier_only: circuit_data.verifier_only.clone(),
            common: circuit_data.common.clone(),
        }
    }
    pub fn new(tree_height: usize) -> Self {
        let circuit = WithdrawCircuit { tree_height };
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_zk_config());

        let targets = circuit.build_withdraw_circuit(&mut builder);
        let circuit_data = builder.build();

        let verifier_data = Self::to_verifier_data(&circuit_data);

        Self {
            circuit,
            circuit_data,
            verifier_data,
            targets,
        }
    }

    pub fn generate_withdraw_proof(
        &self,
        note_commitment: Digest,
        nullifier: Digest,
        merkle_tree_root: [F; 4],
        merkle_proof: Vec<Digest>,
    ) -> Result<PlonkyProof> {
        let mut pw = PartialWitness::new();

        for i in 0..4 {
            let _ = pw.set_target(self.targets.merkle_root.elements[i], merkle_tree_root[i]);
            let _ = pw.set_target(self.targets.nullifier.elements[i], nullifier[i]);
        }

        for i in 0..4 {
            let _ = pw.set_target(self.targets.note_commitment.elements[i], note_commitment[i]);
        }

        for (i, sibling) in merkle_proof.iter().enumerate() {
            for j in 0..4 {
                let _ = pw.set_target(
                    self.targets.merkle_proof.siblings[i].elements[j],
                    sibling[j],
                );
            }
        }

        let proof_with_pis = self.circuit_data.prove(pw)?;

        Ok(proof_with_pis)
    }

    pub fn verify_withdraw_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    ) -> Result<()> {
        self.verifier_data.verify(proof)
    }
}

/// Unit tests for the proof module.
#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
        plonk::config::Hasher,
    };

    use super::*;
    /// Test for constructing an empty MerkleTree.
    #[test]
    fn test_empty_merkle_tree() -> Result<()> {
        let note_commitments: Vec<Digest> = Vec::new();
        let tree_height = 0;

        // Construct an empty Merkle tree.
        let merkle_tree: MerkleTree<F, PoseidonHash> = MerkleTree::new(
            note_commitments.iter().map(|c| c.to_vec()).collect(),
            tree_height,
        );

        // Verify that the Merkle cap is empty.
        assert!(
            merkle_tree.cap.is_empty(),
            "MerkleCap should be empty for an empty tree"
        );

        Ok(())
    }

    /// Test the proof generation and verification process.
    #[test]
    fn test_proof_generation_and_verification() -> Result<()> {
        // Initialize sample data
        let n = 16;
        let tree_height = 4;

        let mut note_commitments: Vec<Digest> = Vec::new();
        let mut secret_keys: Vec<Digest> = Vec::new();

        for i in 0..n {
            let secret_key: [GoldilocksField; 4] = [
                F::from_canonical_u64(i as u64),
                F::from_canonical_u64((i * 2) as u64),
                F::from_canonical_u64((i * 3) as u64),
                F::from_canonical_u64((i * 4) as u64),
            ];
            let commitment = PoseidonHash::hash_no_pad(&secret_key.to_vec()).elements;
            note_commitments.push(commitment);
            secret_keys.push(secret_key);
        }

        // Construct the Merkle tree
        let merkle_tree: MerkleTree<F, PoseidonHash> =
            MerkleTree::new(note_commitments.iter().map(|c| c.to_vec()).collect(), 0);
        let proof_system = TornadoCashProofSystem::new(tree_height);

        // Select a user index
        let user_index = 5;
        let user_secret_key = secret_keys[user_index];
        let user_commitment = note_commitments[user_index];

        // Compute the nullifier
        let nullifier = PoseidonHash::hash_no_pad(&user_secret_key.to_vec()).elements;

        // Retrieve the Merkle root
        let merkle_root = merkle_tree.cap.0[0].elements;

        // Generate the Merkle proof
        let merkle_proof = merkle_tree
            .prove(user_index)
            .siblings
            .iter()
            .map(|h| h.elements)
            .collect::<Vec<[F; 4]>>();

        // Generate the withdrawal proof
        let proof: PlonkyProof = proof_system.generate_withdraw_proof(
            user_commitment,
            nullifier,
            merkle_root,
            merkle_proof,
        )?;

        // Verify the withdrawal proof
        proof_system.verify_withdraw_proof(proof)?;

        Ok(())
    }

    /// Test verification fails for an invalid proof.
    #[test]
    fn test_invalid_proof_verification() -> Result<()> {
        // Initialize sample data
        let n = 16;
        let tree_height = 4;

        let mut note_commitments: Vec<Digest> = Vec::new();
        let mut secret_keys: Vec<Digest> = Vec::new();

        for i in 0..n {
            let secret_key = [
                F::from_canonical_u64(i as u64),
                F::from_canonical_u64((i * 2) as u64),
                F::from_canonical_u64((i * 3) as u64),
                F::from_canonical_u64((i * 4) as u64),
            ];
            let commitment = PoseidonHash::hash_no_pad(&secret_key.to_vec()).elements;
            note_commitments.push(commitment);
            secret_keys.push(secret_key);
        }

        // Construct the Merkle tree
        let merkle_tree: MerkleTree<F, PoseidonHash> = MerkleTree::new(
            note_commitments
                .iter()
                .map(|c: &[GoldilocksField; 4]| c.to_vec())
                .collect(),
            0,
        );
        let proof_system = TornadoCashProofSystem::new(tree_height);

        // Select a user index
        let user_index = 5;
        let user_secret_key = secret_keys[user_index];
        let user_commitment = note_commitments[user_index];

        // Compute the nullifier
        let nullifier = PoseidonHash::hash_no_pad(&user_secret_key.to_vec()).elements;

        // Retrieve the Merkle root
        let merkle_root = merkle_tree.cap.0[0].elements;

        // Generate the Merkle proof
        let mut merkle_proof = merkle_tree
            .prove(user_index)
            .siblings
            .iter()
            .map(|h| h.elements)
            .collect::<Vec<[F; 4]>>();

        // Tamper with the Merkle proof to make it invalid
        if let Some(first_sibling) = merkle_proof.get_mut(0) {
            first_sibling[0] = F::from_canonical_u64(9999); // Introduce an incorrect value
        }

        // Generate the withdrawal proof with the tampered Merkle proof
        let proof: PlonkyProof = proof_system.generate_withdraw_proof(
            user_commitment,
            nullifier,
            merkle_root,
            merkle_proof,
        )?;

        // Verify the invalid withdrawal proof (should fail)
        let verification_result = proof_system.verify_withdraw_proof(proof);
        assert!(
            verification_result.is_err(),
            "Proof verification should fail for invalid proof"
        );

        Ok(())
    }

    // Add more unit tests specific to the proof module here.
}
