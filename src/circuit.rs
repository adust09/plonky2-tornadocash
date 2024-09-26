use crate::types::F;
use plonky2::{
    hash::{hash_types::HashOutTarget, merkle_proofs::MerkleProofTarget, poseidon::PoseidonHash},
    plonk::circuit_builder::CircuitBuilder,
};

pub struct WithdrawCircuitTargets {
    pub merkle_root: HashOutTarget,
    pub nullifier: HashOutTarget,
    pub merkle_proof: MerkleProofTarget,
    pub note_commitment: HashOutTarget,
}

pub struct WithdrawCircuit {
    pub tree_height: usize,
}

impl WithdrawCircuit {
    pub fn build_withdraw_circuit(
        &self,
        builder: &mut CircuitBuilder<F, 2>,
    ) -> WithdrawCircuitTargets {
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);

        let nullifier = builder.add_virtual_hash();
        builder.register_public_inputs(&nullifier.elements);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: (0..self.tree_height)
                .map(|_| HashOutTarget {
                    elements: [builder.add_virtual_target(); 4],
                })
                .collect(),
        };

        let note_commitment = builder.add_virtual_hash();
        let note_commitment_index = builder.add_virtual_target();
        let note_commitment_index_bit = builder.split_le(note_commitment_index, self.tree_height);
        builder.verify_merkle_proof::<PoseidonHash>(
            note_commitment.elements.to_vec(),
            &note_commitment_index_bit,
            merkle_root,
            &merkle_proof,
        );

        // Nullifierの計算: Poseidon(note_commitment || nullifier)
        let computed_nullifier = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            vec![note_commitment.elements, nullifier.elements].concat(),
        );

        WithdrawCircuitTargets {
            merkle_root,
            nullifier: computed_nullifier,
            merkle_proof,
            note_commitment,
        }
    }
}
