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

        // Poseidon(note_commitment || nullifier)
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

/// Unit tests for the circuit module.
#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Sample,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::circuit_data::CircuitConfig,
    };

    use super::*;
    use crate::types::{C, F};

    /// Test the WithdrawCircuit construction.
    #[test]
    fn test_withdraw_circuit_construction() -> Result<(), Box<dyn std::error::Error>> {
        let tree_height = 4;
        let circuit = WithdrawCircuit { tree_height };
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_zk_config());

        // Build the circuit and verify no errors occur.
        let _targets = circuit.build_withdraw_circuit(&mut builder);
        let circuit_data = builder.build::<C>();

        // Assert that the circuit data is constructed correctly.
        assert_eq!(
            circuit_data.common.num_constants, 0,
            "Number of constraints should be initialized correctly"
        );

        Ok(())
    }

    /// Test that the circuit correctly enforces constraints.
    #[test]
    fn test_circuit_constraints() -> Result<(), Box<dyn std::error::Error>> {
        let tree_height = 4;
        let circuit = WithdrawCircuit { tree_height };
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_zk_config());

        // Build the circuit.
        let targets = circuit.build_withdraw_circuit(&mut builder);
        let circuit_data = builder.build::<C>();

        // Create a partial witness with correct assignments.
        let mut pw = PartialWitness::new();
        // Set targets with dummy data (replace with actual test data as needed)
        for target in &targets.merkle_root.elements {
            let _ = pw.set_target(*target, F::rand());
        }
        for target in &targets.nullifier.elements {
            let _ = pw.set_target(*target, F::rand());
        }
        for target in &targets.note_commitment.elements {
            let _ = pw.set_target(*target, F::rand());
        }
        for sibling in &targets.merkle_proof.siblings {
            for element in &sibling.elements {
                let _ = pw.set_target(*element, F::rand());
            }
        }

        // Prove and verify the circuit.
        let proof_with_pis = circuit_data.prove(pw)?;
        let verifier_data = circuit_data.verifier_data();
        verifier_data.verify(proof_with_pis)?;

        Ok(())
    }

    // Add more unit tests related to the circuit here.
}
