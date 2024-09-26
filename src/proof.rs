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

/// Tornado Cashの証明システムを表す構造体
pub struct TornadoCashProofSystem {
    pub circuit: WithdrawCircuit,
    pub circuit_data: CircuitData<F, C, 2>,
    pub verifier_data: VerifierCircuitData<F, C, 2>,
    pub targets: WithdrawCircuitTargets,
}

impl TornadoCashProofSystem {
    pub fn new(leaves: Vec<Digest>, tree_height: usize) -> Self {
        let circuit = WithdrawCircuit { tree_height };
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_zk_config());

        let targets = circuit.build_withdraw_circuit(&mut builder);
        let circuit_data = builder.build();

        let verifier_data = VerifierCircuitData::from_circuit_data(&circuit_data).unwrap();

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
        user_index: usize,
        merkle_tree_root: [F; 4],
        merkle_proof: Vec<Digest>,
    ) -> Result<PlonkyProof> {
        let mut pw = PartialWitness::new();

        for i in 0..4 {
            pw.set_target(self.targets.merkle_root.elements[i], merkle_tree_root[i]);
            pw.set_target(self.targets.nullifier.elements[i], nullifier[i]);
        }

        // Note Commitmentの設定
        for i in 0..4 {
            pw.set_target(self.targets.note_commitment.elements[i], note_commitment[i]);
        }

        // Merkle Proofの設定
        for (i, sibling) in merkle_proof.iter().enumerate() {
            // MerkleProofTargetの兄弟ノードを設定
            for j in 0..4 {
                pw.set_target(
                    self.targets.merkle_proof.siblings[i].elements[j],
                    sibling[j],
                );
            }
        }

        let proof_with_pis = self.circuit_data.prove(pw)?;

        Ok(proof_with_pis)
    }

    /// ウィズドローの証明を検証
    pub fn verify_withdraw_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    ) -> Result<()> {
        self.verifier_data.verify(proof)
    }
}
