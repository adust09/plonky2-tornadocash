use crate::circuit::{WithdrawCircuit, WithdrawCircuitTargets};
use crate::types::{Digest, PlonkyProof, C, F};
use anyhow::Result;
use plonky2::iop::witness::WitnessWrite;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_data::CircuitData, circuit_data::VerifierCircuitData},
};

pub struct TornadoCashProofSystem {
    pub circuit: WithdrawCircuit,
    pub circuit_data: CircuitData<F, C, 2>,
    pub verifier_data: VerifierCircuitData<F, C, 2>,
    pub targets: WithdrawCircuitTargets,
}

impl TornadoCashProofSystem {
    pub fn new(leaves: Vec<Digest>, tree_height: usize) -> Self {
        let circuit = WithdrawCircuit { tree_height };
        let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::new(
            plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_zk_config(),
        );

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
        commitment: Digest,
        nullifier: Digest,
        user_index: usize,
        merkle_tree_root: [F; 4],
        merkle_proof: Vec<Digest>,
    ) -> Result<PlonkyProof> {
        let mut pw = PartialWitness::new();

        for i in 0..4 {
            pw.set_target(self.targets.merkle_root[i], merkle_tree_root[i]);
            pw.set_target(self.targets.nullifier[i], nullifier[i]);
        }

        for i in 0..4 {
            pw.set_target(self.targets.commitment[i], commitment[i]);
        }

        for (i, sibling) in merkle_proof.iter().enumerate() {
            for j in 0..4 {
                pw.set_target(self.targets.path_elements[i][j], sibling[j]);
            }

            pw.set_target(self.targets.path_indices[i], path_indices[i]);
        }

        // 証明の生成
        let proof_with_pis = self.circuit_data.prove(pw)?;

        Ok(proof_with_pis)
    }

    pub fn verify_withdraw_proof(&self, proof: PlonkyProof) -> Result<()> {
        self.verifier_data.verify(proof)
    }
}
