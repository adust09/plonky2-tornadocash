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
