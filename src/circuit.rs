use crate::types::{C, F};
use plonky2::{
    field::{packed::PackedField, types::Field},
    hash::poseidon::PoseidonHash,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

pub struct WithdrawCircuitTargets {
    pub merkle_root: [F; 4],
    pub nullifier: [F; 4],
    pub path_elements: Vec<[F; 4]>,
    pub path_indices: Vec<F>,
    pub recipient: [F; 4],
    pub commitment: [F; 4],
}

pub struct WithdrawCircuit {
    pub tree_height: usize,
}

impl WithdrawCircuit {
    pub fn build_withdraw_circuit(
        &self,
        builder: &mut CircuitBuilder<F, C>,
    ) -> WithdrawCircuitTargets {
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);

        let nullifier = [builder.add_virtual_target(); 4];
        builder.register_public_inputs(&nullifier);

        let recipient = [builder.add_virtual_target(); 4];
        builder.register_public_inputs(&recipient);

        let mut path_elements = Vec::new();
        let mut path_indices = Vec::new();
        for _ in 0..self.tree_height {
            path_elements.push([builder.add_virtual_target(); 4]);
            let path_index = builder.add_virtual_target();
            path_indices.push(path_index);
        }

        let commitment = [builder.add_virtual_target(); 4];

        let mut current_hash = commitment.to_vec();

        for i in 0..self.tree_height {
            let path_index = path_indices[i];
            let is_right = builder.equal(path_index, F::from_canonical_u8(1));

            let left = builder.select(is_right, path_elements[i], &current_hash[..4]);
            let right = builder.select(is_right, &current_hash[..4], path_elements[i]);

            current_hash = PoseidonHash::hash_no_pad(&[left, right].concat())
                .elements
                .to_vec();
        }

        for i in 0..4 {
            builder.connect(merkle_root[i], current_hash[i]);
        }

        WithdrawCircuitTargets {
            merkle_root: [F::ZEROS; 4],
            nullifier,
            path_elements,
            path_indices,
            recipient,
            commitment,
        }
    }
}
