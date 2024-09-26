use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::Proof},
};

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub type Digest = [F; 4];
pub type PlonkyProof = Proof<F, C, 2>;
