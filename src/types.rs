use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;

pub type F = GoldilocksField;
pub type Digest = [F; 4];
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;
pub type C = PoseidonGoldilocksConfig;
