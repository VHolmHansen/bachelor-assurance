use libcrux::drbg::{Drbg, RngCore};
use libcrux::digest;
use bachelor_assurance::protocols::aes::gf2_affine_transform;
use bachelor_assurance::run_faest;
use bachelor_assurance::utils::galois_field;
use crate::protocols::aes::setup_rcon_table;
use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify::faest_verify;
use crate::utils::hash_functions::bits_to_bytes_for_d;
use crate::utils::types::sized_array_for_cop;

pub mod utils;
pub mod protocols;

#[hax_lib::include]
fn main() {
    run_faest::run();
}