use hax_lib::ToInt;
use crate::utils::{finite_field};
use crate::protocols::aes;
mod utils;
mod protocols;
mod verifier;
mod prover;

#[hax_lib::exclude]
fn main() {
    utils::ggm_tree::main();
}

