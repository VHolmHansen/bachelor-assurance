use hax_lib::ToInt;
use crate::utils::{aes, finite_field};
mod utils;
mod mpc;
mod lpzk;
mod verifier;
mod prover;

#[hax_lib::exclude]
fn main() {
    //mpc::main();
    //lpzk::main();
    let field = finite_field::new(257.to_int());
    aes::main(field);
}

