use hax_lib::ToInt;
use crate::utils::{finite_field};
use crate::protocols::aes;
mod utils;
mod protocols;
mod verifier;
mod prover;

#[hax_lib::exclude]
fn main() {
    //mpc::main();
    //lpzk::main();
    //let field = finite_field::new(257.to_int());
    //aes::main(field);
    //hax_poc::non_empty_vec_test();
}

