mod utils;
mod mpc;
mod lpzk;
mod verifier;
mod prover;

#[hax_lib::exclude]
fn main() {
    mpc::main();
    lpzk::main()
}

