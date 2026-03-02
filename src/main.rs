mod utils;
mod mpc;

#[hax_lib::requires(true)]
fn main() {
    mpc::main()
}
