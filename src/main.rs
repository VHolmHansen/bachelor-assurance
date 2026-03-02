mod utils;
mod mpc;
mod lpzk;

#[hax_lib::requires(true)]
fn main() {
    mpc::main();
    lpzk::main()
}
