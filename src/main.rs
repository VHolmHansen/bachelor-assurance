mod utils;
mod mpc;
mod lpzk;

#[hax_lib::exclude]
fn main() {
    mpc::main();
    lpzk::main()
}

