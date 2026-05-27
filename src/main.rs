use bachelor_assurance::run_faest;

pub mod utils;
pub mod protocols;

#[hax_lib::include]
fn main() {
    run_faest::run();
}