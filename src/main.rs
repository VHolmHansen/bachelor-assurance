use bachelor_assurance::run_faest;

pub mod utils;
pub mod protocols;

#[hax_lib::include]
fn main() {
    let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
    let handler = builder.spawn(|| {
        run_faest::run();
    }).unwrap();
    handler.join().unwrap();
}