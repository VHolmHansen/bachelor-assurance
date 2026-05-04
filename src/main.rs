use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify::faest_verify;

pub mod utils;
pub mod protocols;

#[hax_lib::exclude]
fn main() {
    let builder = std::thread::Builder::new().stack_size(32 * 1024 * 1024); // 64MB
    let handler = builder.spawn(|| {
        let start = std::time::Instant::now();
        let (key, pk) = faest_key_gen();
        println!("key_gen took: {:?}", start.elapsed());

        let msg: &[u8] = b"baaaaaaaahhhhhhh";

        let sign_start = std::time::Instant::now();
        let sig = faest_sign(msg, &key, &pk);
        println!("sign took: {:?}", sign_start.elapsed());

        let verify_start = std::time::Instant::now();
        let great_succes = faest_verify(msg, &pk, &sig);
        println!("verify took: {:?}", verify_start.elapsed());

        println!("verify succes: {:?}", great_succes);
    }).unwrap();
    handler.join().unwrap();
}

