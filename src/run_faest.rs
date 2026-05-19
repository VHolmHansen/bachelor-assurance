use std::time::Duration;
use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify::faest_verify;

pub fn run_bench() -> (Duration, Duration, Duration, bool) {
    let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
    let handler = builder.spawn(|| {
        let start_of_key_gen = std::time::Instant::now();
        let (sk, pk) = faest_key_gen();
        let key_gen_end = start_of_key_gen.elapsed();

        let msg: [u8; 32] = rand::random();

        let start_of_sign = std::time::Instant::now();
        let sig = faest_sign(&msg, &sk, &pk);
        let end_of_sign = start_of_sign.elapsed();

        let start_of_verify = std::time::Instant::now();
        let good = faest_verify(&msg, &pk, &sig);
        let end_of_verify = start_of_verify.elapsed();

        (key_gen_end, end_of_sign, end_of_verify, good)
    }).unwrap();
    handler.join().unwrap()
}