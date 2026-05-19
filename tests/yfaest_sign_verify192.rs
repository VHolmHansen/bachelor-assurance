#[cfg(all(test, feature = "lambda_192s"))]
mod tests {
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::protocols::faest_sign::faest_sign;
    use bachelor_assurance::protocols::faest_verify::faest_verify;

    #[test]
    fn sign_verify_test_random_key() {
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
        let handler = builder.spawn(|| {
            let start = std::time::Instant::now();
            let (key, pk) = faest_key_gen();
            println!("key_gen took: {:?}", start.elapsed());

            let msg: &[u8] = b"hello world";

            let sign_start = std::time::Instant::now();
            let sig = faest_sign(msg, &key, &pk);
            println!("sign took: {:?}", sign_start.elapsed());

            let verify_start = std::time::Instant::now();
            let test_work = faest_verify(msg, &pk, &sig);
            println!("verify took: {:?}", verify_start.elapsed());

            assert!(test_work);
        }).unwrap();
        handler.join().unwrap();
    }
}