mod tests {
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::protocols::faest_sign::faest_sign;
    use bachelor_assurance::protocols::faest_verify::faest_verify;

    #[test]
    fn sign_verify_test() {
        let builder = std::thread::Builder::new().stack_size(32 * 1024 * 1024);
        let handler = builder.spawn(|| {
            let key = [
                201, 162, 240, 157, 17, 221, 199, 249, 177, 157, 68, 52, 44, 101, 110, 159,
            ];
            // wrap in Pk array format: [([u8;128], [u8;128]); beta]
            let pk = [(
                [
                    1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
                    0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1,
                    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
                    0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0,
                    1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0,
                ],
                [
                    1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0,
                    1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0,
                    1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                    0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
                    1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
                ],
            )];

            let msg: &[u8] = b"hello world";
            let sig = faest_sign(msg, &key, &pk);

            let test_work = faest_verify(msg, &pk, &sig);
            assert!(test_work);
        }).unwrap();
        handler.join().unwrap();
    }

    #[test]
    fn sign_verify_test_random_key() {
        let builder = std::thread::Builder::new().stack_size(9 * 1024 * 1024);
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

    #[test]
    fn sign_verify_test_random_multiple() {
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
        let handler = builder.spawn(|| {
            for i in 0..10 {
                let messages: Vec<&[u8]> = vec![
                    b"hello world",
                    b"the quick brown fox jumps over the lazy dog",
                    b"FAEST signature scheme",
                    b"post-quantum cryptography",
                    b"",
                    b"a",
                    b"1234567890",
                    b"!@#$%^&*()",
                    b"the answer is 42",
                    b"bachelor assurance project",
                ];
                let (key, pk) = faest_key_gen();
                let msg: &[u8] = messages[i];
                let sig = faest_sign(msg, &key, &pk);
                let test_work = faest_verify(msg, &pk, &sig);
                assert!(test_work);
            }
        }).unwrap();
        handler.join().unwrap();
    }
}