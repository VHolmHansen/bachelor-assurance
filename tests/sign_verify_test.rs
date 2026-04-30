mod tests {
    use Bachelor_Assurance::protocols::faest_key_gen::faest_key_gen;
    use Bachelor_Assurance::protocols::faest_sign::faest_sign;
    use Bachelor_Assurance::protocols::faest_verify::faest_verify;
    use Bachelor_Assurance::protocols::fs_vole::{FAEST_VOLE_commit, chall_dec};
    use Bachelor_Assurance::utils::constants::tau;
    use Bachelor_Assurance::utils::hash_functions::{h_1_for_sign, h_2_3, h_3};
    use Bachelor_Assurance::utils::helper_methods_for_sign::chall3_to_bits;
    use Bachelor_Assurance::utils::types::Tree;
    use stacker;

    #[test]
    fn sign_verify_test() {
        let key = [
            201, 162, 240, 157, 17, 221, 199, 249, 177, 157, 68, 52, 44, 101, 110, 159,
        ];
        let pk = (
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
        );

        let msg: &[u8] = b"hello world";
        let sig = faest_sign(msg, &key, &pk);

        let test_work = faest_verify(msg, &pk, &sig);
        assert!(test_work);
    }
    #[test]
    fn sign_verify_test_random_key() {
        let builder = std::thread::Builder::new().stack_size(3 * 1024 * 1024); // 64MB
        let handler = builder.spawn(|| {
            let (key, pk) = faest_key_gen();
            let msg: &[u8] = b"hello world";
            println!("sign start - remaining stack: {:?}", stacker::remaining_stack());
            let sig = faest_sign(msg, &key, &pk);
            let test_work = faest_verify(msg, &pk, &sig);
            assert!(test_work);
        }).unwrap();
        handler.join().unwrap();
    }
    #[test]
    fn sign_verify_test_random_key_multiple() {
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024); // 64MB
        let handler = builder.spawn(|| {for i in 0..10 {
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
        }}).unwrap();
        handler.join().unwrap();
    }

}
