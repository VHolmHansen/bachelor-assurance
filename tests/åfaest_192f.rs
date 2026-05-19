#[cfg(all(test, feature = "lambda_192f"))]
mod tests {
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::protocols::faest_sign::faest_sign;
    use bachelor_assurance::protocols::faest_verify::faest_verify;
    use bachelor_assurance::protocols::aes::{encrypt, key_expansion};
    use bachelor_assurance::utils::helper_methods_cstrnts::bits_to_byte;
    use bachelor_assurance::utils::math::transform_byte_array_to_state;
    use bachelor_assurance::utils::constants::beta;

    #[test]
    fn test_key_gen() {
        for i in 0..5 {
            let (key, pk) = faest_key_gen();
            for b in 0..beta {
                let (plain_text_flat, cipher_text_flat) = pk[b];
                let plaintext: [u8; 16] = std::array::from_fn(|j| {
                    bits_to_byte(&plain_text_flat[j * 8..j * 8 + 8])
                });
                let ciphertext: [u8; 16] = std::array::from_fn(|j| {
                    bits_to_byte(&cipher_text_flat[j * 8..j * 8 + 8])
                });
                let plaintext_state = transform_byte_array_to_state(&plaintext);
                let computed_cipher = encrypt(plaintext_state, &key_expansion(key));
                let mut computed_flat = [0u8; 16];
                let mut idx = 0;
                for word in computed_cipher {
                    for byte in word { computed_flat[idx] = byte; idx += 1; }
                }
                assert_eq!(ciphertext, computed_flat,
                           "KeyGen iter {i} block {b}: encrypt(key, plaintext) != ciphertext in pk");
            }
        }
    }

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