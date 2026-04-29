mod tests{
    // den her test, tester blot at den public key vi får, er key, (plaintext, enc_key(plaintext))
    #[test]
    fn test_key_gen() {
        use Bachelor_Assurance::protocols::faest_key_gen::faest_key_gen;
        use Bachelor_Assurance::protocols::aes::{encrypt, key_expansion};
        use Bachelor_Assurance::utils::helper_methods_cstrnts::bits_to_byte;
        use Bachelor_Assurance::utils::math::transform_byte_array_to_state;

        let (key, (plain_text_flat, cipher_text_flat)) = faest_key_gen();

        // Verify pk is consistent: encrypt(key, plaintext) == ciphertext
        let plaintext: [u8; 16] = std::array::from_fn(|i| {
            bits_to_byte(&plain_text_flat[i*8..i*8+8])
        });
        let ciphertext: [u8; 16] = std::array::from_fn(|i| {
            bits_to_byte(&cipher_text_flat[i*8..i*8+8])
        });

        let plaintext_state = transform_byte_array_to_state(&plaintext);
        let computed_cipher = encrypt(plaintext_state, &key_expansion(key));

        // Flatten computed ciphertext
        let mut computed_flat = [0u8; 16];
        let mut idx = 0;
        for word in computed_cipher {
            for byte in word {
                computed_flat[idx] = byte;
                idx += 1;
            }
        }

        assert_eq!(
            ciphertext, computed_flat,
            "KeyGen: encrypt(key, plaintext) != ciphertext in pk"
        );

        println!("Key:       {:02x?}", key);
        println!("Plaintext: {:02x?}", plaintext);
        println!("Ciphertext:{:02x?}", ciphertext);
    }
}