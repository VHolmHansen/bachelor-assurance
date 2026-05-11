mod tests {
    #[test]
    fn test_key_gen() {
        use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
        use bachelor_assurance::protocols::aes::{encrypt, key_expansion};
        use bachelor_assurance::utils::helper_methods_cstrnts::bits_to_byte;
        use bachelor_assurance::utils::math::transform_byte_array_to_state;
        use bachelor_assurance::utils::constants::beta;

        let (key, pk) = faest_key_gen();

        // Verify all beta blocks are consistent: encrypt(key, plaintext_b) == ciphertext_b
        for b in 0..beta {
            let (plain_text_flat, cipher_text_flat) = pk[b];

            let plaintext: [u8; 16] = std::array::from_fn(|i| {
                bits_to_byte(&plain_text_flat[i*8..i*8+8])
            });
            let ciphertext: [u8; 16] = std::array::from_fn(|i| {
                bits_to_byte(&cipher_text_flat[i*8..i*8+8])
            });

            let plaintext_state = transform_byte_array_to_state(&plaintext);
            let computed_cipher = encrypt(plaintext_state, &key_expansion(key));

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
                "KeyGen block {}: encrypt(key, plaintext) != ciphertext in pk", b
            );

            println!("Block {}:", b);
            println!("  Key:       {:02x?}", key);
            println!("  Plaintext: {:02x?}", plaintext);
            println!("  Ciphertext:{:02x?}", ciphertext);
        }
    }
}