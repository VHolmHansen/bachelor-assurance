#[cfg(test)]
mod tests {
    use Bachelor_Assurance::protocols::aes::{encrypt, key_expansion, nk};
    use Bachelor_Assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use Bachelor_Assurance::protocols::faest_key_exp_cstrnts::{faest_aes_key_exp_bkwd, faest_aes_key_exp_fwd};
    use Bachelor_Assurance::utils::galois_field::{gf28_inverse, gf28_multiply};
    use Bachelor_Assurance::utils::helper_methods_cstrnts::bits_to_byte;
    use Bachelor_Assurance::utils::math::transform_byte_array_to_state;
    use Bachelor_Assurance::utils::types::{lambda, S_ke};

    #[test]
    fn test_extend_witness(){
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ];
        let expanded_key = key_expansion(key);

        let plaintext_state = transform_byte_array_to_state(&plaintext);
        let ciphertext_state = encrypt(plaintext_state, &expanded_key);

        let w = faest_aes_extend_witness(key, (plaintext_state, ciphertext_state));

        let expanded_key_flat: Vec<u8>= expanded_key.into_iter().flat_map(|arr| arr).collect();

        let first_128_bits_of_witness = w[0..128].to_vec();
        for i in 0..16 {
            let byte_i = &first_128_bits_of_witness[8*i..8*i+8];
            let byte = bits_to_byte(byte_i);

            assert_eq!(byte, key[i]);
        }

        // check first non-lin word at bits [128..160]
        let first_nonlin_word = [0xa0u8, 0xfa, 0xfe, 0x17];
        for i in 0..4 {
            let byte_i = &w[128 + 8*i..128 + 8*i + 8];
            let byte = bits_to_byte(byte_i);
            assert_eq!(
                byte, first_nonlin_word[i],
                "Non-lin word byte {} mismatch: got {:#04x} expected {:#04x}",
                i, byte, first_nonlin_word[i]
            );
        }

        // Round 1 ShiftRows output from FIPS-197 Appendix B
        let round1_after_shiftrows: [u8; 16] = [
            0xd4, 0xbf, 0x5d, 0x30,  // col 0
            0xe0, 0xb4, 0x52, 0xae,  // col 1
            0xb8, 0x41, 0x11, 0xf1,  // col 2
            0x1e, 0x27, 0x98, 0xe5,  // col 3
        ];

        for i in 0..16 {
            let byte_i = &w[448 + 8*i..448 + 8*i + 8];
            let byte = bits_to_byte(byte_i);
            assert_eq!(
                byte, round1_after_shiftrows[i],
                "Round 1 ShiftRows byte {} mismatch: got {:#04x} expected {:#04x}",
                i, byte, round1_after_shiftrows[i]
            );
        }

    }


    #[test]
    fn test_expfwd_and_expbkwd(){
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ];
        let plaintext_state = transform_byte_array_to_state(&plaintext);
        let ciphertext_state = encrypt(plaintext_state, &key_expansion(key));

        let w = faest_aes_extend_witness(key, (plaintext_state, ciphertext_state));

        let fwd = faest_aes_key_exp_fwd(1, w.clone(), false, false, [0;16]);
        let bwd = faest_aes_key_exp_bkwd(1, w[lambda..].to_vec(), fwd.to_vec(), false, false, 0);

        let word4_byte0 = bits_to_byte(&fwd[4*32..4*32+8]);

        assert_eq!(word4_byte0, 0xa0);

        let one_gf8 : u8 = 0x01;

        for i in 0..S_ke{
            let word_idx = i / 4;      // which SubWord word (0..10)
            let byte_idx = i % 4;      // which byte within word (0..4)

            // RotWord: byte 0 of output = byte 1 of input, etc.
            let rotated_idx = (byte_idx + 1) % 4;

            let word_start = (nk - 1 + word_idx * nk) * 32;
            let alpha_bits = &fwd[word_start + 8*rotated_idx..word_start + 8*rotated_idx + 8];
            let gamma_bits = &bwd[i*8..(i+1)*8];

            let w_alpha = bits_to_byte(alpha_bits);
            let w_gamma = bits_to_byte(gamma_bits);


            let product = gf28_multiply(w_alpha, w_gamma);
            if w_alpha != 0 && w_gamma != 0 {
                assert_eq!(product, one_gf8);
            }
        }

    }

}