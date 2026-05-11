#[cfg(test)]
mod tests {
    use bachelor_assurance::protocols::aes::{encrypt, key_expansion};
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_exp_cstrnts::{faest_aes_key_exp_bkwd, faest_aes_key_exp_fwd};
    use bachelor_assurance::utils::galois_field::gf28_multiply;
    use bachelor_assurance::utils::helper_methods_cstrnts::bits_to_byte;
    use bachelor_assurance::utils::math::transform_byte_array_to_state;
    use bachelor_assurance::utils::constants::{nk, ell_hat_bytes, k_0, k_1, lambda, tau, tau_0, S_ke};
    use bachelor_assurance::utils::helper_methods_cstrnts::byte_to_bits;

    fn make_pk(key: [u8;16], plaintext: [u8;16]) -> bachelor_assurance::utils::types::Pk {
        let expanded_key = key_expansion(key);
        let plaintext_state = transform_byte_array_to_state(&plaintext);
        let ciphertext_state = encrypt(plaintext_state, &expanded_key);

        // convert plaintext to bits
        let mut plain_bits = [0u8; 128];
        for i in 0..16 {
            let bits = byte_to_bits(plaintext[i]);
            for b in 0..8 {
                plain_bits[i*8+b] = bits[b];
            }
        }
        // convert ciphertext to bits
        let mut cipher_bits = [0u8; 128];
        let mut idx = 0;
        for col in ciphertext_state {
            for byte in col {
                let bits = byte_to_bits(byte);
                for b in 0..8 {
                    cipher_bits[idx] = bits[b];
                    idx += 1;
                }
            }
        }
        [(plain_bits, cipher_bits)]
    }

    #[test]
    fn test_extend_witness() {
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

        let pk = make_pk(key, plaintext);
        let w = faest_aes_extend_witness(key, pk);

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
            0xd4, 0xbf, 0x5d, 0x30,
            0xe0, 0xb4, 0x52, 0xae,
            0xb8, 0x41, 0x11, 0xf1,
            0x1e, 0x27, 0x98, 0xe5,
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
    fn test_expfwd_and_expbkwd() {
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

        let pk = make_pk(key, plaintext);
        let w = faest_aes_extend_witness(key, pk);

        let fwd = faest_aes_key_exp_fwd(1, w.clone(), false, false, [0; 16]);
        let w_lambda: [u8; 1472] = w[lambda..].try_into().unwrap();
        let bwd = faest_aes_key_exp_bkwd(1, w_lambda, fwd, false, false, 0);

        let word4_byte0 = bits_to_byte(&fwd[4*32..4*32+8]);
        assert_eq!(word4_byte0, 0xa0);

        let one_gf8: u8 = 0x01;

        for i in 0..S_ke {
            let word_idx = i / 4;
            let byte_idx = i % 4;
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

    fn flatten_vole_columns(big_v: &Vec<Vec<[u8; ell_hat_bytes]>>) -> Vec<Vec<u8>> {
        let num_rows = ell_hat_bytes * 8;
        let mut result: Vec<Vec<u8>> = vec![vec![]; num_rows];
        for i in 0..tau {
            let k_b = if i < tau_0 { k_0 } else { k_1 };
            for j in 0..k_b {
                for row in 0..num_rows {
                    let byte_idx = row / 8;
                    let bit_idx = row % 8;
                    let bit = (big_v[i][j][byte_idx] >> bit_idx) & 1;
                    result[row].push(bit);
                }
            }
        }
        result
    }
}