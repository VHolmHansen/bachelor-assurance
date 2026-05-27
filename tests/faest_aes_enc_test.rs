mod tests{
    use bachelor_assurance::protocols::aes::{encrypt, key_expansion};
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_enc_cstrnts::{faest_aes_enc_bkwd, faest_aes_enc_fwd};
    use bachelor_assurance::utils::galois_field::gf128_mul;
    use bachelor_assurance::utils::helper_methods_cstrnts::{byte_to_bits, words_to_blocks};
    use bachelor_assurance::utils::math::transform_byte_array_to_state;
    use bachelor_assurance::utils::types::{State};
    use bachelor_assurance::utils::constants::{s_enc};
    
    /*
    #[test]
    fn test_aes_enc_fwd_bkwd() {
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

        // need to turn it into a bunch of u8's
        let plain_text_flat = blocks_to_u8(plaintext);
        let cipher_text_flat = turn_states_to_bits(ciphertext_state);

        let mut expanded_key_flat = vec![];
        let blocks_of_expanded_key = words_to_blocks(expanded_key);

        for block in blocks_of_expanded_key {
            let bits_of_blocks = blocks_to_u8(block);
            for b in bits_of_blocks {
                expanded_key_flat.push(b);
            }
        }

        let w_enc: Vec<u8> = w[448..1600].to_vec();

        let fwd = faest_aes_enc_fwd(1, &w_enc, &expanded_key_flat, &plain_text_flat, false,false, 0);
        let bwd = faest_aes_enc_bkwd(1, &w_enc, &expanded_key_flat, &cipher_text_flat, false,false, 0);

        for i in 0..s_enc {
            if fwd[i] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] || bwd[i] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] {
                continue;
            }
            let product = gf128_mul(&fwd[i], &bwd[i]);
            assert_eq!(product, [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "S-box #{i} failed: {:?}", product);
        }

    }


    fn blocks_to_u8(x : [u8;16]) -> Vec<u8>{
        let mut x_flat = vec![];
        for byte in x {
            let bits = byte_to_bits(byte);
            for bit in bits {
                x_flat.push(bit);
            }
        }
        x_flat
    }
    fn turn_states_to_bits(x : State) -> Vec<u8> {
        let mut res = vec![];
        for word in x {
            for byte in word {
                let bits = byte_to_bits(byte);
                for bit in bits {
                    res.push(bit);
                }
            }
        }
        res
    }
    
     */
}