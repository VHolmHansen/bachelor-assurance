use crate::utils::constants::{beta, ell, key_schedule_bits, l_enc, l_ke, w_lambda_size};
use crate::utils::constants::{lambda_bytes, ret_size_exp_bwd};
use crate::utils::constants::{nk, R};
use crate::utils::galois_field::gf28_multiply;
use crate::protocols::faest_key_exp_cstrnts::faest_aes_key_exp_bkwd;
use crate::utils::constants::LAMBDA;
use crate::utils::constants::S_ke;
use crate::protocols::faest_key_exp_cstrnts::faest_aes_key_exp_fwd;
use crate::protocols::faest_key_enc_cstrnts::{faest_aes_enc_bkwd, faest_aes_enc_fwd};
use crate::utils::helper_methods_cstrnts::{bits_to_byte, byte_to_bits, words_to_blocks};
use crate::utils::types::{Pk, State, Word, PkBlock};
use crate::protocols::aes::{encrypt, key_expansion};
use crate::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
use crate::utils::constants::s_enc;
use crate::utils::galois_field::gf_lambda_mul;
use crate::utils::libcrux_proxy::RandGenProxy;
use crate::utils::math::transform_byte_array_to_state;


pub fn faest_key_gen() -> ([u8; lambda_bytes], Pk) {
    let mut rng = RandGenProxy::get_rand_gen_sha256();
    loop {
        let mut key: [u8; lambda_bytes] = [0u8; lambda_bytes];
        rng.fill_bytes(&mut key);

        let expanded_key: [Word; (R + 1) << 2] = key_expansion(key);

        // generate beta plaintext/ciphertext pairs under same key
        let mut pk: Pk = [([0u8; 128], [0u8; 128]); beta];
        for b in 0..beta {
            let mut plaintext: [u8; 16] = [0u8; 16];
            rng.fill_bytes_plaintext(&mut plaintext);
            let plaintext_state = transform_byte_array_to_state(&plaintext);
            let ciphertext_state = encrypt(plaintext_state, &expanded_key);
            pk[b] = (blocks_to_u8(plaintext), turn_states_to_bits(ciphertext_state));
        }

        let w = faest_aes_extend_witness(key, pk);
        // first fwd - key schedule check
        let fwd_key = faest_aes_key_exp_fwd(1, w, false, false, [0; lambda_bytes]);
        let w_lambda: [u8; w_lambda_size] = w[LAMBDA..].try_into().unwrap();
        let bwd_key: [u8; ret_size_exp_bwd] = faest_aes_key_exp_bkwd(1, w_lambda, fwd_key, false, false, 0);
        let mut valid = true;

        let one_gf8: u8 = 0x01;
        for i in 0..S_ke {
            let word_idx = i >> 2;
            let byte_idx = i % 4;
            let rotated_idx = (byte_idx + 1) % 4;
            let word_start = (nk - 1 + (word_idx << 2)) << 5;
            let alpha_bits = &fwd_key[word_start + (rotated_idx << 3)..word_start + (rotated_idx << 3) + 8];
            let gamma_bits = &bwd_key[i << 3..(i + 1) << 3];
            let w_alpha = bits_to_byte(alpha_bits);
            let w_gamma = bits_to_byte(gamma_bits);
            let product = gf28_multiply(w_alpha, w_gamma);
            if product != one_gf8 {
                valid = false;
                break;
            }
        }

        if !valid { continue; }
        // second fwd - encryption check for all beta blocks
        let mut expanded_key_flat = [0u8; key_schedule_bits];
        let blocks_of_expanded_key: [[u8; 16]; R + 1] = words_to_blocks(expanded_key);
        let mut idx = 0;
        for block in blocks_of_expanded_key {
            let bits_of_blocks = blocks_to_u8(block);
            for b in bits_of_blocks {
                expanded_key_flat[idx] = b;
                idx += 1;
            }
        }

        let mut one = [0u8; lambda_bytes];
        one[0] = 1;
        let zero = [0u8; lambda_bytes];

        for b in 0..beta {
            let w_enc_start = l_ke + b * l_enc;
            let w_enc: [u8; l_enc] = w[w_enc_start..w_enc_start + l_enc].try_into().unwrap();
            let enc_fwd = faest_aes_enc_fwd(1, &w_enc, &expanded_key_flat, &pk[b].0, false, false, 0);
            let enc_bwd = faest_aes_enc_bkwd(1, &w_enc, &expanded_key_flat, &pk[b].1, false, false, 0);

            for i in 0..s_enc {
                if enc_fwd[i] == zero || enc_bwd[i] == zero {
                    valid = false;
                    break;
                }
                let product = gf_lambda_mul(&enc_fwd[i], &enc_bwd[i]);
                if product != one {
                    valid = false;
                    break;
                }
            }
            if !valid { break; }
        }

        if !valid { continue; }

        return (key, pk);
    }
}

fn blocks_to_u8(x: [u8; 16]) -> [u8; 128] {
    let mut x_flat = [0; 128];
    let mut word_index = 0;
    for byte in x {
        let bits = byte_to_bits(byte);
        for bit in bits {
            x_flat[word_index] = bit;
            word_index += 1;
        }
    }
    x_flat
}

fn turn_states_to_bits(x: State) -> [u8; 128] {
    let mut res = [0; 128];
    let mut word_index = 0;
    for word in x {
        for byte in word {
            let bits = byte_to_bits(byte);
            for bit in bits {
                res[word_index] = bit;
                word_index += 1;
            }
        }
    }
    res
}