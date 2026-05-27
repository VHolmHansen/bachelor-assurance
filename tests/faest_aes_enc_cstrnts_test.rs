
mod tests {
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::aes::{encrypt, key_expansion};
    use bachelor_assurance::protocols::faest_key_exp_cstrnts::{
        faest_aes_exp_cstrnts_qDelta, faest_aes_exp_cstrnts_wv,
        faest_aes_key_exp_fwd,
    };
    use bachelor_assurance::protocols::faest_key_enc_cstrnts::{
        faest_aes_enc_cstrnts_prover, faest_aes_enc_cstrnts_verifier,
    };
    use bachelor_assurance::utils::galois_field::gf128_mul;
    use bachelor_assurance::utils::helper_methods_cstrnts::{byte_to_bits, words_to_blocks};
    use bachelor_assurance::utils::math::{transform_byte_array_to_state, xor_arrays};
    use bachelor_assurance::utils::types::{State};
    use bachelor_assurance::utils::constants::{l_enc, l_ke, lambda, s_enc, S_ke,nk, R};
/*
    fn make_synthetic_vole(
        w_bits: &[u8],
        delta: &[u8; 16],
    ) -> (Vec<[u8; 16]>, Vec<[u8; 16]>) {
        let mut v: Vec<[u8; 16]> = Vec::new();
        let mut q: Vec<[u8; 16]> = Vec::new();

        // Use a simple deterministic "random" for reproducibility in tests
        let mut seed: u64 = 0xdeadbeefcafe1234;
        let mut next_bytes = |s: &mut u64| -> [u8; 16] {
            let mut out = [0u8; 16];
            for i in 0..2 {
                *s ^= *s << 13;
                *s ^= *s >> 7;
                *s ^= *s << 17;
                let bytes = s.to_le_bytes();
                out[i*8..(i+1)*8].copy_from_slice(&bytes);
            }
            out
        };

        for &bit in w_bits {
            let vi = next_bytes(&mut seed);
            // q[i] = bit * delta XOR v[i]
            // bit * delta: if bit=1 use delta, if bit=0 use [0;16]
            let bit_times_delta: [u8; 16] = if bit == 1 {
                *delta
            } else {
                [0u8; 16]
            };
            let qi = xor_arrays(&bit_times_delta, &vi);
            v.push(vi);
            q.push(qi);
        }
        (v, q)
    }

    fn get_key_witness_ciphertext_plaintext() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let key: [u8; 16] = [
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

        let plain_text_flat = blocks_to_u8(plaintext);
        let cipher_text_flat = turn_states_to_bits(ciphertext_state);

        let expanded_key = key_expansion(key);

        let mut expanded_key_flat = vec![];
        let blocks_of_expanded_key = words_to_blocks(expanded_key);

        for block in blocks_of_expanded_key {
            let bits_of_blocks = blocks_to_u8(block);
            for b in bits_of_blocks {
                expanded_key_flat.push(b);
            }
        }


        (expanded_key_flat, w[448..1600].to_vec(), cipher_text_flat, plain_text_flat)
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


    // test for vole tags being zero
    #[test]
    fn test_enc_cstrnts_zero_tags_give_zero_a0() {
        let (key, witness, ciphertext, plaintext) = get_key_witness_ciphertext_plaintext();

        let zero_v = [[0u8; 16]; l_enc];
        let k: [u8; 128 * (R + 1)] = key.try_into().unwrap();
        let v_k = [[0u8; 16]; 128 * (R + 1)];

        let (a0, _a1) = faest_aes_enc_cstrnts_prover(
            lambda,
            plaintext,
            ciphertext,
            witness,
            zero_v,
            k,
            v_k,
            false,
        );

        for i in 0..s_enc {
            assert_eq!(a0[i], [0u8; 16],
                       "A0[{}] should be zero when all VOLE tags are zero", i);
        }
    }

    #[test]
    fn test_enc_cstrnts_zero_delta() {
        let (key, witness, ciphertext, plaintext) = get_key_witness_ciphertext_plaintext();

        let delta = [0u8; 16];
        let (v_enc, q_enc) = make_synthetic_vole(&witness, &delta);

        let v_enc_arr: [[u8; 16]; l_enc] = v_enc.try_into().unwrap();
        let q_enc_arr: [[u8; 16]; l_enc] = q_enc.try_into().unwrap();

        let k: [u8; 128 * (R + 1)] = key.try_into().unwrap();
        let v_k = [[0u8; 16]; 128 * (R + 1)];
        let q_k = [[0u8; 16]; 128 * (R + 1)];

        let (a0, _a1) = faest_aes_enc_cstrnts_prover(
            lambda,
            plaintext.clone(),
            ciphertext.clone(),
            witness,
            v_enc_arr,
            k,
            v_k,
            false,
        );

        let b = faest_aes_enc_cstrnts_verifier(
            lambda,
            (*plaintext).try_into().unwrap(),
            (*ciphertext).try_into().unwrap(),
            &q_enc_arr,
            &q_k,
            delta,
            true,
        );

        for i in 0..s_enc {
            assert_eq!(b[i], a0[i],
                       "With delta=0, B[{}] must equal A0[{}]", i, i);
        }
    }

    #[test]
    fn test_enc_cstrnts_invariant() {
        let (key, witness, ciphertext, plaintext) = get_key_witness_ciphertext_plaintext();

        let delta: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];

        // Make VOLE for the encryption witness
        let (v_enc, q_enc) = make_synthetic_vole(&witness, &delta);

        // Make VOLE for the expanded key
        let (v_k_vec, q_k_vec) = make_synthetic_vole(&key, &delta);

        let v_enc_arr: [[u8; 16]; l_enc] = v_enc.try_into().unwrap();
        let q_enc_arr: [[u8; 16]; l_enc] = q_enc.try_into().unwrap();

        let k: [u8; 128 * (R + 1)] = key.try_into().unwrap();
        let v_k: [[u8; 16]; 128 * (R + 1)] = v_k_vec.try_into().unwrap();
        let q_k: [[u8; 16]; 128 * (R + 1)] = q_k_vec.try_into().unwrap();

        let (a0, a1) = faest_aes_enc_cstrnts_prover(
            lambda,
            plaintext.clone(),
            ciphertext.clone(),
            witness.clone(),
            v_enc_arr,
            k,
            v_k,
            false,
        );

        let b = faest_aes_enc_cstrnts_verifier(
            lambda,
            (*plaintext).try_into().unwrap(),
            (*ciphertext).try_into().unwrap(),
            &q_enc_arr,
            &q_k,
            delta,
            true,
        );

        use bachelor_assurance::protocols::faest_key_enc_cstrnts::faest_aes_enc_fwd;

        let s = faest_aes_enc_fwd::<Vec<u8>>(
            1,
            &witness,
            &k.to_vec(),
            &plaintext,
            false,
            false,
            0,
        );

        let mut zero_sbox = vec![false; s_enc];
        for i in 0..s_enc {
            if s[i] == [0u8; 16] {
                zero_sbox[i] = true;
            }
        }

        for i in 0..s_enc {
            if zero_sbox[i] { continue; }

            let a1_times_delta = gf128_mul(&a1[i], &delta);
            let expected = xor_arrays(&a0[i], &a1_times_delta);

            assert_eq!(
                b[i], expected,
                "Invariant B[i] = A0[i] + A1[i]*delta failed at i={}.\n\
             A0[i]    = {:?}\n\
             A1[i]    = {:?}\n\
             delta    = {:?}\n\
             A1*delta = {:?}\n\
             expected = {:?}\n\
             got B[i] = {:?}",
                i, a0[i], a1[i], delta, a1_times_delta, expected, b[i]
            );
        }

        let total = s_enc;
        let skipped = zero_sbox.iter().filter(|&&z| z).count();
        println!("Checked {}/{} constraints ({} skipped due to zero S-box input)",
                 total - skipped, total, skipped);
    }

    #[test]
    fn test_enc_cstrnts_invariant2() {
        let key: [u8; 16] = [
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

        // Get all the parts we need
        let w_ke = w[..l_ke].to_vec();
        let w_enc = w[l_ke..l_ke + l_enc].to_vec();

        let plain_text_flat = blocks_to_u8(plaintext);
        let cipher_text_flat = turn_states_to_bits(ciphertext_state);

        let expanded_key = key_expansion(key);
        let mut expanded_key_flat = vec![];
        let blocks_of_expanded_key = words_to_blocks(expanded_key);
        for block in blocks_of_expanded_key {
            let bits_of_blocks = blocks_to_u8(block);
            for b in bits_of_blocks {
                expanded_key_flat.push(b);
            }
        }
        let k: [u8; 128 * (R + 1)] = expanded_key_flat.try_into().unwrap();

        let delta: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];

        // Make VOLE for encryption witness
        let (v_enc, q_enc) = make_synthetic_vole(&w_enc, &delta);

        // Make VOLE for key expansion witness, then derive v_k and q_k via KeyExpFwd
        let (v_ke_vole, q_ke_vole) = make_synthetic_vole(&w_ke, &delta);
        let v_k_vec = faest_aes_key_exp_fwd(128, v_ke_vole.clone(), true, false, [0u8; 16]);
        let q_k_vec = faest_aes_key_exp_fwd(128, q_ke_vole.clone(), false, true, delta);

        let v_enc_arr: [[u8; 16]; l_enc] = v_enc.try_into().unwrap();
        let q_enc_arr: [[u8; 16]; l_enc] = q_enc.try_into().unwrap();
        let v_k: [[u8; 16]; 128 * (R + 1)] = v_k_vec.try_into().unwrap();
        let q_k: [[u8; 16]; 128 * (R + 1)] = q_k_vec.try_into().unwrap();

        println!("test v_ke_vole[0] = {:?}", v_ke_vole[0]);
        println!("test v_ke_vole[1] = {:?}", v_ke_vole[1]);

        let (a0, a1) = faest_aes_enc_cstrnts_prover(
            lambda,
            plain_text_flat.clone(),
            cipher_text_flat.clone(),
            w_enc.clone(),
            v_enc_arr,
            k,
            v_k,
            false,
        );

        let b = faest_aes_enc_cstrnts_verifier(
            lambda,
            (*plain_text_flat).try_into().unwrap(),
            (*cipher_text_flat).try_into().unwrap(),
            &q_enc_arr,
            &q_k,
            delta,
            true,
        );

        use bachelor_assurance::protocols::faest_key_enc_cstrnts::faest_aes_enc_fwd;

        let s = faest_aes_enc_fwd::<Vec<u8>>(
            1,
            &w_enc,
            &k.to_vec(),
            &plain_text_flat,
            false,
            false,
            0,
        );

        let mut zero_sbox = vec![false; s_enc];
        for i in 0..s_enc {
            if s[i] == [0u8; 16] {
                zero_sbox[i] = true;
            }
        }

        for i in 0..s_enc {
            if zero_sbox[i] { continue; }

            let a1_times_delta = gf128_mul(&a1[i], &delta);
            let expected = xor_arrays(&a0[i], &a1_times_delta);

            assert_eq!(
                b[i], expected,
                "Invariant B[i] = A0[i] + A1[i]*delta failed at i={}.\n\
             A0[i]    = {:?}\n\
             A1[i]    = {:?}\n\
             delta    = {:?}\n\
             A1*delta = {:?}\n\
             expected = {:?}\n\
             got B[i] = {:?}",
                i, a0[i], a1[i], delta, a1_times_delta, expected, b[i]
            );
        }

        let total = s_enc;
        let skipped = zero_sbox.iter().filter(|&&z| z).count();
        println!("Checked {}/{} constraints ({} skipped due to zero S-box input)",
                 total - skipped, total, skipped);
    }
    
 */

}