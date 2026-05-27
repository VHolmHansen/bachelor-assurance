#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

mod tests{
    use bachelor_assurance::protocols::aes::{encrypt, key_expansion};
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_exp_cstrnts::{faest_aes_exp_cstrnts_qDelta, faest_aes_key_exp_fwd};
    use bachelor_assurance::protocols::faest_prove_and_verify::{faest_aes_prove, faest_aes_verify};
    use bachelor_assurance::utils::constants::{ell_bit_size, l_ke, lambda};
    use bachelor_assurance::utils::galois_field::gf128_mul;
    use bachelor_assurance::utils::helper_methods_cstrnts::byte_to_bits;
    use bachelor_assurance::utils::helper_methods_prove_verify::{to_field, zk_hash};
    use bachelor_assurance::utils::math::{transform_byte_array_to_state, xor_arrays};
    use bachelor_assurance::utils::types::State;
    /*
    #[test]
    fn test_prove_and_verify(){
        let (key, plaintext, w)= find_valid_faest_key();


        let plaintest_state = transform_byte_array_to_state(&plaintext);
        let ciphertext_state = encrypt(plaintest_state, &key_expansion(key));
        let w_arr : [u8; ell_bit_size] = w.try_into().unwrap();

        let plain_text_flat = blocks_to_u8(plaintext);
        let cipher_text_flat = turn_states_to_bits(ciphertext_state);

        let chall_3: [u8; lambda] = [1,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,
                                    0,1,0,1,1,0,1,0,0,1,1,1,0,0,1,0,
                                    1,1,0,0,1,0,1,1,0,1,0,0,1,1,1,0,
                                    0,1,1,0,0,1,0,1,1,0,1,0,0,1,1,1,
                                    1,0,0,1,0,1,1,0,0,1,1,0,1,0,1,0,
                                    0,1,1,1,0,0,1,0,1,1,0,1,0,0,1,1,
                                    1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,
                                    1,1,0,1,0,0,1,1,1,0,0,1,0,1,1,0];
        let delta = to_field(&chall_3, lambda);


        // claude finder på voles
        // fill u with random bits
        let mut u_arr = [0u8; ell_bit_size + lambda];
        for i in 0..ell_bit_size + lambda {
            u_arr[i] = (i % 2) as u8;
        }

        // Build V and Q satisfying q[row] = u[row] * delta XOR v[row]
        let mut V = [[0u8; lambda]; ell_bit_size + lambda];
        let mut Q = [[0u8; lambda]; ell_bit_size + lambda];

        let mut seed: u64 = 0xdeadbeefcafe1234;
        for row in 0..ell_bit_size + lambda {
            let mut v_row = [0u8; lambda];
            for col in 0..lambda {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v_row[col] = (seed & 1) as u8;
            }
            V[row] = v_row;

            let u_times_delta: [u8; lambda] = if u_arr[row] == 1 {
                chall_3
            } else {
                [0u8; lambda]
            };

            let mut q_row = [0u8; lambda];
            for col in 0..lambda {
                q_row[col] = u_times_delta[col] ^ v_row[col];
            }
            Q[row] = q_row;
        }

        let chall_2: [u8; 3 * lambda + 64] = {
            let mut arr = [0u8; 3 * lambda + 64];
            for i in 0..3 * lambda + 64 {
                arr[i] = (i % 2) as u8;
            }
            arr
        };

        let delta_field = to_field(&chall_3, lambda)[0];
        for row in 0..10 {  // just check first 10
            let v_field = to_field(&V[row], lambda)[0];
            let q_field = to_field(&Q[row], lambda)[0];

            let u_times_delta = if u_arr[row] == 1 {
                delta_field
            } else {
                [0u8; 16]
            };

            let expected_q = xor_arrays(&u_times_delta, &v_field);
            assert_eq!(q_field, expected_q,
                       "VOLE relation broken at row {}", row);
        }




        let (a_tilde, b_tilde) = faest_aes_prove(
            w_arr, &u_arr, &V, (plain_text_flat.clone().try_into().unwrap(), cipher_text_flat.clone().try_into().unwrap()), chall_2
        );


        let (a_tilde, b_tilde) = faest_aes_prove(
            w_arr, &u_arr, &V, (plain_text_flat.clone().try_into().unwrap(), cipher_text_flat.clone().try_into().unwrap()), chall_2
        );

        // ============ DIAGNOSTIC CHECKS ============
        use bachelor_assurance::protocols::faest_key_exp_cstrnts::faest_aes_exp_cstrnts_wv;
        use bachelor_assurance::protocols::faest_key_enc_cstrnts::faest_aes_enc_cstrnts_prover;
        use bachelor_assurance::utils::constants::{S_ke, s_enc};

        let delta_field = to_field(&chall_3, lambda)[0];

        // Recompute a0, a1 from prove internals
        let v: Vec<[u8;16]> = (0..ell_bit_size + lambda)
            .map(|row| to_field(&V[row], lambda)[0])
            .collect();

        let w_tilde_exp = &w_arr[0..l_ke];
        let v_tilde_exp = &v[0..l_ke];

        let (a_tilde_0_exp, a_tilde_1_exp, k, v_k) = faest_aes_exp_cstrnts_wv(
            &*w_tilde_exp.to_vec(), &*v_tilde_exp.to_vec(), false
        );

        // Check KeyExp constraint relation: b_i = a0_i XOR gf128_mul(a1_i, delta)
        // Recompute b from verify side
        let q: Vec<[u8;16]> = (0..ell_bit_size + lambda)
            .map(|row| to_field(&Q[row], lambda)[0])
            .collect();

        let mut d = [0u8; ell_bit_size];
        for i in 0..ell_bit_size {
            d[i] = w_arr[i] ^ u_arr[i];
        }

        // Correct Q with d (as verify does)
        let mut Q_mut = Q.clone();
        for row in 0..ell_bit_size {
            if d[row] == 1 {
                for col in 0..lambda {
                    Q_mut[row][col] ^= chall_3[col];
                }
            }
        }
        let q_corrected: Vec<[u8;16]> = (0..ell_bit_size + lambda)
            .map(|row| to_field(&Q_mut[row], lambda)[0])
            .collect();

        let (b1, _) = faest_aes_exp_cstrnts_qDelta(
            delta_field, q_corrected[0..l_ke].to_vec().try_into().unwrap(), true
        );

        // Check each KeyExp constraint
        println!("=== Checking KeyExp constraints ===");
        for i in 0..S_ke {
            let a1_times_delta = gf128_mul(&a_tilde_1_exp[i], &delta_field);
            let expected_b = xor_arrays(&a_tilde_0_exp[i], &a1_times_delta);
            if b1[i] != expected_b {
                println!("KeyExp constraint {} BROKEN:", i);
                println!("  b (verify)          = {:?}", b1[i]);
                println!("  a0 + a1*delta       = {:?}", expected_b);
                println!("  a0                  = {:?}", a_tilde_0_exp[i]);
                println!("  a1                  = {:?}", a_tilde_1_exp[i]);
                println!("  a1*delta            = {:?}", a1_times_delta);
            }
        }

        // Check u_star / v_star / q_star relation
        println!("=== Checking masking values ===");
        for i in 0..lambda {
            let v_field = v[ell_bit_size + i];
            let q_field = q_corrected[ell_bit_size + i];
            let u_val = u_arr[ell_bit_size + i];
            let u_times_delta = if u_val == 1 { delta_field } else { [0u8;16] };
            let expected_q = xor_arrays(&u_times_delta, &v_field);
            if q_field != expected_q {
                println!("Masking VOLE broken at index {}: q={:?}, expected={:?}",
                         i, q_field, expected_q);
            }
        }
        println!("=== Diagnostics done ===");
        // ============ END DIAGNOSTICS ============




        // det gør de inde i sign/verify
        let mut d = [0u8; ell_bit_size];
        for i in 0..ell_bit_size {
            d[i] = w_arr[i] ^ u_arr[i];
        }


        let result = faest_aes_verify(
            d, Q, chall_2, chall_3, a_tilde, (plain_text_flat.try_into().unwrap(), cipher_text_flat.try_into().unwrap())
        );



        assert_eq!(
            result, b_tilde,
            "Verifier output should equal prover b_tilde.\n\
         got:      {:?}\n\
         expected: {:?}",
            result, b_tilde
        );

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

    fn find_valid_faest_key() -> ([u8; 16], [u8; 16], Vec<u8>) {
        use bachelor_assurance::protocols::faest_key_exp_cstrnts::faest_aes_key_exp_fwd;
        use bachelor_assurance::utils::helper_methods_cstrnts::bits_to_byte;
        use bachelor_assurance::utils::constants::{nk, S_ke, lambda};

        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ];

        let mut key_candidate: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        loop {
            let plaintext_state = transform_byte_array_to_state(&plaintext);
            let ciphertext_state = encrypt(plaintext_state, &key_expansion(key_candidate));
            let w = faest_aes_extend_witness(key_candidate, (plaintext_state, ciphertext_state));

            // Pass full w
            let k_exp = faest_aes_key_exp_fwd::<Vec<u8>>(
                1, w.clone().to_vec(), false, false, [0u8;16]
            );

            let mut valid = true;
            let mut i_wd = 32 * (nk - 1);
            for j in 0..(S_ke / 4) {
                for r in 0..4 {
                    let rotated = (r + 1) % 4;
                    let byte_val = bits_to_byte(
                        &k_exp[(i_wd + 8*rotated)..(i_wd + 8*rotated + 8)]
                    );
                    if byte_val == 0 {
                        valid = false;
                        break;
                    }
                }
                if !valid { break; }
                i_wd += 128;
            }

            if valid {
                println!("Found valid FAEST key: {:02x?}", key_candidate);
                return (key_candidate, plaintext, w.to_vec());
            }

            // Increment key
            for i in (0..16).rev() {
                key_candidate[i] = key_candidate[i].wrapping_add(1);
                if key_candidate[i] != 0 { break; }
            }
        }
    }
    
     */
}