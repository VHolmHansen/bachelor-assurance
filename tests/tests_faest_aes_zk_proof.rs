#[cfg(all(test, feature = "lambda_128s"))]
mod tests{
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::protocols::faest_prove_and_verify::{faest_aes_prove, faest_aes_verify};
    use bachelor_assurance::protocols::fs_vole::{chall_dec_k0, chall_dec_k1, FAEST_VOLE_commit, FAEST_VOLE_reconstruct};
    use bachelor_assurance::utils::constants::{chall2_bytes, chall3_bytes, ell, ell_hat_bytes, ell_plus_lambda, iv_bytes, k_0, k_1, lambda_bytes, tau, tau_0, LAMBDA};
    use bachelor_assurance::utils::hash_functions::h_2_3;
    use bachelor_assurance::utils::helper_methods_for_sign::{chall3_to_bits, u_to_1728_bits, vole_to_row_major};
    use bachelor_assurance::utils::types::sized_array_for_cop;
    use bachelor_assurance::utils::vector_commit::{vec_open_k0, vec_open_k1};

    #[test]
    fn test_prove_verify_correlation() {
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
        let handler = builder.spawn(|| {
            // generate a valid FAEST key pair
            let (sk, pk) = faest_key_gen();
            // extend the witness
            let witness = faest_aes_extend_witness(sk, pk);

            // generate r and iv for VOLE commit, same as faest_sign does
            let r: [u8; lambda_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let iv: [u8; iv_bytes] = std::array::from_fn(|_| rand::random::<u8>());

            // commit to the VOLE — gives us u_bytes and v_bytes
            let (hash_com, all_decoms, big_c, u_0, big_v) = FAEST_VOLE_commit(r, iv);

            // convert u_bytes to bits, same as faest_sign line: u_to_1728_bits
            let u_bits: [u8; ell_plus_lambda] = u_to_1728_bits(&u_0);

            // convert v_bytes to row major, same as faest_sign line: vole_to_row_major
            let v_rows: [[u8; LAMBDA]; ell_plus_lambda] = vole_to_row_major(big_v);

            // random chall2 for ZKHash
            let chall2: [u8; chall2_bytes] = std::array::from_fn(|_| rand::random::<u8>());

            // compute d = witness XOR u[0..ell], same as faest_sign
            let d: [u8; ell] = std::array::from_fn(|i| witness[i] ^ u_bits[i]);

            // prover computes (alpha_tilde, beta_tilde)
            let (alpha_tilde, beta_tilde) = faest_aes_prove(witness, &u_bits, &v_rows, pk, chall2);

            // chall3 is derived from chall2 and the proof in real execution
            // here we use it as random for testing
            let chall3: [u8; chall3_bytes] = h_2_3(chall2, alpha_tilde, beta_tilde);

            // open vector commitments using chall3, same as faest_sign
            let mut pdecoms: [(sized_array_for_cop, [u8; 2*lambda_bytes]); tau] =
                [(sized_array_for_cop::sized_array_1([[0u8; lambda_bytes]; k_0]), [0u8; 2*lambda_bytes]); tau];
            for i in 0..tau {
                pdecoms[i] = if i < tau_0 {
                    let s_i: [u8; k_0] = chall_dec_k0(chall3, i);
                    vec_open_k0(&all_decoms[i], &s_i)
                } else {
                    let s_i: [u8; k_1] = chall_dec_k1(chall3, i);
                    vec_open_k1(&all_decoms[i], &s_i)
                };
            }

            // reconstruct VOLE keys
            let (hash_rec, big_q) = FAEST_VOLE_reconstruct(chall3, &pdecoms, iv);
            assert_eq!(hash_com, hash_rec, "VOLE commitment hash mismatch");

            // correct q with c_bytes, same as faest_verify does
            let mut q_corrected = big_q;
            for i in 1..tau {
                if i < tau_0 {
                    let delta_bits: [u8; k_0] = chall_dec_k0(chall3, i);
                    for j in 0..k_0 {
                        if delta_bits[j] == 1 {
                            for byte in 0..ell_hat_bytes {
                                let mut row = *q_corrected[i].get(j);
                                row[byte] ^= big_c[i-1][byte];
                                q_corrected[i] = q_corrected[i].set(j, row);
                            }
                        }
                    }
                } else {
                    let delta_bits: [u8; k_1] = chall_dec_k1(chall3, i);
                    for j in 0..k_1 {
                        if delta_bits[j] == 1 {
                            for byte in 0..ell_hat_bytes {
                                let mut row = *q_corrected[i].get(j);
                                row[byte] ^= big_c[i-1][byte];
                                q_corrected[i] = q_corrected[i].set(j, row);
                            }
                        }
                    }
                }
            }

            // now convert corrected q to row major
            let q_rows: [[u8; LAMBDA]; ell + LAMBDA] = vole_to_row_major(q_corrected);

            // verifier recomputes beta_tilde — should equal beta_tilde from prove
            let result = faest_aes_verify(
                d,
                q_rows,
                chall2,
                chall3_to_bits(&chall3),
                alpha_tilde,
                pk
            );

            assert_eq!(result, beta_tilde, "prove/verify correlation failed");

        }).unwrap();
        handler.join().unwrap();
    }
}