#[cfg(all(test, feature = "lambda_128s"))]
mod tests{
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_exp_cstrnts::{faest_aes_exp_cstrnts_qDelta, faest_aes_exp_cstrnts_wv};
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::utils::constants::{key_schedule_bits, l_ke, lambda_bytes, S_ke};
    use bachelor_assurance::utils::galois_field::gf_lambda_mul;
    use bachelor_assurance::utils::math::xor_arrays;

    #[test]
    fn test_exp_cstrnts_correlation() {
        // generate a valid FAEST key pair, ensuring no S-box gets a zero input (Section 8.1)
        let (sk, pk) = faest_key_gen();
        // extend the witness — gives us key bits, non-linear word bits and shift-row bits (Section 6.1)
        let witness = faest_aes_extend_witness(sk, pk);

        // extract the key expansion part of the witness — first l_ke = 448 bits
        // this contains the raw key bits (first lambda = 128 bits) and the
        // non-linear word bits (the words that went through SubWord, next 320 bits)
        let w_tilde_exp: [u8; l_ke] = witness[0..l_ke].try_into().unwrap();

        // generate random VOLE tags for each of the l_ke witness bits
        // in a real execution these come from FAEST_VOLE_commit, but any random
        // values work here since the correlation holds independently of the tags
        let v_tilde_exp: [[u8; lambda_bytes]; l_ke] =
            std::array::from_fn(|_| std::array::from_fn(|_| rand::random::<u8>()));

        // random global VOLE key Delta in F_{2^lambda} (Section 2.1.1)
        // this is the verifier's secret that makes the VOLE commitments binding
        let delta: [u8; lambda_bytes] =
            std::array::from_fn(|_| rand::random::<u8>());

        // prover side — computes:
        // A_0[j] = v_k_hat[j] * v_w_hat[j]  (product of VOLE tags of S-box input and output)
        // A_1[j] = (k_hat[j] + v_k_hat[j]) * (w_hat[j] + v_w_hat[j]) - 1 - A_0[j]
        // also returns k (full expanded key as bits) and v_k (VOLE tags for expanded key)
        // which are needed by enc_cstrnts (Section 6.2.3)
        let (A_0, A_1, k, v_k) = faest_aes_exp_cstrnts_wv(w_tilde_exp, v_tilde_exp, false);

        // compute VOLE keys q from the VOLE relation (Equation 1):
        // q[i] = v[i] XOR (w[i] * Delta)
        // since w[i] is a single bit, w[i] * Delta is either Delta or 0
        let mut q: [[u8; lambda_bytes]; l_ke] = [[0u8; lambda_bytes]; l_ke];
        for i in 0..l_ke {
            let w_times_delta = if w_tilde_exp[i] == 1 { delta } else { [0u8; lambda_bytes] };
            q[i] = xor_arrays(&v_tilde_exp[i], &w_times_delta);
        }

        // verifier side — computes:
        // B[j] = q_k_hat[j] * q_w_hat[j] - Delta^2
        // using only the VOLE keys q and Delta, without seeing w or v directly
        // also returns q_k (VOLE keys for expanded key) needed by enc_cstrnts verifier
        let (B, q_k) = faest_aes_exp_cstrnts_qDelta(delta, q, true);

        // check the core QuickSilver relation from Section 2.3.2 equation (3):
        // B[j] == A_0[j] XOR (A_1[j] * Delta) for each of the S_ke key expansion S-boxes
        // this holds if and only if the prover correctly computed k_hat[j] * w_hat[j] = 1
        // for every SubWord S-box in the key expansion, meaning the key schedule was correct
        for j in 0..S_ke {
            let a1_times_delta = gf_lambda_mul(&A_1[j], &delta);
            let expected_b = xor_arrays(&A_0[j], &a1_times_delta);
            assert_eq!(B[j], expected_b, "key exp constraint correlation failed at S-box {j}");
        }

        // additionally check that q_k is consistent with v_k and k via the VOLE relation:
        // q_k[i] = v_k[i] XOR (k[i] * Delta)
        // this verifies that the expanded key VOLE keys returned by the verifier
        // are correctly derived from the expanded key bits and their VOLE tags
        for i in 0..key_schedule_bits {
            let k_times_delta = if k[i] == 1 { delta } else { [0u8; lambda_bytes] };
            let expected_q_k = xor_arrays(&v_k[i], &k_times_delta);
            assert_eq!(q_k[i], expected_q_k, "q_k VOLE relation failed at index {i}");
        }
    }

}