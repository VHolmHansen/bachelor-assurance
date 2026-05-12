#[cfg(test)]
mod tests{
    use bachelor_assurance::protocols::aes::key_expansion;
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_enc_cstrnts::{faest_aes_enc_cstrnts_prover, faest_aes_enc_cstrnts_verifier};
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::protocols::fs_vole::FAEST_VOLE_commit;
    use bachelor_assurance::utils::constants::{chall3_bytes, iv_bytes, key_schedule_bits, l_enc, l_ke, lambda_bytes, s_enc, R};
    use bachelor_assurance::utils::galois_field::gf_lambda_mul;
    use bachelor_assurance::utils::helper_methods_cstrnts::byte_to_bits;
    use bachelor_assurance::utils::math::xor_arrays;
    use bachelor_assurance::utils::preliminary_helper_methods::flatten;
    // a test for checking the constraints that should hold for the encryption routine
    #[test]
    fn test_enc_cstrnts_correlation() {
        // generate a secret key and a public key
        let (sk, pk) = faest_key_gen();
        // generate a witness
        let witness = faest_aes_extend_witness(sk, pk);

        // here we want to get the shift_row bits, which are the one we get in the expanded witness from the encryption routine
        let w: [u8; l_enc] = witness[l_ke..l_ke + l_enc].try_into().unwrap();

        // We need to rewrite the expanded key into bits, this k is used by the prover, and the vole correlated values
        let expanded_key = key_expansion(sk);
        let k_flat: [u8; (R+1) << 4] = flatten::<{(R+1) << 2}, 4, {(R+1) << 4}>(expanded_key);
        let mut k: [u8; key_schedule_bits] = [0u8; key_schedule_bits];
        for i in 0..(R+1)*16 {
            let bits = byte_to_bits(k_flat[i]);
            for b in 0..8 {
                k[i*8 + b] = bits[b];
            }
        }

        // we need some vole correlated values, since they are used to do VITH
        let v: [[u8; lambda_bytes]; l_enc] =
            std::array::from_fn(|_| std::array::from_fn(|_| rand::random::<u8>()));
        let v_k: [[u8; lambda_bytes]; key_schedule_bits] =
            std::array::from_fn(|_| std::array::from_fn(|_| rand::random::<u8>()));

        // A random challenge
        let delta: [u8; lambda_bytes] =
            std::array::from_fn(|_| rand::random::<u8>());

        // compute q and q_k from vole relation q[i] = v[i] XOR (w[i] * delta), this is proven by fs_vole tests
        let mut q: [[u8; lambda_bytes]; l_enc] = [[0u8; lambda_bytes]; l_enc];
        for i in 0..l_enc {
            let w_times_delta = if w[i] == 1 { delta } else { [0u8; lambda_bytes] };
            q[i] = xor_arrays(&v[i], &w_times_delta);
        }

        let mut q_k: [[u8; lambda_bytes]; key_schedule_bits] = [[0u8; lambda_bytes]; key_schedule_bits];
        for i in 0..key_schedule_bits {
            let k_times_delta = if k[i] == 1 { delta } else { [0u8; lambda_bytes] };
            q_k[i] = xor_arrays(&v_k[i], &k_times_delta);
        }
        // get plaintext and ciphertext
        let (in_block, out_block) = pk[0];

        // Using the prover we get A_0 and A_1
        let (A_0, A_1) = faest_aes_enc_cstrnts_prover(
            1, in_block, out_block, w, v, k, v_k, false
        );

        // from verifier we compute B
        let B = faest_aes_enc_cstrnts_verifier(
            1, &in_block, &out_block, &q, &q_k, delta, true
        );

        // check B[j] == A_0[j] XOR (A_1[j] * delta), this should hold for every s_box
        for j in 0..s_enc {
            let a1_times_delta = gf_lambda_mul(&A_1[j], &delta);
            let expected_b = xor_arrays(&A_0[j], &a1_times_delta);
            assert_eq!(B[j], expected_b, "enc constraint correlation failed at S-box {j}");
        }
    }
}