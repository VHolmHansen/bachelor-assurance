#[cfg(test)]
mod tests{
    use Bachelor_Assurance::protocols::aes::{encrypt, key_expansion, nk, R};
    use Bachelor_Assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use Bachelor_Assurance::protocols::faest_key_exp_cstrnts::{faest_aes_exp_cstrnts_qDelta, faest_aes_exp_cstrnts_wv};
    use Bachelor_Assurance::utils::galois_field::gf128_mul;
    use Bachelor_Assurance::utils::helper_methods_cstrnts::{alpha_pow, byte_combine};
    use Bachelor_Assurance::utils::math::{transform_byte_array_to_state, xor_arrays};
    use Bachelor_Assurance::utils::types::{l_ke, lambda, S_ke};

    fn get_key_and_witness() -> ([u8; 16], Vec<u8>) {
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
        (key, w)
    }

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

    // alle vole er 0
    #[test]
    fn test_cstrnts_zero_tags_give_zero_a0() {
        let (_key, w) = get_key_and_witness();
        let w_ke = w[..l_ke].to_vec();

        let zero_v = vec![[0u8; 16]; l_ke];
        let (a0, _a1, _, _) = faest_aes_exp_cstrnts_wv(w_ke, zero_v, false);

        for i in 0..S_ke {
            assert_eq!(a0[i], [0u8; 16],
                       "A0[i] should be zero when all VOLE tags are zero, failed at i={}", i);
        }
    }

    #[test]
    fn test_cstrnts_zero_delta() {
        let (_key, w) = get_key_and_witness();
        let w_ke = w[..l_ke].to_vec();

        let delta = [0u8; 16];
        let (v_ke, q_ke) = make_synthetic_vole(&w_ke, &delta);

        let (a0, _a1, _, _) = faest_aes_exp_cstrnts_wv(w_ke, v_ke, false);
        let (b, _)          = faest_aes_exp_cstrnts_qDelta(delta, q_ke, false);

        for i in 0..S_ke {
            assert_eq!(b[i], a0[i],
                       "With delta=0, B[i] must equal A0[i] at i={}", i);
        }
    }

    #[test]
    fn test_diagnose_zero_delta_failure() {
        let (_key, w) = get_key_and_witness();
        let w_ke = w[..l_ke].to_vec();
        let delta = [0u8; 16];

        // With delta=0, q[i] = 0*delta XOR v[i] = v[i]
        // So q and v carry identical data.
        // This means KeyExpFwd and KeyExpBkwd should produce
        // identical outputs when called with (v, Mtag=true)
        // versus (q, Mkey=true, delta=0).

        let (v_ke, q_ke) = make_synthetic_vole(&w_ke, &delta);

        // These should be identical since q[i] == v[i] when delta=0
        for i in 0..l_ke {
            assert_eq!(v_ke[i], q_ke[i],
                       "Precondition failed: v[{}] != q[{}] with delta=0", i, i);
        }

        // Now check that KeyExpFwd gives same result for both paths
        use Bachelor_Assurance::protocols::faest_key_exp_cstrnts::{
            faest_aes_key_exp_fwd, faest_aes_key_exp_bkwd
        };

        let vk_from_tags = faest_aes_key_exp_fwd(128, v_ke.clone(), true, false, [0;16]);
        let qk_from_keys = faest_aes_key_exp_fwd(128, q_ke.clone(), false, true, delta);

        for i in 0..vk_from_tags.len() {
            assert_eq!(
                vk_from_tags[i], qk_from_keys[i],
                "KeyExpFwd diverges at index i={} between tag path and key path with delta=0",
                i
            );
        }

        // Now check KeyExpBkwd
        let k = faest_aes_key_exp_fwd(1, w_ke.clone(), false, false, [0;16]);

        let vw_from_tags = faest_aes_key_exp_bkwd(
            128, v_ke[lambda..].to_vec(), vk_from_tags.to_vec(), true, false, [0;16]
        );
        let qw_from_keys = faest_aes_key_exp_bkwd(
            128, q_ke[lambda..].to_vec(), qk_from_keys.to_vec(), false, true, delta
        );

        for i in 0..vw_from_tags.len() {
            assert_eq!(
                vw_from_tags[i], qw_from_keys[i],
                "KeyExpBkwd diverges at index i={} between tag path and key path with delta=0",
                i
            );
        }
    }

    #[test]
    fn test_diagnose_bytecombine_loop() {
        let (_key, w) = get_key_and_witness();
        let w_ke = w[..l_ke].to_vec();
        let delta = [0u8; 16];

        let (v_ke, q_ke) = make_synthetic_vole(&w_ke, &delta);

        use Bachelor_Assurance::protocols::faest_key_exp_cstrnts::{
            faest_aes_key_exp_fwd, faest_aes_key_exp_bkwd
        };

        let k        = faest_aes_key_exp_fwd(1,   w_ke.clone(), false, false, [0;16]);
        let v_k      = faest_aes_key_exp_fwd(128, v_ke.clone(), true,  false, [0;16]);
        let w_tilde  = faest_aes_key_exp_bkwd(1,   w_ke[lambda..].to_vec(), k.to_vec(),   false, false, 0);
        let v_w      = faest_aes_key_exp_bkwd(128, v_ke[lambda..].to_vec(), v_k.to_vec(), true,  false, [0;16]);

        let q_k      = faest_aes_key_exp_fwd(128, q_ke.clone(), false, true, delta);
        let q_w_flat = faest_aes_key_exp_bkwd(128, q_ke[lambda..].to_vec(), q_k.to_vec(), false, true, delta);

        // With delta=0, q==v so intermediate arrays must match
        for i in 0..v_k.len() {
            assert_eq!(v_k[i], q_k[i],
                       "v_k[{}] != q_k[{}]", i, i);
        }
        for i in 0..v_w.len() {
            assert_eq!(v_w[i], q_w_flat[i],
                       "v_w[{}] != q_w_flat[{}]", i, i);
        }


        let mut i_wd = 32 * (nk - 1);
        let mut do_rot_word = true;

        for j in 0..(S_ke / 4) {
            let mut k_hat:   [[u8;16];4] = [[0;16];4];
            let mut v_k_hat: [[u8;16];4] = [[0;16];4];
            let mut w_hat:   [[u8;16];4] = [[0;16];4];
            let mut v_w_hat: [[u8;16];4] = [[0;16];4];
            let mut q_hat_k: [[u8;16];4] = [[0;16];4];
            let mut q_hat_w: [[u8;16];4] = [[0;16];4];

            for r in 0..4 {
                let r_mark = if do_rot_word {
                    ((r as i64 + 3).rem_euclid(4)) as usize
                } else {
                    r
                };

                // Key words: use r_mark (RotWord reorders key input)
                k_hat[r_mark]   = byte_combine(k  [(i_wd+8*r)..(i_wd+8*r+8)].to_vec());
                v_k_hat[r_mark] = byte_combine(v_k[(i_wd+8*r)..(i_wd+8*r+8)].to_vec());
                q_hat_k[r_mark] = byte_combine(q_k[(i_wd+8*r)..(i_wd+8*r+8)].to_vec());

                // S-box outputs: use plain r (no rotation on output side)
                w_hat[r]   = byte_combine(w_tilde [(32*j+8*r)..(32*j+8*r+8)].to_vec());
                v_w_hat[r] = byte_combine(v_w     [(32*j+8*r)..(32*j+8*r+8)].to_vec());
                q_hat_w[r] = byte_combine(q_w_flat[(32*j+8*r)..(32*j+8*r+8)].to_vec());
                //                                  ^^^^^^^^^ plain r, not r_mark
            }

            if lambda == 256 { do_rot_word = !do_rot_word; }

            // With delta=0: v_k_hat == q_hat_k and v_w_hat == q_hat_w
            for r in 0..4 {
                assert_eq!(v_k_hat[r], q_hat_k[r],
                           "j={} r={}: v_k_hat != q_hat_k after byte_combine", j, r);
                assert_eq!(v_w_hat[r], q_hat_w[r],
                           "j={} r={}: v_w_hat != q_hat_w after byte_combine", j, r);
            }

            // Products must also match when delta=0
            for r in 0..4 {
                let a0 = gf128_mul(&v_k_hat[r], &v_w_hat[r]);
                let b  = gf128_mul(&q_hat_k[r], &q_hat_w[r]);
                assert_eq!(a0, b,
                           "j={} r={}: A0 != B even though inputs matched", j, r);
            }

            if lambda == 192 { i_wd += 192; } else { i_wd += 128; }
        }


    }

#[test]
fn test_cstrnts_invariant() {
    let (_key, w) = get_key_and_witness();
    let w_ke = w[..l_ke].to_vec();

    let delta: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10,
    ];

    let (v_ke, q_ke) = make_synthetic_vole(&w_ke, &delta);

    let (a0, a1, _k_exp, _vk_exp) = faest_aes_exp_cstrnts_wv(
        w_ke.clone(), v_ke, false,
    );
    let (b, _qk_exp) = faest_aes_exp_cstrnts_qDelta(
        delta, q_ke, false,
    );

    use Bachelor_Assurance::protocols::faest_key_exp_cstrnts::faest_aes_key_exp_fwd;
    use Bachelor_Assurance::utils::helper_methods_cstrnts::bits_to_byte;

    // Reconstruct which S-box indices have zero inputs so we can skip them
    let k = faest_aes_key_exp_fwd(1, w_ke.clone(), false, false, [0;16]);
    let mut zero_sbox = vec![false; S_ke];
    let mut i_wd = 32 * (nk - 1);
    let mut do_rot_word = true;
    for j in 0..(S_ke / 4) {
        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };
            let k_byte = bits_to_byte(&k[(i_wd + 8*rotated)..(i_wd + 8*rotated + 8)]);
            if k_byte == 0 {
                zero_sbox[4*j + r] = true;
            }
        }
        if lambda == 256 { do_rot_word = !do_rot_word; }
        if lambda == 192 { i_wd += 192; } else { i_wd += 128; }
    }

    for i in 0..S_ke {
        // Skip zero S-box inputs — constraint k*w=1 does not hold for zero
        if zero_sbox[i] { continue; }

        let a1_times_delta = gf128_mul(&a1[i], &delta);
        let expected = xor_arrays(&a0[i], &a1_times_delta);

        assert_eq!(
            b[i], expected,
            "Invariant B[i] = A0[i] + A1[i]*delta failed at i={}.\n\
             A0[i]      = {:?}\n\
             A1[i]      = {:?}\n\
             delta      = {:?}\n\
             A1*delta   = {:?}\n\
             expected   = {:?}\n\
             got B[i]   = {:?}",
            i, a0[i], a1[i], delta, a1_times_delta, expected, b[i]
        );
    }

    // Also verify that ALL non-zero constraints pass, print a summary
    let total = S_ke;
    let skipped = zero_sbox.iter().filter(|&&z| z).count();
    println!("Checked {}/{} constraints ({} skipped due to zero S-box input)",
        total - skipped, total, skipped);
}

}