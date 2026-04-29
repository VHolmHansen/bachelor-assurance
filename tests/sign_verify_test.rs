mod tests {
    use Bachelor_Assurance::protocols::faest_key_gen::faest_key_gen;
    use Bachelor_Assurance::protocols::faest_sign::faest_sign;
    use Bachelor_Assurance::protocols::faest_verify::faest_verify;
    use Bachelor_Assurance::protocols::fs_vole::{FAEST_VOLE_commit, chall_dec};
    use Bachelor_Assurance::utils::constants::tau;
    use Bachelor_Assurance::utils::hash_functions::{h_1_for_sign, h_2_3, h_3};
    use Bachelor_Assurance::utils::helper_methods_for_sign::chall3_to_bits;
    use Bachelor_Assurance::utils::types::Tree;
    use Bachelor_Assurance::utils::vector_commit::vec_open;

    #[test]
    fn sign_verify_test() {
        let key = [
            201, 162, 240, 157, 17, 221, 199, 249, 177, 157, 68, 52, 44, 101, 110, 159,
        ];
        let pk = (
            vec![
                1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
                0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1,
                1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
                0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0,
                1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0,
            ],
            vec![
                1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0,
                1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0,
                1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
                1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
            ],
        );

        let msg: &[u8] = b"hello world";
        let sig = faest_sign(msg, key, pk.clone());

        let test_work = faest_verify(msg, pk, sig);
        assert!(test_work);
    }
    #[test]
    fn sign_verify_test_random_key() {
        let (key, pk) = faest_key_gen();

        let msg: &[u8] = b"hello world";
        let sig = faest_sign(msg, key, pk.clone());

        let test_work = faest_verify(msg, pk, sig);
        assert!(test_work);
    }
    #[test]
    fn sign_verify_test_random_key_multiple() {
        let messages: Vec<&[u8]> = vec![
            b"hello world",
            b"the quick brown fox jumps over the lazy dog",
            b"FAEST signature scheme",
            b"post-quantum cryptography",
            b"",
            b"a",
            b"1234567890",
            b"!@#$%^&*()",
            b"the answer is 42",
            b"bachelor assurance project",
        ];
        for i in 0..10 {
            let (key, pk) = faest_key_gen();

            let msg: &[u8] = messages[i];
            let sig = faest_sign(msg, key, pk.clone());

            let test_work = faest_verify(msg, pk, sig);
            assert!(test_work);
        }
    }

    use super::*;
    use Bachelor_Assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use Bachelor_Assurance::protocols::faest_key_enc_cstrnts::{
        faest_aes_enc_bkwd, faest_aes_enc_fwd,
    };
    use Bachelor_Assurance::protocols::faest_prove_and_verify::{
        faest_aes_prove, faest_aes_verify,
    };
    use Bachelor_Assurance::protocols::fs_vole::FAEST_VOLE_reconstruct;
    use Bachelor_Assurance::utils::constants::{ell_bit_size, k_0, k_1, lambda, tau_0};
    use Bachelor_Assurance::utils::galois_field::gf128_mul;
    use Bachelor_Assurance::utils::hash_functions::{h_1_for_non_specific_size, h_2_1, h_2_2};
    use Bachelor_Assurance::utils::helper_methods_for_sign::{
        bits_to_state, expand_bits_56, u_to_bits, vole_hash, vole_to_row_major,
    };
    use Bachelor_Assurance::utils::math::xor_arrays;

    #[test]
    fn test_sign_verify_intermediate_relationships() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024) // 64 MB
            .spawn(|| {
            // ── hardcoded inputs ──────────────────────────────────────────────
            let key = [
                201, 162, 240, 157, 17, 221, 199, 249,
                177, 157,  68,  52, 44, 101, 110, 159,
            ];
            let pk = (
                vec![
                    1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,
                    1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,1,0,1,1,0,
                    0,1,1,1,0,0,0,1,0,1,0,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1,1,0,0,1,1,1,
                    1,0,0,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,0,0,0,0,0,1,1,1,0,1,1,1,0,0,
                ],
                vec![
                    1,1,0,0,0,1,0,1,1,0,0,0,0,0,1,1,0,1,0,1,1,0,0,1,0,0,0,0,1,1,0,0,
                    0,0,0,1,0,0,0,1,0,1,0,1,1,0,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,0,1,1,
                    1,0,1,0,1,1,1,1,0,0,1,1,0,0,0,1,0,0,0,0,0,0,1,1,1,1,1,0,1,0,0,1,
                    1,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,
                ],
            );
            let msg: &[u8] = b"hello world";
            let rho: [u8; 16] = [
                61, 215, 79, 64, 155, 186, 86, 32,
                78,  30,  5, 68, 224, 135, 13, 95,
            ];

            // ── shared mu ─────────────────────────────────────────────────────
            let mu: [u8; 32] = h_1_for_sign(pk.clone(), msg);

            // ═════════════════════════════════════════════════════════════════
            // SIGN SIDE
            // ═════════════════════════════════════════════════════════════════
            let (r, iv): ([u8; 16], [u8; 16]) = h_3(key, mu, rho);

            let (h_com, decoms, c_bytes, u_bytes, v_bytes) = FAEST_VOLE_commit(r, iv);

            let chall_1: [u8; 88] = h_2_1(mu, h_com, c_bytes.clone(), iv);

            // u_tilde
            let u_x_0 = &u_bytes[0..216];
            let u_x_1 = &u_bytes[216..234];
            let u_tilde = vole_hash(&chall_1, u_x_0, u_x_1);

            // v_tilde + h_v
            let mut v_tilde: Vec<[u8; 18]> = vec![];
            for i in 0..tau {
                let k_b = if i < tau_0 { k_0 } else { k_1 };
                for j in 0..k_b {
                    let col = &v_bytes[i][j];
                    let col_hash = vole_hash(&chall_1, &col[0..216], &col[216..234]);
                    v_tilde.push(col_hash.try_into().unwrap());
                }
            }
            let h_v_sign = h_1_for_non_specific_size(v_tilde.into_iter().flatten().collect());

            // bits
            let u_bits_full: Vec<u8> = u_to_bits(&u_bytes);
            let u_bits = u_bits_full[..ell_bit_size + lambda].to_vec();
            let v_rows: Vec<[u8; lambda]> = vole_to_row_major(&v_bytes);

            // extended witness + d
            let pt_state = bits_to_state(pk.clone().0);
            let ct_state = bits_to_state(pk.clone().1);
            let extended_witness = faest_aes_extend_witness(key, (pt_state, ct_state));

            let mut d: Vec<u8> = vec![];
            for i in 0..ell_bit_size {
                d.push(extended_witness[i] ^ u_bits[i]);
            }

            let chall_2: [u8; 56] = h_2_2(chall_1, u_tilde.clone(), h_v_sign, d.clone());

            let u_arr: [u8; ell_bit_size + lambda] = u_bits.try_into().unwrap();
            let v_arr: [[u8; lambda]; ell_bit_size + lambda] = v_rows.try_into().unwrap();

            let (a_tilde, b_tilde_sign) = faest_aes_prove(
                extended_witness.clone().try_into().unwrap(),
                u_arr,
                v_arr,
                (pk.0.clone().try_into().unwrap(), pk.1.clone().try_into().unwrap()),
                expand_bits_56(chall_2),
            );

            let chall_3: [u8; 16] = h_2_3(chall_2, a_tilde, b_tilde_sign);

            // pdecoms
            let mut pdecoms: Vec<(Vec<[u8; 16]>, [u8; 32])> = vec![];
            for i in 0..tau {
                let s_i = chall_dec(chall_3, i);
                let pdecom = vec_open(decoms[i].clone(), s_i.clone(), s_i.len() as i128);
                pdecoms.push(pdecom);
            }

            // ═════════════════════════════════════════════════════════════════
            // VERIFY SIDE
            // ═════════════════════════════════════════════════════════════════
            let (h_com_verify, q_mark) = FAEST_VOLE_reconstruct(chall_3, pdecoms, iv);

            // CHECK 1: h_com must match
            assert_eq!(
                h_com, h_com_verify,
                "FAIL: h_com from VOLECommit != h_com from VOLEReconstruct"
            );

            let chall_1_verify: [u8; 88] = h_2_1(mu, h_com_verify, c_bytes.clone(), iv);

            // CHECK 2: chall_1 must match
            assert_eq!(
                chall_1, chall_1_verify,
                "FAIL: chall_1 differs between sign and verify"
            );

            // correct Q
            let mut q_corrected = q_mark.clone();
            for i in 1..tau {
                let k_b = if i < tau_0 { k_0 } else { k_1 };
                let delta_bits = chall_dec(chall_3, i);
                for j in 0..k_b {
                    if delta_bits[j] == 1 {
                        for byte in 0..234 {
                            q_corrected[i][j][byte] ^= c_bytes[i][byte];
                        }
                    }
                }
            }

            // CHECK A4: verify vole_to_row_major is consistent between v and q
            // Take instance 0, column 0, and manually check what row 0 should be.
            // v_bytes[0][0] is the raw column of 234 bytes.
            // Row i of that column = bit i of the 234-byte array, expanded to lambda bits.
            // vole_to_row_major should give us v_arr[i] = the i-th row across ALL columns.

            // Manually extract row 0 and row 1 from v_bytes directly
            // by reading bit i from each column and assembling the lambda-bit row.
            {
                // The structure of v_bytes is:
                // v_bytes[instance][column][byte] where each column is ell_hat bits packed
                // Row i of V = for each (instance,col), take bit i of that column
                // assembled into a lambda-bit value.

                // Let's just compare what vole_to_row_major gives for v vs q
                // against what we get by manually reading instance 0, col 0, bit 0

                println!("=== vole_to_row_major consistency check ===");
                println!("v_arr row 0 first 8: {:?}", &v_arr[0][..8]);
                println!("v_arr row 1 first 8: {:?}", &v_arr[1][..8]);

                let q_rows_raw: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);
                println!("q_arr row 0 first 8: {:?}", &q_rows_raw[0][..8]);
                println!("q_arr row 1 first 8: {:?}", &q_rows_raw[1][..8]);

                // Now manually read: what is bit 0 of v_bytes[0][0]?
                // and bit 0 of q_corrected[0][0]?
                println!("v_bytes[0][0] byte 0: {:08b}", v_bytes[0][0][0]);
                println!("q_corrected[0][0] byte 0: {:08b}", q_corrected[0][0][0]);

                // The VOLE relation at column level (before row_major) should hold:
                // q_corrected[0][0] XOR v_bytes[0][0] = delta_0 * u_bytes
                // where delta_0 = chall_dec(chall_3, 0)[0]
                let delta_bits_0 = chall_dec(chall_3, 0);
                println!("delta bit 0 for instance 0: {}", delta_bits_0[0]);

                let mut col_xor = [0u8; 234];
                for b in 0..234 {
                    col_xor[b] = q_corrected[0][0][b] ^ v_bytes[0][0][b];
                }
                let expected_col: [u8; 234] = if delta_bits_0[0] == 1 {
                    u_bytes
                } else {
                    [0u8; 234]
                };
                println!("col_xor first 8: {:?}", &col_xor[..8]);
                println!("expected first 8: {:?}", &expected_col[..8]);
                println!("column relation holds: {}", col_xor == expected_col);

                // So if column relation holds but row relation doesn't,
                // vole_to_row_major must be reordering or mispacking bits.
                // Check: does vole_to_row_major treat v_bytes and q_corrected
                // as the same shape?
                println!("v_bytes[0].len()={}, q_corrected[0].len()={}",
                         v_bytes[0].len(), q_corrected[0].len());
                println!("v_bytes[0][0].len()={}, q_corrected[0][0].len()={}",
                         v_bytes[0][0].len(), q_corrected[0][0].len());
            }

            // CHECK A3: verify that c_bytes[i] == u_i XOR u_0
            // We have u_bytes (= u_0) from VOLECommit.
            // We need u_i for each i, which VOLECommit also produced internally.
            // We can re-derive it: run ConvertToVOLE on instance i's seeds and
            // extract its u output, then check c_bytes[i] == u_i XOR u_bytes.

            // For now, do the inverse check: after ci-correction, does
            // q_corrected[i][j] match what it should be if c_i were correct?
            // Specifically: for delta_j=1, q_corrected[i][j] should now equal
            // v_bytes[i][j] XOR (delta_j * u_bytes)
            // i.e. the same relation as instance 0.

            println!("Checking c_bytes consistency:");
            for i in 1..tau {
                let k_b = if i < tau_0 { k_0 } else { k_1 };
                let delta_bits = chall_dec(chall_3, i);
                for j in 0..k_b {
                    if delta_bits[j] == 1 {
                        // After correction, q[i][j] should equal v[i][j] XOR u_bytes
                        // (same as instance 0 with delta_j=1)
                        let mut expected = v_bytes[i][j];
                        for byte in 0..234 {
                            expected[byte] ^= u_bytes[byte];
                        }
                        if q_corrected[i][j] != expected {
                            println!(
                                "  instance {i} col {j}: q_corrected != v XOR u\n  first 8 of q_corrected: {:?}\n  first 8 of expected:    {:?}\n  first 8 of c_bytes[i]:  {:?}\n  first 8 of u_bytes:     {:?}",
                                &q_corrected[i][j][..8],
                                &expected[..8],
                                &c_bytes[i][..8],
                                &u_bytes[..8],
                            );
                        } else {
                            println!("  instance {i} col {j}: OK after correction");
                        }
                    }
                }
            }

            // CHECK 3: raw VOLE correlation Q[i][j] = V[i][j] XOR (delta_j * u_i)
            // where u_i is the per-instance secret (before correction)
            // After correction all instances share u = u_0
            // So: Q_corrected[i][j] = V[i][j] XOR (delta_j * u)  (bitwise, per byte)
            {
                let delta_bits_0 = chall_dec(chall_3, 0);
                let k_b_0 = k_0;
                for j in 0..k_b_0 {
                    for byte in 0..234 {
                        let expected = if delta_bits_0[j] == 1 {
                            v_bytes[0][j][byte] ^ u_bytes[byte]
                        } else {
                            v_bytes[0][j][byte]
                        };
                        assert_eq!(
                            q_corrected[0][j][byte], expected,
                            "FAIL: VOLE correlation broken at instance 0, col {j}, byte {byte}"
                        );
                    }
                }
                // spot-check instance 1 after correction (shares same u as instance 0)
                if tau > 1 {
                    let delta_bits_1 = chall_dec(chall_3, 1);
                    let k_b_1 = if 1 < tau_0 { k_0 } else { k_1 };
                    for j in 0..k_b_1 {
                        for byte in 0..234 {
                            let expected = if delta_bits_1[j] == 1 {
                                v_bytes[1][j][byte] ^ u_bytes[byte]
                            } else {
                                v_bytes[1][j][byte]
                            };
                            assert_eq!(
                                q_corrected[1][j][byte], expected,
                                "FAIL: VOLE correlation broken at instance 1 (after correction), col {j}, byte {byte}"
                            );
                        }
                    }
                }
            }

            // Q_e columns + XOR with u_tilde
            let mut q_e_columns: Vec<[u8; 18]> = vec![];
            for i in 0..tau {
                let k_b = if i < tau_0 { k_0 } else { k_1 };
                for j in 0..k_b {
                    let col = &q_corrected[i][j];
                    let col_hash = vole_hash(&chall_1_verify, &col[0..216], &col[216..234]);
                    q_e_columns.push(col_hash.try_into().unwrap());
                }
            }
            let mut q_e_xored = q_e_columns.clone();
            let mut col_idx = 0;
            for i in 0..tau {
                let k_b = if i < tau_0 { k_0 } else { k_1 };
                let delta_bits = chall_dec(chall_3, i);
                for j in 0..k_b {
                    if delta_bits[j] == 1 {
                        for byte in 0..18 {
                            q_e_xored[col_idx][byte] ^= u_tilde[byte];
                        }
                    }
                    col_idx += 1;
                }
            }
            let q_e_flat: Vec<u8> = q_e_xored.iter().flatten().copied().collect();
            let h_v_verify = h_1_for_non_specific_size(q_e_flat);

            // CHECK 4: h_v must match between sign and verify
            assert_eq!(
                h_v_sign, h_v_verify,
                "FAIL: h_v differs — VOLEHash consistency check failed"
            );

            let chall_2_verify: [u8; 56] = h_2_2(chall_1_verify, u_tilde.clone(), h_v_verify, d.clone());

            // CHECK 5: chall_2 must match
            assert_eq!(
                chall_2, chall_2_verify,
                "FAIL: chall_2 differs between sign and verify"
            );

            // ═══════════════════════════════════════════════════════
            // DRILL-DOWN: isolate where b_tilde diverges
            // ═══════════════════════════════════════════════════════

            // We need to expose the internals of prove/verify.
            // Replicate the delta reconstruction here so we can
            // check the per-row VOLE relation on Q vs V before
            // they enter ZKHash.

            // Reconstruct Delta from chall_3 (same as AESVerify does)
            use Bachelor_Assurance::utils::helper_methods_prove_verify::to_field;

            let delta: [u8; lambda] = chall3_to_bits(&chall_3).try_into().unwrap();

            {
                let q_rows_check: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);

                // check row 0 (w=1 expected from pk bits) vs row 1 (w=0)
                let row0_qxv: Vec<u8> = (0..lambda)
                    .map(|b| q_rows_check[0][b] ^ v_arr[0][b])
                    .collect();
                let row1_qxv: Vec<u8> = (0..lambda)
                    .map(|b| q_rows_check[1][b] ^ v_arr[1][b])
                    .collect();

                println!("w[0]={}, q^v row0: {:?}", extended_witness[0], &row0_qxv[..8]);
                println!("w[1]={}, q^v row1: {:?}", extended_witness[1], &row1_qxv[..8]);
                println!("delta first 8:     {:?}", &delta[..8]);

                // Are they the same value?
                println!("row0==row1: {}", row0_qxv == row1_qxv);
                // Does either equal delta?
                println!("row0==delta: {}", row0_qxv == delta.to_vec());
                println!("row1==delta: {}", row1_qxv == delta.to_vec());
                // Does either equal zero?
                println!("row0==zero: {}", row0_qxv.iter().all(|&x| x == 0));
                println!("row1==zero: {}", row1_qxv.iter().all(|&x| x == 0));

                // Also check: what does q look like BEFORE d-correction?
                // i.e. from q_mark (raw VOLEReconstruct output) row 1
                let q_mark_rows: Vec<[u8; lambda]> = vole_to_row_major(&q_mark);
                let row1_raw_qxv: Vec<u8> = (0..lambda)
                    .map(|b| q_mark_rows[1][b] ^ v_arr[1][b])
                    .collect();
                println!("BEFORE d-correction, w[1]={}, q^v row1: {:?}",
                         extended_witness[1], &row1_raw_qxv[..8]);
                println!("row1_raw==zero:  {}", row1_raw_qxv.iter().all(|&x| x == 0));
                println!("row1_raw==delta: {}", row1_raw_qxv == delta.to_vec());
            }

            // CHECK A: per-row VOLE relation should be q[i] = v[i] XOR (u[i] * Delta)
            // NOT w[i] * Delta — that only holds after d-correction inside AESVerify
            {
                let q_rows_check: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);

                let mut vole_relation_ok = true;
                for i in 0..ell_bit_size {
                    let q_row = q_rows_check[i];
                    let v_row = v_arr[i];
                    let u_bit = u_arr[i]; // ← use u_bit not w_bit

                    let mut q_xor_v = [0u8; lambda];
                    for b in 0..lambda {
                        q_xor_v[b] = q_row[b] ^ v_row[b];
                    }
                    let expected: [u8; lambda] = if u_bit == 1 { delta } else { [0u8; lambda] };

                    if q_xor_v != expected {
                        println!(
                            "FAIL VOLE relation at row {i}: u={u_bit}\n  q^v    = {:?}\n  u*Delta= {:?}",
                            q_xor_v, expected
                        );
                        vole_relation_ok = false;
                        if i > 2 { break; }
                    }
                }
                assert!(vole_relation_ok, "FAIL: per-row VOLE relation q=v+u*Delta broken");
                println!("CHECK A passed: per-row VOLE relation holds for all witness rows");
            }

            // CHECK B: the masking rows (lambda rows after ell_bit_size)
            // These hold u* and v* / q*.
            // q*[i] = v*[i] + u*[i] * Delta  (same relation, random u not witness)
            {
                let q_rows_check: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);

                let mut mask_ok = true;
                for i in ell_bit_size..(ell_bit_size + lambda) {
                    let q_row = q_rows_check[i];
                    let v_row = v_arr[i];
                    let u_bit = u_arr[i]; // random mask bit, not witness

                    let mut q_xor_v = [0u8; lambda];
                    for b in 0..lambda {
                        q_xor_v[b] = q_row[b] ^ v_row[b];
                    }
                    let expected: [u8; lambda] = if u_bit == 1 { delta } else { [0u8; lambda] };

                    if q_xor_v != expected {
                        println!(
                            "FAIL masking VOLE relation at row {i}: u={u_bit}\n  q^v    = {:?}\n  w*Delta= {:?}",
                            q_xor_v, expected
                        );
                        mask_ok = false;
                        if i > ell_bit_size + 2 { break; }
                    }
                }
                assert!(mask_ok, "FAIL: per-row VOLE relation broken in masking rows (u*, v*, q*)");
                println!("CHECK B passed: masking row VOLE relation holds");
            }

        // CHECK C: verify elementwise constraint relation b[i] = a0[i] + a1[i] * Delta
        // We need to expose a0, a1, b from the prove/verify internals.
        // Do this by rerunning the constraint functions directly here in the test.

        use Bachelor_Assurance::protocols::faest_key_exp_cstrnts::{faest_aes_exp_cstrnts_wv, faest_aes_exp_cstrnts_qDelta};
        use Bachelor_Assurance::protocols::faest_key_enc_cstrnts::{faest_aes_enc_cstrnts_prover, faest_aes_enc_cstrnts_verifier};
        use Bachelor_Assurance::utils::constants::{l_ke, l_enc, S_ke};

        {
            // reconstruct prove inputs
            let v_prove: Vec<[u8;16]> = (0..ell_bit_size+lambda)
                .map(|row| to_field(&v_arr[row], lambda)[0])
                .collect();

            let (a0_exp, a1_exp, k, v_k) = faest_aes_exp_cstrnts_wv(
                extended_witness[0..l_ke].to_vec(),
                v_prove[0..l_ke].to_vec(),
                false
            );

            // reconstruct verify inputs
            let delta_fe = to_field(&chall3_to_bits(&chall_3), lambda)[0];

            let q_rows_fe: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);
            let mut q_mut_fe = q_rows_fe.clone();
            let chall_3_bits: [u8; 128] = chall3_to_bits(&chall_3);

            for row in 0..ell_bit_size {
                if d[row] == 1 {
                    for col in 0..lambda {
                        q_mut_fe[row][col] ^= chall_3_bits[col];
                    }
                }
            }
            let q_fe: Vec<[u8;16]> = (0..ell_bit_size+lambda)
                .map(|row| to_field(&q_mut_fe[row], lambda)[0])
                .collect();

            let (b_exp, _q_k) = faest_aes_exp_cstrnts_qDelta(
                delta_fe,
                q_fe[0..l_ke].to_vec(),
                true
            );

            // check relation b[i] = a0[i] + a1[i] * Delta for key expansion constraints
            println!("=== Checking elementwise constraint relation (key exp) ===");
            let mut all_ok = true;
            for i in 0..S_ke {
                let a1_delta = gf128_mul(&a1_exp[i], &delta_fe);
                let expected_b = xor_arrays(&a0_exp[i], &a1_delta);
                if expected_b != b_exp[i] {
                    println!("FAIL at key exp constraint {i}:");
                    println!("  a0[i]          = {:?}", &a0_exp[i][..4]);
                    println!("  a1[i]          = {:?}", &a1_exp[i][..4]);
                    println!("  a1[i]*Delta    = {:?}", &a1_delta[..4]);
                    println!("  a0+a1*Delta    = {:?}", &expected_b[..4]);
                    println!("  b[i]           = {:?}", &b_exp[i][..4]);
                    all_ok = false;
                    if i > 2 { break; }
                }
            }
            if all_ok {
                println!("All key exp constraints satisfy b = a0 + a1*Delta");
            }
        }

        // CHECK C2: verify elementwise constraint relation for encryption constraints
        {
            use Bachelor_Assurance::protocols::faest_key_enc_cstrnts::{faest_aes_enc_cstrnts_prover, faest_aes_enc_cstrnts_verifier};
            use Bachelor_Assurance::utils::math::xor_arrays;
            use Bachelor_Assurance::utils::galois_field::gf128_mul;

            let v_prove: Vec<[u8;16]> = (0..ell_bit_size+lambda)
                .map(|row| to_field(&v_arr[row], lambda)[0])
                .collect();

            let chall_3_bits: [u8; 128] = chall3_to_bits(&chall_3);
            let delta_fe = to_field(&chall_3_bits, lambda)[0];

            // rerun key exp to get k, v_k, q_k
            let (_, _, k, v_k) = faest_aes_exp_cstrnts_wv(
                extended_witness[0..l_ke].to_vec(),
                v_prove[0..l_ke].to_vec(),
                false
            );

            let q_rows_fe: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);
            let mut q_mut_fe = q_rows_fe.clone();
            for row in 0..ell_bit_size {
                if d[row] == 1 {
                    for col in 0..lambda {
                        q_mut_fe[row][col] ^= chall_3_bits[col];
                    }
                }
            }
            let q_fe: Vec<[u8;16]> = (0..ell_bit_size+lambda)
                .map(|row| to_field(&q_mut_fe[row], lambda)[0])
                .collect();

            let (_, q_k) = faest_aes_exp_cstrnts_qDelta(
                delta_fe,
                q_fe[0..l_ke].to_vec(),
                true
            );

            // prover enc constraints
            let v_enc: [[u8;16]; l_enc] = v_prove[l_ke..(l_ke+l_enc)].try_into().unwrap();
            let (a0_enc, a1_enc) = faest_aes_enc_cstrnts_prover(
                1,
                pk.0.clone().to_vec(),
                pk.1.clone().to_vec(),
                extended_witness[l_ke..(l_ke+l_enc)].to_vec(),
                v_enc,
                k,
                v_k,
                false
            );

            // verifier enc constraints
            let q_enc: [[u8;16]; l_enc] = q_fe[l_ke..(l_ke+l_enc)].try_into().unwrap();
            let b_enc = faest_aes_enc_cstrnts_verifier(
                128,
                pk.0.clone().to_vec(),
                pk.1.clone().to_vec(),
                q_enc,
                q_k,
                delta_fe,
                true
            );

            // CHECK D: does the VOLE relation hold for s and s_overline?
            // Recompute s, v_s, s_overline, v_s_overline, q_s, q_s_overline directly
            let s_fwd = faest_aes_enc_fwd(
                1, extended_witness[l_ke..(l_ke+l_enc)].to_vec(),
                k.to_vec(), pk.0.clone().to_vec(), false, false, 0u8
            );
            let v_s_fwd = faest_aes_enc_fwd(
                lambda, v_prove[l_ke..(l_ke+l_enc)].to_vec(),
                v_k.to_vec(), pk.0.clone().to_vec(), true, false, [0u8;16]
            );
            let s_bkwd = faest_aes_enc_bkwd(
                1, extended_witness[l_ke..(l_ke+l_enc)].to_vec(),
                k.to_vec(), pk.1.clone().to_vec(), false, false, 0u8
            );
            let v_s_bkwd = faest_aes_enc_bkwd(
                lambda, v_prove[l_ke..(l_ke+l_enc)].to_vec(),
                v_k.to_vec(), pk.1.clone().to_vec(), true, false, [0u8;16]
            );
            let q_s_fwd = faest_aes_enc_fwd(
                lambda, q_fe[l_ke..(l_ke+l_enc)].to_vec(),
                q_k.to_vec(), pk.0.clone().to_vec(), false, true, delta_fe
            );
            let q_s_bkwd = faest_aes_enc_bkwd(
                lambda, q_fe[l_ke..(l_ke+l_enc)].to_vec(),
                q_k.to_vec(), pk.1.clone().to_vec(), false, true, delta_fe
            );

            // check VOLE relation: q_s[i] = v_s[i] + s[i]*Delta
            println!("=== CHECK D: VOLE relation for enc fwd/bkwd ===");
            for i in 0..3 {
                let expected_q_s = xor_arrays(&v_s_fwd[i], &gf128_mul(&s_fwd[i], &delta_fe));
                let expected_q_s_bar = xor_arrays(&v_s_bkwd[i], &gf128_mul(&s_bkwd[i], &delta_fe));
                println!("fwd[{i}]: q_s={:?} expected={:?} ok={}",
                         &q_s_fwd[i][..4], &expected_q_s[..4], q_s_fwd[i] == expected_q_s);
                println!("bkwd[{i}]: q_s_bar={:?} expected={:?} ok={}",
                         &q_s_bkwd[i][..4], &expected_q_s_bar[..4], q_s_bkwd[i] == expected_q_s_bar);
            }

            // check b[i] = a0[i] + a1[i] * Delta
            println!("=== Checking elementwise constraint relation (enc) ===");
            let mut all_ok = true;
            for i in 0..a0_enc.len() {
                let a1_delta = gf128_mul(&a1_enc[i], &delta_fe);
                let expected_b = xor_arrays(&a0_enc[i], &a1_delta);
                if expected_b != b_enc[i] {
                    println!("FAIL at enc constraint {i}:");
                    println!("  a0[i]       = {:?}", &a0_enc[i][..4]);
                    println!("  a1[i]       = {:?}", &a1_enc[i][..4]);
                    println!("  a1*Delta    = {:?}", &a1_delta[..4]);
                    println!("  a0+a1*Delta = {:?}", &expected_b[..4]);
                    println!("  b[i]        = {:?}", &b_enc[i][..4]);
                    all_ok = false;
                    if i > 2 { break; }
                }
            }
            if all_ok {
                println!("All enc constraints satisfy b = a0 + a1*Delta");
            }

            // CHECK E: verify s[i] * s_bar[i] = 1 for each constraint
            println!("=== CHECK E: s * s_bar = 1 ===");
            for i in 0..4 {
                let s_byte = s_fwd[i][0];
                let s_bar_byte = s_bkwd[i][0];
                let product_f28 = Bachelor_Assurance::utils::galois_field::gf28_multiply(s_byte, s_bar_byte);
                println!("F28 check [{i}]: s={} s_bar={} s*s_bar={} (should be 1 if same S-box)",
                         s_byte, s_bar_byte, product_f28);
                // CHECK H: manually trace S-box 0
                // fwd[0]: reads in_out[0..8] XOR x_k[0..8]
                let pt = pk.0.clone().to_vec();
                let k_bits_full = k.to_vec(); // expanded key bits

                // reconstruct s[0] manually
                let mut s0_byte = 0u8;
                let mut k0_byte = 0u8;
                for i in 0..8 {
                    s0_byte |= pt[i] << i;
                    k0_byte |= k_bits_full[i] << i;
                }
                let sbox_input_0 = s0_byte ^ k0_byte;
                println!("manual s[0] input = {} (s[0][0] = {})", sbox_input_0, s_fwd[0][0]);

                // bkwd[0]: reads witness at ird=0, i.e. w[0..8]
                let w_enc = extended_witness[l_ke..].to_vec();
                let mut w_byte0 = 0u8;
                for i in 0..8 {
                    w_byte0 |= w_enc[i] << i;
                }
                println!("witness byte 0 = {} (s_bar[0][0] = {})", w_byte0, s_bkwd[0][0]);

                // what is the AES sbox output for sbox_input_0?
                // we can check: gf28_inverse(sbox_input_0) should equal w_byte0 after affine inverse
                // or: sbox_input_0 * w_byte0 should = 1 in F28 (since bkwd inverts affine, leaving the inverse)
                let product = Bachelor_Assurance::utils::galois_field::gf28_multiply(sbox_input_0, w_byte0);
                println!("sbox_input_0 * w_byte0 in F28 = {} (should be 1)", product);

                // Also check: what is at witness position 0 vs position 8?
                println!("w_enc[0..8] = {:?}", &w_enc[0..8]);
                println!("w_enc[8..16] = {:?}", &w_enc[8..16]);
            }

            // CHECK F: print raw witness values that fwd and bkwd read for S-box index 1
            // S-box 1 corresponds to j=0, c=0, r=1 (since index = 16*j + 4*c + r)
            // fwd reads from: first round AddRoundKey uses in_out[8*1..8*2]
            // bkwd for j=0: reads from witness at ird = 128*0 + 32*0 + 8*1 = 8 (with fix)
            //               then applies affine inverse

            println!("=== CHECK F: raw inputs for S-box index 1 ===");
            // S-box 1 is j=0, c=0, r=1
            // fwd: for j=0 (first round), reads from in_out at 8*i+j where i=1
            // That's in_out[8..16] XOR x_k[8..16]
            let pt = pk.0.clone().to_vec(); // plaintext bits
            let k_bits = k.to_vec();        // expanded key bits

            println!("plaintext bits [8..16]: {:?}", &pt[8..16]);
            println!("k bits [8..16]: {:?}", &k_bits[8..16]);

            // bkwd for j=0: ird = 0 + 0 + 8*1 = 8, reads x[8..16] from witness
            let w_enc = extended_witness[l_ke..(l_ke+l_enc)].to_vec();
            println!("witness bits [8..16]: {:?}", &w_enc[8..16]);

            // for j=1 (second round), fwd reads x at i_x = 128*0 + 32*0 = 0, then i_x+8*r for r=1 gives 8
            // bkwd reads x at ird = 128*1 + 32*0 + 8*1 = 136
            println!("witness bits [136..144] (bkwd j=1,c=0,r=1): {:?}", &w_enc[136..144]);
            // fwd for j=1,c=0: reads x[0..32], specifically r=1 reads x[8..16]
            println!("witness bits [8..16] (fwd j=1,c=0,r=1): {:?}", &w_enc[8..16]);

            // Also check the 1_{F28} used in a1 computation vs b computation
            // In prover: one_f28 = [0x01, 0, 0, ...] (element of F_{2^128} representing 1 in F_{2^8})
            // In verifier: delta^2 should equal delta*delta
            let delta_sq = gf128_mul(&delta_fe, &delta_fe);
            println!("Delta^2 = {:?}", &delta_sq[..4]);
            // If s*s_bar=1 in F_{2^8}, then s*s_bar*Delta^2 = Delta^2
            // but 1_{F28} in F_{2^128} representation might differ from [1,0,0,...]
        }
            // run AESVerify — returns q_tilde - a_tilde * delta, which should equal b_tilde
            let q_rows_verify: Vec<[u8; lambda]> = vole_to_row_major(&q_corrected);
            let q_arr: [[u8; lambda]; ell_bit_size + lambda] = q_rows_verify.try_into().unwrap();

            let b_tilde_verify = faest_aes_verify(
                d.clone().try_into().unwrap(),
                q_arr,
                expand_bits_56(chall_2_verify),
                chall3_to_bits(&chall_3),
                a_tilde,
                (pk.0.try_into().unwrap(), pk.1.try_into().unwrap()),
            );


            // CHECK 6: b_tilde from sign == b_tilde reconstructed by verify
            assert_eq!(
                b_tilde_sign, b_tilde_verify,
                "FAIL: b_tilde mismatch — QuickSilver proof check failed\n  sign:   {:?}\n  verify: {:?}",
                b_tilde_sign, b_tilde_verify
            );

            // CHECK 7: final chall_3 round-trip
            let chall_3_verify = h_2_3(chall_2_verify, a_tilde, b_tilde_verify);
            assert_eq!(
                chall_3, chall_3_verify,
                "FAIL: chall_3 round-trip failed — signature would be rejected"
            );

            println!("All intermediate checks passed.");
            println!("chall_2      : {:?}", chall_2);
            println!("a_tilde      : {:?}", a_tilde);
            println!("b_tilde sign : {:?}", b_tilde_sign);
            println!("b_tilde vrfy : {:?}", b_tilde_verify);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
