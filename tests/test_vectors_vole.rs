#[cfg(test)]
mod tests {
    use bachelor_assurance::protocols::fs_vole::{chall_dec_k0, chall_dec_k1, FAEST_VOLE_commit, FAEST_VOLE_reconstruct};
    use bachelor_assurance::utils::constants::{k_0, k_1, tau, tau_0};
    use bachelor_assurance::utils::math::xor_arrays;
    use bachelor_assurance::utils::preliminary_helper_methods::{num_rec_k0, num_rec_k1};
    use bachelor_assurance::utils::types::{sized_array_for_cop, sized_array_for_q_v};
    use bachelor_assurance::utils::vector_commit::{vec_open_k0, vec_open_k1};

    const ROOT_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const IV: [u8; 16] = [0x00; 16];
    const CHALL: [u8; 16] = [0xFF; 16]; // all ones challenge

    #[test]
    fn test_vole_commit_reconstruct_roundtrip() {
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024); // 64MB
        let handler = builder.spawn(|| {
        // commit
        let (hcom, all_decoms, big_c, u_0, big_v) = FAEST_VOLE_commit(ROOT_KEY, IV);

        // open all vector commitments using challenge
        let mut pdecoms: [(sized_array_for_cop, [u8; 32]); tau] =
            std::array::from_fn(|_| (sized_array_for_cop::sized_array_1([[0u8;16];k_0]), [0u8;32]));

        for i in 0..tau {
            let b = if i < tau_0 {
                let b = chall_dec_k0(CHALL, i);
                let pdecom = vec_open_k0(&all_decoms[i], &b, k_0 as i128);
                pdecoms[i] = pdecom;
            } else {
                let b = chall_dec_k1(CHALL, i);
                let pdecom = vec_open_k1(&all_decoms[i], &b, k_1 as i128);
                pdecoms[i] = pdecom;
            };
        }

        // reconstruct
        let (hcom_rec, big_q) = FAEST_VOLE_reconstruct(CHALL, &pdecoms, IV);

        // check hashes match
        assert_eq!(hcom, hcom_rec, "hcom mismatch");
        }).unwrap();
        handler.join().unwrap();
    }

    #[test]
    fn test_vole_correlation_property() {
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024); // 64MB
        let handler = builder.spawn(|| {
        // tests the core VOLE property:
        // if delta_j == 1: q[j] XOR u == v[j]
        // if delta_j == 0: q[j] == v[j]
        let (hcom, all_decoms, big_c, u_0, big_v) = FAEST_VOLE_commit(ROOT_KEY, IV);

        let mut pdecoms: [(sized_array_for_cop, [u8; 32]); tau] =
            std::array::from_fn(|_| (sized_array_for_cop::sized_array_1([[0u8;16];k_0]), [0u8;32]));

        for i in 0..tau {
            if i < tau_0 {
                let b = chall_dec_k0(CHALL, i);
                pdecoms[i] = vec_open_k0(&all_decoms[i], &b, k_0 as i128);
            } else {
                let b = chall_dec_k1(CHALL, i);
                pdecoms[i] = vec_open_k1(&all_decoms[i], &b, k_1 as i128);
            }
        }

        let (_hcom_rec, big_q) = FAEST_VOLE_reconstruct(CHALL, &pdecoms, IV);

        // check VOLE correlation for each instance
        for i in 0..tau {
            let b = if i < tau_0 {
                chall_dec_k0(CHALL, i).to_vec()
            } else {
                chall_dec_k1(CHALL, i).to_vec()
            };

            let depth = if i < tau_0 { k_0 } else { k_1 };
            let delta = if i < tau_0 {
                num_rec_k0(&chall_dec_k0(CHALL, i))
            } else {
                num_rec_k1(&chall_dec_k1(CHALL, i))
            };

            for j in 0..depth {
                let q_j = match &big_q[i] {
                    sized_array_for_q_v::sized_array_1(inner) => inner[j],
                    sized_array_for_q_v::sized_array_2(inner) => inner[j],
                };
                let v_j = match &big_v[i] {
                    sized_array_for_q_v::sized_array_1(inner) => inner[j],
                    sized_array_for_q_v::sized_array_2(inner) => inner[j],
                };

                if b[j] == 1 {
                    if i > 0 {
                        // need to apply correction value c[i-1]
                        let q_xor_c = xor_arrays(&q_j, &big_c[i-1]);
                        let q_xor_c_xor_u = xor_arrays(&q_xor_c, &u_0);
                        assert_eq!(q_xor_c_xor_u, v_j,
                                   "VOLE correlation failed at i={}, j={}: q XOR c XOR u != v", i, j);
                    } else {
                        let q_xor_u = xor_arrays(&q_j, &u_0);
                        assert_eq!(q_xor_u, v_j,
                                   "VOLE correlation failed at i={}, j={}: q XOR u != v", i, j);
                    }
                } else {
                    assert_eq!(q_j, v_j,
                               "VOLE correlation failed at i={}, j={}: q != v", i, j);
                }
            }
        }}).unwrap();
        handler.join().unwrap();
    }
}