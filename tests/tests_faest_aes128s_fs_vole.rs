#[cfg(all(test, feature = "lambda_128s"))]
mod tests {
    use bachelor_assurance::protocols::fs_vole::{chall_dec_k0, chall_dec_k1, FAEST_VOLE_commit, FAEST_VOLE_reconstruct};
    use bachelor_assurance::utils::constants::{chall3_bytes, ell_hat, ell_hat_bytes, iv_bytes, k_0, k_1, lambda_bytes, tau, tau_0, tau_minus_one};
    use bachelor_assurance::utils::math::xor_arrays;
    use bachelor_assurance::utils::types::{sized_array_for_cop, sized_array_for_q_v};
    use bachelor_assurance::utils::vector_commit::{vec_open_k0, vec_open_k1};

    // if challenge is 0, then Q should equal V, this explicitely follows proposition 5
    #[test]
    fn test_fs_vole_chall_0(){
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
        let handler = builder.spawn(|| {
            let r: [u8; lambda_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let iv: [u8; iv_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let chall : [u8; chall3_bytes] = [0;chall3_bytes]; // std::array::from_fn(|_| rand::random::<u8>());

            let (hash_com, all_decoms, big_c, u_0, big_v) = FAEST_VOLE_commit(r, iv);

            let real_u = get_u(big_c, u_0);

            let mut pdecoms : [(sized_array_for_cop, [u8; 2*lambda_bytes]);tau] = [(sized_array_for_cop::sized_array_1([[0u8;lambda_bytes];k_0]),[0u8;2*lambda_bytes]);tau];
            for i in 0..tau {
                let pdecom = if i < tau_0 {
                    let s_i : [u8;k_0] = chall_dec_k0(chall, i);
                    vec_open_k0(&all_decoms[i], &s_i)
                } else {
                    let s_i : [u8;k_1] = chall_dec_k1(chall, i);
                    vec_open_k1(&all_decoms[i], &s_i)
                };

                pdecoms[i] = pdecom;
            }

            let (hash_rec, big_q) = FAEST_VOLE_reconstruct(chall, &pdecoms, iv);

            assert_eq!(hash_com, hash_rec);

            for i in 0..tau{
                if i < tau_0 {
                    let Q = match big_q[i] {
                        sized_array_for_q_v::sized_array_1(x) => x,
                        _ => unreachable!(),
                    };
                    let V = match big_v[i] {
                        sized_array_for_q_v::sized_array_1(x) => x,
                        _ => unreachable!(),
                    };
                    assert_eq!(Q, V);
                }
                else {
                    let Q = match big_q[i] {
                        sized_array_for_q_v::sized_array_2(x) => x,
                        _ => unreachable!(),
                    };
                    let V = match big_v[i] {
                        sized_array_for_q_v::sized_array_2(x) => x,
                        _ => unreachable!(),
                    };
                    assert_eq!(Q, V);
                }
            }

        }).unwrap();
        handler.join().unwrap();
    }
    #[test]
    fn test_fs_vole_chall_not_0(){
        let builder = std::thread::Builder::new().stack_size(64 * 1024 * 1024);
        let handler = builder.spawn(|| {
            let r: [u8; lambda_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let iv: [u8; iv_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let chall : [u8; chall3_bytes] = std::array::from_fn(|_| rand::random::<u8>());

            let (hash_com, all_decoms, big_c, u_0, big_v) = FAEST_VOLE_commit(r, iv);

            let real_u = get_u(big_c, u_0);

            let mut pdecoms : [(sized_array_for_cop, [u8; 2*lambda_bytes]);tau] = [(sized_array_for_cop::sized_array_1([[0u8;lambda_bytes];k_0]),[0u8;2*lambda_bytes]);tau];
            for i in 0..tau {
                let pdecom = if i < tau_0 {
                    let s_i : [u8;k_0] = chall_dec_k0(chall, i);
                    vec_open_k0(&all_decoms[i], &s_i)
                } else {
                    let s_i : [u8;k_1] = chall_dec_k1(chall, i);
                    vec_open_k1(&all_decoms[i], &s_i)
                };

                pdecoms[i] = pdecom;
            }

            let (hash_rec, big_q) = FAEST_VOLE_reconstruct(chall, &pdecoms, iv);

            assert_eq!(hash_com, hash_rec);

            for i in 0..tau{
                if i < tau_0 {
                    // this delta should be equal to the one gotten from bitdec, in proposition 5
                    // since this is the value before we use numrec on it, and bitdec is reverse of numrec
                    let delta = chall_dec_k0(chall, i);

                    let Q = match big_q[i] {
                        sized_array_for_q_v::sized_array_1(x) => x,
                        _ => unreachable!(),
                    };
                    let V = match big_v[i] {
                        sized_array_for_q_v::sized_array_1(x) => x,
                        _ => unreachable!(),
                    };
                    for j in 0..k_0{
                        if delta[j] == 1 {
                            let this_q = Q[j];
                            let this_v = V[j];
                            let this_u = real_u[i];
                            let q_prover = xor_arrays(&this_v, &this_u);
                            assert_eq!(q_prover, this_q);

                        } else {
                            // for delta = 0, it should hold that q = v xor delta * u => q = v
                            assert_eq!(Q[j], V[j]);
                        }
                    }
                }
                else {
                    let delta = chall_dec_k1(chall, i);

                    let Q = match big_q[i] {
                        sized_array_for_q_v::sized_array_2(x) => x,
                        _ => unreachable!(),
                    };
                    let V = match big_v[i] {
                        sized_array_for_q_v::sized_array_2(x) => x,
                        _ => unreachable!(),
                    };
                    for j in 0..k_1{
                        if delta[j] == 1 {
                            let this_q = Q[j];
                            let this_v = V[j];
                            let this_u = real_u[i];
                            let q_prover = xor_arrays(&this_v, &this_u);
                            assert_eq!(q_prover, this_q);
                        } else {
                            // for delta = 0, it should hold that q = v xor delta * u => q = v
                            assert_eq!(Q[j], V[j]);
                        }
                    }
                }
            }

        }).unwrap();
        handler.join().unwrap();
    }


    fn chall_3_to_bits(chall_3 : [u8;chall3_bytes]) -> [u8;chall3_bytes*8] {
        let mut chall_3_bits = [0u8;chall3_bytes*8];
        for j in 0..chall3_bytes{
            for i in 0..8{
                let bit = (chall_3[j] >> i) & 1;
                chall_3_bits[j*8 + i] = bit;
            }
        }
        chall_3_bits
    }
    fn get_u(big_c : [[u8;ell_hat_bytes];tau_minus_one], u_0 : [u8;ell_hat_bytes]) -> [[u8;ell_hat_bytes];tau] {
        let mut res = [[0;ell_hat_bytes];tau];
        res[0] = u_0;
        for i in 0..tau_minus_one {
            res[i+1] = xor_arrays(&big_c[i], &u_0);
        }
        res
    }
    // takes the outbut of challdec
    fn bit_dec_k0(chall : u64) -> [u8;k_0] {
        let mut bit_dec = [0u8; k_0];
        for i in 0..k_0 {
            bit_dec[i] = ((chall >> i) & 1) as u8;
        }
        bit_dec
    }
    fn bit_dec_k1(chall : u64) -> [u8;k_1] {
        let mut bit_dec = [0u8; k_1];
        for i in 0..k_1 {
            bit_dec[i] = ((chall >> i) & 1) as u8;
        }
        bit_dec
    }
}