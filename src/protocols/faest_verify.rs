use crate::utils::constants::{chall1_bytes, chall2_bytes, ell_bytes, h_v_size, x0_bytes};
use crate::utils::constants::iv_bytes;
use crate::utils::constants::{chall3_bytes, ell_hat_bytes, lambda_bytes, lambda_bytes_times_two, x1_bytes};
use crate::utils::constants::{tau_1, tau_minus_one};
use crate::protocols::fs_vole::{chall_dec_k0, chall_dec_k1};
use crate::utils::types::{sized_array_for_q_v, Pk};
use crate::utils::types::sized_array_for_cop;
use crate::protocols::faest_prove_and_verify::faest_aes_verify;
use crate::protocols::fs_vole::{FAEST_VOLE_reconstruct};
use crate::utils::constants::{tau, tau_0, k_0, k_1, LAMBDA, ell};
use crate::utils::hash_functions::{bits_to_bytes_for_d, h_1_for_2304, h_1_for_sign, h_2_1, h_2_2, h_2_3};
use crate::utils::helper_methods_for_sign::{chall3_to_bits, vole_hash, vole_to_row_major};
use crate::utils::preliminary_helper_methods::flatten;

pub fn faest_verify(
    msg : &[u8],
    pk : &Pk,
    sig : &([[u8;ell_hat_bytes];tau_minus_one], [u8;x1_bytes], [u8; ell], [u8; lambda_bytes], [(sized_array_for_cop, [u8; lambda_bytes_times_two]); tau], [u8; chall3_bytes], [u8; iv_bytes]))
    -> bool
{
    let c_bytes : &[[u8;ell_hat_bytes];tau_minus_one] = &sig.0;
    let u_tilde: &[u8;x1_bytes] = &sig.1;
    let d : &[u8; ell]= &sig.2;
    let a_tilde : &[u8; lambda_bytes]= &sig.3;
    let pdcoms: &[(sized_array_for_cop, [u8; lambda_bytes_times_two]); tau] = &sig.4;
    let chall_3 : &[u8; chall3_bytes] = &sig.5;
    let iv : &[u8; iv_bytes]= &sig.6;

    let my : [u8;lambda_bytes_times_two]= h_1_for_sign(*pk, msg);
    let _rec_start = std::time::Instant::now();
    let (h_com, q_mark) : ([u8; lambda_bytes_times_two], [sized_array_for_q_v; tau])= FAEST_VOLE_reconstruct(*chall_3, pdcoms, *iv);
    // println!("reconstruct took: {:?}", rec_start.elapsed());

    let chall_1 : [u8;chall1_bytes] = h_2_1(my, h_com, c_bytes, *iv);

    // fixing q:
    let mut q_corrected : [sized_array_for_q_v; tau]  = q_mark;
    let _challenge_start = std::time::Instant::now();
    for i in 1..tau {
        if i < tau_0 {
            let delta_bits : [u8;k_0] = chall_dec_k0(*chall_3, i);
            for j in 0..k_0 {
                if delta_bits[j] == 1 {
                    // XOR column j of Q'i with ci
                    for byte in 0..ell_hat_bytes {
                        let mut row : [u8;ell_hat_bytes] = *q_corrected[i].get(j);
                        row[byte] ^= c_bytes[i-1][byte];
                        q_corrected[i] = q_corrected[i].set(j, row);
                    }
                }
            }
        } else {
            let delta_bits : [u8;k_1] = chall_dec_k1(*chall_3, i);
            for j in 0..k_1 {
                if delta_bits[j] == 1 {
                    // XOR column j of Q'i with ci
                    for byte in 0..ell_hat_bytes {
                        let mut row : [u8;ell_hat_bytes] = *q_corrected[i].get(j);
                        row[byte] ^= c_bytes[i-1][byte];
                        q_corrected[i] = q_corrected[i].set(j, row);
                    }
                }
            }
        }
    }
    // println!("challenge took: {:?}", challenge_start.elapsed());

    let mut q_e_columns: [[u8;x1_bytes];tau_0*k_0+tau_1*k_1] = [[0;x1_bytes];tau_0*k_0+tau_1*k_1];
    let mut index : usize = 0;
    for i in 0..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            let col : &[u8;ell_hat_bytes] = q_corrected[i].get(j);
            let col_0 : &[u8;x0_bytes] = &col[0..x0_bytes].try_into().unwrap();
            let col_1 : &[u8;x1_bytes] = &col[x0_bytes..ell_hat_bytes].try_into().unwrap();
            let col_hash : [u8;x1_bytes] = vole_hash(&chall_1, col_0, col_1);
            q_e_columns[index] = col_hash.try_into().unwrap();
            index += 1;
        }
    }
    let mut q_e_xored : [[u8;x1_bytes];tau_0*k_0+tau_1*k_1] = q_e_columns.clone();
    let mut col_idx : usize = 0;
    for i in 0..tau {
        if i < tau_0 {
            let delta_bits : [u8;k_0] = chall_dec_k0(*chall_3, i);
            for j in 0..k_0 {
                if delta_bits[j] == 1 {
                    for byte in 0..x1_bytes {
                        q_e_xored[col_idx][byte] ^= u_tilde[byte];
                    }
                }
                col_idx += 1;
            }
        } else {
            let delta_bits : [u8;k_1] = chall_dec_k1(*chall_3, i);
            for j in 0..k_1 {
                if delta_bits[j] == 1 {
                    for byte in 0..x1_bytes {
                        q_e_xored[col_idx][byte] ^= u_tilde[byte];
                    }
                }
                col_idx += 1;
            }
        }
    }
    let q_e_flat: [u8; h_v_size] = flatten::<{tau_0*k_0+tau_1*k_1}, x1_bytes, {h_v_size}>(q_e_xored);

    // h_v value
    let h_v : [u8;lambda_bytes_times_two] = h_1_for_2304(&q_e_flat);

    let d_bytes : [u8;ell_bytes] = bits_to_bytes_for_d(d);

    // chall 2
    let chall_2 : [u8;chall2_bytes] = h_2_2(chall_1, u_tilde.clone(), h_v, d_bytes);

    // et lille fix til hvordan q den hænger sammen, samme check som til prove
    let q_rows : [[u8; LAMBDA]; ell+ LAMBDA] = vole_to_row_major(q_corrected);
    let q_arr: [[u8; LAMBDA]; ell + LAMBDA] = q_rows.try_into().unwrap();



    let _verify_start = std::time::Instant::now();
    let b_tilde : [u8;lambda_bytes] = faest_aes_verify(
        d.clone().try_into().unwrap(),
        q_arr,
        chall_2,
        chall3_to_bits(&chall_3),
        *a_tilde,
        *pk
    );
    // println!("verify took: {:?}", verify_start.elapsed());

    let chall_3_mark : [u8;chall3_bytes] = h_2_3(chall_2, *a_tilde, b_tilde);
    

    *chall_3 == chall_3_mark

}