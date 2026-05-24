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
    // outpacking the signature
    let c_bytes : &[[u8;ell_hat_bytes];tau_minus_one] = &sig.0;
    let u_tilde: &[u8;x1_bytes] = &sig.1;
    let d : &[u8; ell]= &sig.2;
    let a_tilde : &[u8; lambda_bytes]= &sig.3;
    let pdcoms: &[(sized_array_for_cop, [u8; lambda_bytes_times_two]); tau] = &sig.4;
    let chall_3 : &[u8; chall3_bytes] = &sig.5;
    let iv : &[u8; iv_bytes]= &sig.6;
    // calculating my based on public key and message just as in sign
    let my : [u8;lambda_bytes_times_two]= h_1_for_sign(*pk, msg);
    // calculating the vole correlated q, based on delta, pdecoms and iv, also returns h_com which should correspond with the value from sign
    let (h_com, q_mark) : ([u8; lambda_bytes_times_two], [sized_array_for_q_v; tau])= FAEST_VOLE_reconstruct(*chall_3, pdcoms, *iv);
    // calculate chall_1 based on the priveous tape as done in sign
    let chall_1 : [u8;chall1_bytes] = h_2_1(my, h_com, c_bytes, *iv);
    // fixing q, by using the corrected C, so now q is only correlated with u_0
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

    // --- VOLE consistency check ---
    // The verifier recomputes h_V from its corrected VOLE keys Q to verify that the
    // prover's VOLE values were correctly formed. This corresponds to the consistency
    // check described in Section 2.2 of the spec ("VOLE Consistency Check").
    //
    // The key insight is that by the VOLE relation and the linearity of VOLEHash:
    //   VOLEHash(chall1, Q_col) = VOLEHash(chall1, V_col) + delta_j * VOLEHash(chall1, u)
    //                           = v_tilde[col] + delta_j * u_tilde
    // so by XORing u_tilde into the columns where delta_j = 1, the verifier recovers
    // exactly v_tilde[col] from the signing algorithm, without needing to know V directly.

    // Part 1: compute VOLEHash of each corrected VOLE key column.
    // this mirrors what the prover did in signing: for each column j of VOLE instance i,
    // apply VOLEHash(chall1, Q_col) to compress the ell_hat-bit column into lambda+B bits.
    // (Figure 8.3, line 15: Q_tilde := VOLEHash(chall1, Q), column-wise)
    let mut q_e_columns: [[u8; x1_bytes]; tau_0 * k_0 + tau_1 * k_1] =
        [[0; x1_bytes]; tau_0 * k_0 + tau_1 * k_1];
    let mut index: usize = 0;
    for i in 0..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            // extract column j of VOLE instance i from the corrected key matrix
            let col: &[u8; ell_hat_bytes] = q_corrected[i].get(j);
            // split the column into x0 (used for the polynomial hash) and
            // x1 (used as the masking value), same split as in signing
            let col_0: &[u8; x0_bytes] = &col[0..x0_bytes].try_into().unwrap();
            let col_1: &[u8; x1_bytes] = &col[x0_bytes..ell_hat_bytes].try_into().unwrap();
            // apply VOLEHash to compress this column into lambda+B bits.
            // by the VOLE relation, this equals v_tilde[col] + delta_j * u_tilde
            let col_hash: [u8; x1_bytes] = vole_hash(&chall_1, col_0, col_1);
            q_e_columns[index] = col_hash.try_into().unwrap();
            index += 1;
        }
    }

    // Part 2: correct q_e by XORing u_tilde into columns where delta_j = 1.
    // by the VOLE relation:
    //   q_e_columns[col] = v_tilde[col] + delta_j * u_tilde
    // so XORing u_tilde into the columns where delta_j = 1 gives:
    //   q_e_xored[col] = q_e_columns[col] XOR delta_j * u_tilde
    //                  = v_tilde[col] + delta_j * u_tilde  XOR  delta_j * u_tilde
    //                  = v_tilde[col]
    // after this correction, q_e_xored matches the prover's v_tilde column by column.
    // (Figure 8.3, line 16: h_V := H1(Q_tilde XOR [delta_0*u_tilde ... delta_{tau-1}*u_tilde]))
    let mut q_e_xored: [[u8; x1_bytes]; tau_0 * k_0 + tau_1 * k_1] = q_e_columns.clone();
    let mut col_idx: usize = 0;
    for i in 0..tau {
        if i < tau_0 {
            // extract the k_0-bit challenge Delta_i for this instance
            let delta_bits: [u8; k_0] = chall_dec_k0(*chall_3, i);
            for j in 0..k_0 {
                if delta_bits[j] == 1 {
                    // delta_j = 1: XOR u_tilde into this column to cancel the Delta contribution,
                    // recovering v_tilde[col] = q_e_columns[col] XOR u_tilde
                    for byte in 0..x1_bytes {
                        q_e_xored[col_idx][byte] ^= u_tilde[byte];
                    }
                }
                // delta_j = 0: this column already equals v_tilde[col], no correction needed
                col_idx += 1;
            }
        } else {
            // same logic as above but for k_1-bit challenges (instances i >= tau_0)
            let delta_bits: [u8; k_1] = chall_dec_k1(*chall_3, i);
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

    // flatten q_e_xored (which now equals the prover's v_tilde) into a single byte array,
    // ready to be hashed into h_V using H1 and compared against the value in the signature
    let q_e_flat: [u8; h_v_size] =
        flatten::<{ tau_0 * k_0 + tau_1 * k_1 }, x1_bytes, { h_v_size }>(q_e_xored);
    // h_v value as in verify
    let h_v : [u8;lambda_bytes_times_two] = h_1_for_2304(&q_e_flat);
    // bytes of d again as in very
    let d_bytes : [u8;ell_bytes] = bits_to_bytes_for_d(d);
    // chall 2, calculated exactly as in verify
    let chall_2 : [u8;chall2_bytes] = h_2_2(chall_1, u_tilde.clone(), h_v, d_bytes);
    // the same operations done to q as in v
    let q_rows : [[u8; LAMBDA]; ell+ LAMBDA] = vole_to_row_major(q_corrected);
    let q_arr: [[u8; LAMBDA]; ell + LAMBDA] = q_rows.try_into().unwrap();
    // calculating b_tilde using zk proof verify
    let b_tilde : [u8;lambda_bytes] = faest_aes_verify(
        d.clone().try_into().unwrap(),
        q_arr,
        chall_2,
        chall3_to_bits(&chall_3),
        *a_tilde,
        *pk
    );
    // calculating chall_3 exactly as in sign
    let chall_3_mark : [u8;chall3_bytes] = h_2_3(chall_2, *a_tilde, b_tilde);
    // by then comparing this chall_3 to the one from sign
    *chall_3 == chall_3_mark

}