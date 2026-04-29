use crate::utils::types::sizeds_array;
use crate::protocols::faest_prove_and_verify::faest_aes_verify;
use crate::protocols::fs_vole::{chall_dec, FAEST_VOLE_reconstruct};
use crate::utils::constants::{tau, tau_0, k_0, k_1, lambda, ell_bit_size};
use crate::utils::hash_functions::{h_1_for_non_specific_size, h_1_for_sign, h_2_1, h_2_2, h_2_3};
use crate::utils::helper_methods_for_sign::{chall3_to_bits, expand_bits_56, vole_hash, vole_to_row_major};
use crate::utils::helper_methods_prove_verify::to_field;

pub fn faest_verify(msg : &[u8], pk : ([u8;lambda], [u8;lambda]), sig : (Vec<[u8; 234]>, Vec<u8>, Vec<u8>, [u8; 16], Vec<(sizeds_array, [u8; 32])>, [u8; 16], [u8; 16])) -> bool{
    let c_bytes = sig.0;
    let u_tilde = sig.1;
    let d = sig.2;
    let a_tilde = sig.3;
    let pdcoms = sig.4;
    let chall_3 = sig.5;
    let iv = sig.6;

    let my : [u8;32]= h_1_for_sign(pk.clone(), msg);
    let (h_com, q_mark) = FAEST_VOLE_reconstruct(chall_3, pdcoms, iv);

    let chall_1 = h_2_1(my, h_com, c_bytes.clone(), iv);

    // fixing q:
    let mut q_corrected = q_mark.clone();
    for i in 1..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        // get delta bits for this instance from chall_3
        let delta_bits = chall_dec(chall_3, i);
        for j in 0..k_b {
            if delta_bits[j] == 1 {
                // XOR column j of Q'i with ci
                for byte in 0..234 {
                    q_corrected[i][j][byte] ^= c_bytes[i][byte];
                }
            }
        }
    }


    let mut q_e_columns: Vec<[u8;18]> = vec![];
    for i in 0..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            let col = &q_corrected[i][j];
            let col_hash = vole_hash(&chall_1, &col[0..216], &col[216..234]);
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

    // h_v value
    let h_v = h_1_for_non_specific_size(q_e_flat);

    // chall 2
    let chall_2 = h_2_2(chall_1, u_tilde.clone(), h_v, d.clone());

    // et lille fix til hvordan q den hænger sammen, samme check som til prove
    let q_rows = vole_to_row_major(&q_corrected);
    let q_arr: [[u8; lambda]; ell_bit_size + lambda] = q_rows.try_into().unwrap();



    let b_tilde = faest_aes_verify(
        d.try_into().unwrap(),
        q_arr,
        expand_bits_56(chall_2),
        chall3_to_bits(&chall_3),
        a_tilde,
        (pk.0.try_into().unwrap(), pk.1.try_into().unwrap())
    );

    let chall_3_mark = h_2_3(chall_2, a_tilde, b_tilde);
    

    chall_3 == chall_3_mark

}