use crate::utils::constants::{tau_1, tau_minus_one};
use crate::protocols::fs_vole::{chall_dec_k0, chall_dec_k1};
use crate::utils::types::sized_array_for_q_v;
use crate::utils::types::sized_array_for_cop;
use crate::protocols::faest_prove_and_verify::faest_aes_verify;
use crate::protocols::fs_vole::{FAEST_VOLE_reconstruct};
use crate::utils::constants::{tau, tau_0, k_0, k_1, lambda, ell_bit_size};
use crate::utils::hash_functions::{bits_to_bytes_for_d, h_1_for_2304, h_1_for_sign, h_2_1, h_2_2, h_2_3};
use crate::utils::helper_methods_for_sign::{chall3_to_bits, vole_hash, vole_to_row_major};
use crate::utils::preliminary_helper_methods::flatten;
use subtle::ConstantTimeEq;

#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::requires(msg.len() < usize::MAX - 16 * 2 - 1)]
pub fn faest_verify(
    msg : &[u8],
    pk : &([u8;lambda], [u8;lambda]),
    sig : &([[u8;234];tau_minus_one], [u8;18],[u8;ell_bit_size], [u8; 16], [(sized_array_for_cop, [u8; 32]); 11], [u8; 16], [u8; 16]))
    -> bool
{
    let c_bytes : &[[u8;234];tau_minus_one] = &sig.0;
    let u_tilde: &[u8;18] = &sig.1;
    let d : &[u8;ell_bit_size]= &sig.2;
    let a_tilde : &[u8; 16]= &sig.3;
    let pdcoms: &[(sized_array_for_cop, [u8; 32]); 11] = &sig.4;
    let chall_3 : &[u8; 16] = &sig.5;
    let iv : &[u8; 16]= &sig.6;

    hax_lib::assert!(msg.len() < usize::MAX - 16 * 2 - 1);
    let my : [u8;32]= h_1_for_sign(pk.clone(), msg);

    #[cfg(not(hax))]
    let _rec_start = std::time::Instant::now();

    let (h_com, q_mark) : ([u8; 32], [sized_array_for_q_v; 11])= FAEST_VOLE_reconstruct(*chall_3, pdcoms, *iv);
    // println!("reconstruct took: {:?}", rec_start.elapsed());
    hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                k >= q_mark.len()
                || (k < tau_0 && q_mark[k].len() == k_0)
                || (k >= tau_0 && q_mark[k].len() == k_1)));
    let chall_1 : [u8;88] = h_2_1(my, h_com, c_bytes, *iv);

    // fixing q:
    let mut q_corrected : [sized_array_for_q_v; 11]  = q_mark;

    #[cfg(not(hax))]
    let _challenge_start = std::time::Instant::now();
    hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                k >= q_corrected.len()
                || (k < tau_0 && q_corrected[k].len() == k_0)
                || (k >= tau_0 && q_corrected[k].len() == k_1)));

    for i in 1..tau {
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::Prop::from(i <= tau)
            .and(hax_lib::Prop::from(i >= 1))
            .and(hax_lib::forall(|k: usize|
                k >= q_corrected.len()
                || (k < tau_0 && q_corrected[k].len() == k_0)
                || (k >= tau_0 && q_corrected[k].len() == k_1)))
        });
        if i < tau_0 {
            hax_lib::assert!(q_corrected[i].len() == k_0);
            let delta_bits : [u8;12] = chall_dec_k0(*chall_3, i);
            for j in 0..k_0 {
                hax_lib::loop_invariant!(|j: usize| {
                    hax_lib::Prop::from(j <= k_0)
                    .and(hax_lib::Prop::from(q_corrected[i].len() == k_0))
                    .and(hax_lib::forall(|k: usize|
                            k >= q_corrected.len()
                            || (k < tau_0 && q_corrected[k].len() == k_0)
                            || (k >= tau_0 && q_corrected[k].len() == k_1)))
                });
                hax_lib::assert!(j < k_0);
                hax_lib::assert!(q_corrected[i].len() == k_0);
                hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                            k >= q_corrected.len()
                            || (k < tau_0 && q_corrected[k].len() == k_0)
                            || (k >= tau_0 && q_corrected[k].len() == k_1)));
                if delta_bits[j] == 1 {
                    // XOR column j of Q'i with ci
                    for byte in 0..234 {
                        hax_lib::loop_invariant!(|byte: usize| {
                            hax_lib::Prop::from(byte <= 234)
                            .and(hax_lib::Prop::from(q_corrected[i].len() == k_0))
                            .and(hax_lib::forall(|k: usize|
                                    k >= q_corrected.len()
                                    || (k < tau_0 && q_corrected[k].len() == k_0)
                                    || (k >= tau_0 && q_corrected[k].len() == k_1)))
                        });
                        hax_lib::assert_prop!(hax_lib::implies(j < k_0, j < q_corrected[i].len()));
                        hax_lib::assert!(j < q_corrected[i].len());
                        let mut row : [u8;234] = *q_corrected[i].get(j);
                        row[byte] ^= c_bytes[i-1][byte];
                        q_corrected[i] = q_corrected[i].set(j, row);
                        hax_lib::assert!(q_corrected[i].len() == k_0);
                        hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                            k >= q_corrected.len()
                            || (k < tau_0 && q_corrected[k].len() == k_0)
                            || (k >= tau_0 && q_corrected[k].len() == k_1)))


                    }
                }

                hax_lib::assert!(q_corrected[i].len() == k_0);
                hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                    k >= q_corrected.len()
                    || (k < tau_0 && q_corrected[k].len() == k_0)
                    || (k >= tau_0 && q_corrected[k].len() == k_1)))


            }
        } else {
            hax_lib::assert!(q_corrected[i].len() == k_1);
            let delta_bits : [u8;11] = chall_dec_k1(*chall_3, i);
            for j in 0..k_1 {
                hax_lib::loop_invariant!(|j: usize| {
                    hax_lib::Prop::from(j <= k_1)
                    .and(hax_lib::Prop::from(q_corrected[i].len() == k_1))
                    .and(hax_lib::forall(|k: usize|
                        k >= q_corrected.len()
                        || (k < tau_0 && q_corrected[k].len() == k_0)
                        || (k >= tau_0 && q_corrected[k].len() == k_1)))
                });
                hax_lib::assert!(j < k_1);
                hax_lib::assert!(q_corrected[i].len() == k_1);
                hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                            k >= q_corrected.len()
                            || (k < tau_0 && q_corrected[k].len() == k_0)
                            || (k >= tau_0 && q_corrected[k].len() == k_1)));
                if delta_bits[j] == 1 {
                    // XOR column j of Q'i with ci
                    for byte in 0..234 {
                        hax_lib::loop_invariant!(|byte: usize| {
                            hax_lib::Prop::from(byte <= 234)
                            .and(hax_lib::Prop::from(q_corrected[i].len() == k_1))
                            .and(hax_lib::forall(|k: usize|
                                k >= q_corrected.len()
                                || (k < tau_0 && q_corrected[k].len() == k_0)
                                || (k >= tau_0 && q_corrected[k].len() == k_1)))
                        });
                        hax_lib::assert!(j < q_corrected[i].len());
                        let mut row : [u8;234] = *q_corrected[i].get(j);
                        row[byte] ^= c_bytes[i-1][byte];
                        q_corrected[i] = q_corrected[i].set(j, row);
                        hax_lib::assert!(q_corrected[i].len() == k_1);
                        hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                            k >= q_corrected.len()
                            || (k < tau_0 && q_corrected[k].len() == k_0)
                            || (k >= tau_0 && q_corrected[k].len() == k_1)))
                    }
                }
                hax_lib::assert!(q_corrected[i].len() == k_1);
                hax_lib::assert_prop!(hax_lib::forall(|k: usize|
                    k >= q_corrected.len()
                    || (k < tau_0 && q_corrected[k].len() == k_0)
                    || (k >= tau_0 && q_corrected[k].len() == k_1)))
            }
        }
    }
    // println!("challenge took: {:?}", challenge_start.elapsed());

    let mut q_e_columns: [[u8;18];tau_0*k_0+tau_1*k_1] = [[0;18];tau_0*k_0+tau_1*k_1];
    let mut index : usize = 0;
    for i in 0..tau {
        hax_lib::loop_invariant!(|i: usize| {
            i <= tau
            && ((i < tau_0 && index == i * k_0) || (i >= tau_0 && index == (i - tau_0) * k_1 + tau_0 * k_0))
        });
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            hax_lib::loop_invariant!(|j: usize| {
                j <= k_b
                && ((i < tau_0 && index == i * k_0 + j) || (i >= tau_0 && index == (i - tau_0) * k_1 + tau_0 * k_0 + j))
            });
            let col : &[u8;234] = q_corrected[i].get(j);
            let col_0 : &[u8;216] = &col[0..216].try_into().unwrap();
            let col_1 : &[u8;18] = &col[216..234].try_into().unwrap();
            let col_hash : [u8;18] = vole_hash(&chall_1, col_0, col_1);
            q_e_columns[index] = col_hash.try_into().unwrap();
            index += 1;
        }
    }

    let mut q_e_xored : [[u8;18];tau_0*k_0+tau_1*k_1] = q_e_columns.clone();
    let mut col_idx : usize = 0;
    for i in 0..tau {
        hax_lib::loop_invariant!(|i: usize| {
            i <= tau
            && ((i < tau_0 && col_idx == i * k_0) || (i >= tau_0 && col_idx == (i - tau_0) * k_1 + tau_0 * k_0))
        });
        if i < tau_0 {
            let delta_bits : [u8;12] = chall_dec_k0(*chall_3, i);
            for j in 0..k_0 {
                hax_lib::loop_invariant!(|j: usize| {
                    j <= k_0
                    && ((i < tau_0 && col_idx == i * k_0 + j) || (i >= tau_0 && col_idx == (i - tau_0) * k_1 + tau_0 * k_0 + j))
                });
                if delta_bits[j] == 1 {
                    for byte in 0..18 {
                        q_e_xored[col_idx][byte] ^= u_tilde[byte];
                    }
                }
                col_idx += 1;
            }
        } else {
            let delta_bits : [u8;11] = chall_dec_k1(*chall_3, i);
            for j in 0..k_1 {
                hax_lib::loop_invariant!(|j: usize| {
                    j <= k_1
                    && ((i < tau_0 && col_idx == i * k_0 + j) || (i >= tau_0 && col_idx == (i - tau_0) * k_1 + tau_0 * k_0 + j))
                });
                if delta_bits[j] == 1 {
                    for byte in 0..18 {
                        q_e_xored[col_idx][byte] ^= u_tilde[byte];
                    }
                }
                col_idx += 1;
            }
        }
    }
    let q_e_flat: [u8; 18 * (tau_0*k_0+tau_1*k_1)] = flatten::<{tau_0*k_0+tau_1*k_1}, 18, {18 * (tau_0*k_0+tau_1*k_1)}>(q_e_xored);

    // h_v value
    let h_v : [u8;32] = h_1_for_2304(&q_e_flat);

    let d_bytes : [u8;200] = bits_to_bytes_for_d(d);

    // chall 2
    let chall_2 : [u8;56] = h_2_2(chall_1, u_tilde.clone(), h_v, d_bytes);

    // et lille fix til hvordan q den hænger sammen, samme check som til prove
    let q_rows : [[u8; 128]; 1728] = vole_to_row_major(q_corrected);
    let q_arr: [[u8; lambda]; ell_bit_size + lambda] = q_rows.try_into().unwrap();

    //let _verify_start = std::time::Instant::now();
    let b_tilde : [u8;16] = faest_aes_verify(
        d.clone().try_into().unwrap(),
        q_arr,
        chall_2,
        chall3_to_bits(&chall_3),
        *a_tilde,
        (pk.0.try_into().unwrap(), pk.1.try_into().unwrap())
    );
    // println!("verify took: {:?}", verify_start.elapsed());

    let chall_3_mark : [u8;16] = h_2_3(chall_2, *a_tilde, b_tilde);

    #[cfg(hax)]
    let res = *chall_3 == chall_3_mark;

    #[cfg(not(hax))]
    let res = (*chall_3).ct_eq(&chall_3_mark).unwrap_u8() == 1;

    res
}