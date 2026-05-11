#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::protocols::aes::{add_round_key, key_expansion, mix_columns, shift_rows, sub_bytes};
use crate::utils::helper_methods_cstrnts::byte_to_bits;
use crate::utils::types::{Pk, State};
use crate::utils::constants::{lambda, S_ke, nk, R, ell, lambda_bytes, beta};
use crate::utils::preliminary_helper_methods::flatten;
use crate::utils::helper_methods_for_sign::bits_to_state;

pub fn faest_aes_extend_witness(k: [u8; lambda_bytes], pk: Pk) -> [u8; ell] {
    let k_overline = key_expansion(k);
    let bytes_from_k_overline: [u8; lambda_bytes] = flatten::<nk, 4, {lambda_bytes}>(k_overline[0..nk].try_into().unwrap());
    let mut witness: [u8; ell] = [0; ell];
    let mut index = 0;

    // key bits
    for b in 0..bytes_from_k_overline.len() {
        let bits = byte_to_bits(bytes_from_k_overline[b]);
        for bit in 0..bits.len() {
            witness[index] = bits[bit];
            index += 1;
        }
    }

    let k_overline_for_loops: [u8; (R+1) << 4] = flatten::<{(R+1) << 2}, 4, {(R+1) << 4}>(k_overline);

    // non-linear key expansion bits
    let mut ik = nk;
    for _ in 0..(S_ke >> 2) {
        for byte in (ik << 2)..((ik+1) << 2) {
            let bits = byte_to_bits(k_overline_for_loops[byte]);
            for bit in 0..bits.len() {
                witness[index] = bits[bit];
                index += 1;
            }
        }
        ik = if lambda == 192 { ik+6 } else { ik+4 };
    }

    // beta encryption blocks
    for b in 0..beta {
        let (in_block, _out_block) = pk[b];
        let mut state_new: State = bits_to_state(&in_block);
        add_round_key(&mut state_new, k_overline[0..4].try_into().unwrap());
        for j in 1..R {
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            for col in 0..4 {
                for row in 0..4 {
                    let bits = byte_to_bits(state_new[col][row]);
                    for bit in 0..bits.len() {
                        witness[index] = bits[bit];
                        index += 1;
                    }
                }
            }
            mix_columns(&mut state_new);
            add_round_key(&mut state_new, k_overline[(j << 2)..(j << 2)+4].try_into().unwrap());
        }
    }

    witness
}