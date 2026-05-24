#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::protocols::aes::{add_round_key, key_expansion, mix_columns, shift_rows, sub_bytes};
use crate::utils::helper_methods_cstrnts::byte_to_bits;
use crate::utils::types::{Pk, State};
use crate::utils::constants::{LAMBDA, S_ke, nk, R, ell, lambda_bytes, beta};
use crate::utils::preliminary_helper_methods::flatten;
use crate::utils::helper_methods_for_sign::bits_to_state;

// computing of the extended witness, using secret key k and public key pk
// Contains all values needed to later compute the zk proof constraints
// is composed of the secret key, the words of the expanded key depending on subword i.e. sbox key expand
// the state bits after each shiftrow operation for each encryption block
pub fn faest_aes_extend_witness(k: [u8; lambda_bytes], pk: Pk) -> [u8; ell] {
    // running aes key expansion
    let k_overline = key_expansion(k);
    // taking the first 4 words and turning it into bytes, i.e. the secret key
    let bytes_from_k_overline: [u8; lambda_bytes] = flatten::<nk, 4, {lambda_bytes}>(k_overline[0..nk].try_into().unwrap());
    // the witness
    let mut witness: [u8; ell] = [0; ell];
    // and index for inserting values into the witness
    let mut index = 0;
    for b in 0..bytes_from_k_overline.len() {
        // turning the key to bits
        let bits = byte_to_bits(bytes_from_k_overline[b]);
        // inserting each bit into the witness
        for bit in 0..bits.len() {
            witness[index] = bits[bit];
            index += 1;
        }
    }
    // making the full expanded key into a byte array will make indexing easier
    let k_overline_for_loops: [u8; (R+1) << 4] = flatten::<{(R+1) << 2}, 4, {(R+1) << 4}>(k_overline);
    // taking all the bytes of the expanded key that was produced by subword
    // these are nonlinear outputs, so instead of doing the nonlinear computation, we just find the output this way
    // for aes128 and 256, these appear every 4 words, its every six for aes192
    let mut ik = nk;
    for _ in 0..(S_ke >> 2) {
        // record all 4 bytes (32 bits) of the current non-linear word
        for byte in (ik << 2)..((ik+1) << 2) {
            // turning byte to bits and inserting
            let bits = byte_to_bits(k_overline_for_loops[byte]);
            for bit in 0..bits.len() {
                witness[index] = bits[bit];
                index += 1;
            }
        }
        ik = if LAMBDA == 192 { ik+6 } else { ik+4 };
    }
    // it runs over beta, because if beta is 2 then we have two plaintext-ciphertext pairs
    // so it runs for each plaintext ciophertext pair
    // we want to record the state bits after each ShiftRows operation for rounds 1..R-1
    // these acts as inputs to the next sbox evaluation
    for b in 0..beta {
        // get plaintext from the public key
        let (in_block, _out_block) = pk[b];
        // initialise of state from plaintext
        let mut state_new: State = bits_to_state(&in_block);
        // applying the first round key
        add_round_key(&mut state_new, k_overline[0..4].try_into().unwrap());
        // runs for [1, ..., R-1]
        for j in 1..R {
            // applies subbytes and shiftrows
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            // record the state bits after ShiftRows in column-major order
            for col in 0..4 {
                for row in 0..4 {
                    let bits = byte_to_bits(state_new[col][row]);
                    for bit in 0..bits.len() {
                        witness[index] = bits[bit];
                        index += 1;
                    }
                }
            }
            // continue the round: MixColumns then AddRoundKey, advancing the state
            // to the input of the next SubBytes layer
            mix_columns(&mut state_new);
            add_round_key(&mut state_new, k_overline[(j << 2)..(j << 2)+4].try_into().unwrap());
        }
    }

    witness
}