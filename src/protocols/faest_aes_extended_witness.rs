#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::protocols::aes::{add_round_key, key_expansion, mix_columns, shift_rows, sub_bytes};
use crate::utils::helper_methods_cstrnts::{byte_to_bits};
use crate::utils::types::{State};
use crate::utils::constants::{lambda, S_ke, nk, R, ell_bit_size};
use crate::utils::preliminary_helper_methods::flatten;

#[hax_lib::fstar::options("--z3rlimit 50")]
pub fn faest_aes_extend_witness(k :[u8;16], pk : (State, State)) -> [u8; ell_bit_size]{
    let (in_aes, _out_aes) = pk;
    let k_overline = key_expansion(k);
    let bytes_from_k_overline: [u8; 16] = flatten::<nk, 4, {nk * 4} >(k_overline[0..nk].try_into().unwrap());     //INNER_LEN = word len
    let mut witness : [u8;ell_bit_size] = [0;ell_bit_size];
    //let mut index = 0;
    for b in 0..16{     //bytes_from_k_overline_len
        hax_lib::loop_invariant!(|b: usize| {
            b <= 16 &&
            b <= usize::MAX >> 3 &&
            b << 3 <= 128
        });
        let bits: [u8; 8] = byte_to_bits(bytes_from_k_overline[b]);
        for bit in 0..8 {
            hax_lib::loop_invariant!(|bit: usize| {
                bit <= 8 &&
                b <= (usize::MAX >> 8) - bit &&
                (b << 3) + bit <= 128
            });
            //hax_lib::assume!(index < witness.len()); //TODO
            witness[(b << 3) + bit] = bits[bit];
        }
    }
    let k_overline_for_loops : [u8; (R+1) << 4] = flatten::<{(R+1) << 2}, 4, {(R+1) << 4}>(k_overline);

    let mut ik = nk;

    let idx_fst = 16 << 3;       //bytes_from_k_overline_len * bits_len = 128

    for i in 0..(S_ke >> 2){       //S_ke / 4 = S_ke >> 2 == 40 / 4
        hax_lib::loop_invariant!(|i: usize| {
            i <= S_ke >> 2 &&
            (16 << 3) + (i << 2 << 3) <= 128 + 320 &&
            ik == (i << 2) + 4
            //((lambda == 192 && ik == nk + i * 6) || (ik == nk + i * 4)) &&
            //index == 16 * 8 + i * (((ik+1) << 2) - (ik << 2)) * 8
        });
        hax_lib::assert!(ik == i * 4 + nk);
        for byte in (ik << 2)..((ik+1) << 2) {     //ik*4 = ik << 2 & (ik+1)*4=(ik+1) << 2
            hax_lib::loop_invariant!(|byte: usize| {
                byte <= ((ik+1) << 2) &&
                byte >= (ik << 2) &&
                ((ik+1) << 2) <= 164 &&
                (16 << 3) + (i << 2 << 3) + ((byte - (ik << 2)) << 3) <= 128 + 320

                //index == 16 * 8 + i * (((ik+1) << 2) - (ik << 2)) * 8 + (byte - (ik << 2)) * 8
            });
            let bits: [u8; 8] = byte_to_bits(k_overline_for_loops[byte]);
            for bit in 0..8 {
                hax_lib::loop_invariant!(|bit: usize| {
                    bit <= 8 &&
                    (16 << 3) + (i << 2 << 3) + ((byte - (ik << 2)) << 3) + bit <= 128 + 320
                    //index == 16 * 8 + i * (((ik+1) << 2) - (ik << 2)) * 8 + (byte - (ik << 2)) * 8 + bit
                });
                witness[(16 << 3) + (i << 2 << 3) + ((byte - (ik << 2)) << 3) + bit] = bits[bit];
                //index += 1;
            }
        }


        ik = if lambda == 192 { ik+6 } else { ik+4 };
    }
    let idx_snd = idx_fst + ((S_ke >> 2) << 2 << 3);    // = 320
    let Beta = lambda >> 7;    //lambda / 128 = lambda >> 7
    for b in 0..Beta {
        hax_lib::loop_invariant!(|b: usize| {
            b <= Beta &&
            idx_snd == 448 &&
            idx_snd + (b * (R - 1) << 2 << 2 << 3) <= ell_bit_size
            //index == idx_snd + b * (R-1) * 4 * 4 * 8
        });
        //let bval =  b * (R-1) << 2 << 2 << 3;
        let mut state_new : State = in_aes;
        add_round_key(&mut state_new, k_overline[0..4].try_into().unwrap());
        for j in 1..R{
            hax_lib::loop_invariant!(|j: usize| {
                j <= R &&
                j >= 1 &&
                (j << 2) + 4 <= k_overline.len() &&
                idx_snd + (b * (R - 1) << 2 << 2 << 3) + ((j-1) << 2 << 2 << 3) <= ell_bit_size
                //index == idx_snd + bval + (j-1) * 4 * 4 * 8
            });
            //let jval = (j-1) << 2 << 2 << 3;
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            for col in 0..4 {
                hax_lib::loop_invariant!(|col: usize| {
                    col <= 4 &&
                    idx_snd + (b * (R - 1) << 2 << 2 << 3) + ((j-1) << 2 << 2 << 3) + (col << 2 << 3) <= ell_bit_size
                    //index == idx_snd + bval + jval + col * 4 * 8
                });
                //let colval = col << 2 << 3;
                for row in 0..4 {
                    hax_lib::loop_invariant!(|row: usize| {
                        row <= 4 &&
                        idx_snd + (b * (R - 1) << 2 << 2 << 3) + ((j-1) << 2 << 2 << 3) + (col << 2 << 3) + (row << 3) <= ell_bit_size
                        //index == idx_snd + bval + jval + colval + row * 8
                    });
                    //let rowval = row << 3;
                    let bits: [u8; 8] = byte_to_bits(state_new[col][row]);
                    for bit in 0..8 {
                        hax_lib::loop_invariant!(|bit: usize| {
                            bit <= 8 &&
                            idx_snd + (b * (R - 1) << 2 << 2 << 3) + ((j-1) << 2 << 2 << 3) + (col << 2 << 3) + (row << 3) + bit <= ell_bit_size
                            //index == idx_snd + bval + jval + colval + rowval + bit
                        });
                        witness[idx_snd + (b * (R - 1) << 2 << 2 << 3) + ((j-1) << 2 << 2 << 3) + (col << 2 << 3) + (row << 3) + bit] = bits[bit];
                        //index += 1;
                    }
                }
            }
            mix_columns(&mut state_new);    //TODO some sub
            add_round_key(&mut state_new, k_overline[(j << 2)..(j << 2)+4].try_into().unwrap());  //4*j = j << 2
        }
    }

    witness
}