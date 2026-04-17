use crate::protocols::aes::{add_round_key, key_expansion, mix_columns, nk, shift_rows, sub_bytes, R};
use crate::utils::helper_methods_cstrnts::{byte_to_bits, words_to_blocks};
use crate::utils::types::{lambda, S_ke, State};

pub fn faest_aes_extend_witness(k :[u8;16], pk : (State, State)) -> Vec<u8>{
    let (in_aes, out_aes) = pk;
    let k_overline = key_expansion(k);
    let bytes_from_k_overline : Vec<u8> = words_to_blocks(k_overline.clone()[0..nk].to_vec()).into_iter().flat_map(|arr| arr).collect();
    let mut witness : Vec<u8> = vec![];
    for b in bytes_from_k_overline{
        let bits = byte_to_bits(b);
        for bit in bits {
            witness.push(bit);
        }
    }

    let k_overline_for_loops : Vec<u8> = k_overline.clone().into_iter().flat_map(|word| word).collect();

    let mut ik = nk;

    for j in 0..(S_ke/4){
        for byte in &k_overline_for_loops[ik*4..(ik+1)*4] {
            let bits = byte_to_bits(*byte);
            for bit in bits {
                witness.push(bit);
            }
        }


        ik = if lambda == 192 { ik+6 } else { ik+4 };
    }
    let Beta = lambda / 128;
    for b in 0..Beta{
        let mut state_new : State = in_aes;
        add_round_key(&mut state_new, k_overline[0..4].to_vec());
        for j in 1..R{
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            for col in 0..4 {
                for row in 0..4 {
                    let bits = byte_to_bits(state_new[col][row]);
                    for bit in bits{
                        witness.push(bit);
                    }
                }
            }
            mix_columns(&mut state_new);
            add_round_key(&mut state_new, k_overline[4*j..4*j+4].to_vec());
        }
    }

    witness
}