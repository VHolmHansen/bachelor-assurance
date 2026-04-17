use crate::utils::galois_field::gf128_pow;
use crate::utils::types::Word;
use crate::utils::types::{k_0, k_1, ret_size_exp_bwd, ret_size_exp_fwd, ret_value, s_enc, tau_0, S_ke, State};
pub fn words_to_blocks(x: Vec<Word>) -> Vec<[u8; 16]> {
    x.chunks(4)
        .map(|chunk| {
            let mut block = [0u8; 16];
            for (i, word) in chunk.iter().enumerate() {
                block[i * 4..(i + 1) * 4].copy_from_slice(word);
            }
            block
        })
        .collect()
}

pub fn byte_combine<T : ret_value>(x : T) -> [u8;16] {
    if x.len() % 8 != 0 {
        panic!("invalid byte length")
    }
    let mut res : [u8;16] = [0;16];
    for i in 0..8 {
        let alpha_pow_val = alpha_pow(i);
        res = <Vec<[u8;16]> as ret_value>::xor_array(&res, &<T as ret_value>::multiply_with_alpha(x.get_element(i as usize), alpha_pow_val));
    }
    res
}

pub fn alpha_pow(i : i32) -> [u8;16] {
    if i == 0 {
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    } else if i == 1 {
        alpha
    } else {
        gf128_pow(&alpha, i)
    }
}

pub const alpha : [u8;16] = [0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1, 0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05];

pub fn byte_to_bits(byte: u8) -> [u8; 8] {
    let mut bits = [0u8; 8];
    for i in 0..8 {
        bits[i] = (byte >> i) & 1;
    }
    bits
}

pub fn bits_to_byte(bits: &[u8]) -> u8 {
    let mut result = 0u8;
    for i in 0..8 {
        result |= bits[i] << i;
    }
    result
}