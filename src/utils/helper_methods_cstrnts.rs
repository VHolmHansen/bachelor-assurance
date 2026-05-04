use crate::utils::galois_field::gf128_pow;
use crate::utils::types::Word;
use crate::utils::types::{ret_value};
use crate::utils::constants::{alpha};
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
// M is N/4
// TODO: make pub when integrating
#[allow(dead_code)]
fn array_words_to_blocks<const N: usize, const M: usize>(x: [Word; N]) -> [[u8; 16]; M]
    //where [(); N / 4]: Sized
{
    let mut a: [[u8; 16]; M] = [[0u8; 16]; M];
    for i in 0..M {
        let mut acc: usize = 0;
        for j in 0..4 {
            for k in 0..4 { // word len
                let word = x[i * 4 + j][k];
                a[i][acc] = word;
                acc += 1
            }
        }
    }
    a
}

pub fn byte_combine<T: ret_value>(x: T) -> [u8; 16] {
    if x.len() % 8 != 0 {
        panic!("invalid byte length")
    }
    let mut res: [u8; 16] = [0; 16];
    for i in 0..8 {
        let alpha_pow_val = alpha_pow(i);
        let elem = x.get_element(i as usize);

        // multiply_with_alpha must behave as:
        // - if elem is a scalar bit (0 or 1): return alpha_pow_val if bit=1, else [0;16]
        // - if elem is a field element [u8;16]: return gf128_mul(elem, alpha_pow_val)
        let contribution = <T as ret_value>::multiply_with_alpha(elem, alpha_pow_val);
        res = <[[u8;16];4] as ret_value>::xor_array(&res, &contribution); // 4 is a dummy value
    }
    res
}

/*
pub fn byte_combine<T: ret_value>(x: T) -> [u8; 16] {
    if x.len() % 8 != 0 {
        panic!("invalid byte length")
    }
    let mut res: [u8; 16] = [0; 16];
    for i in 0..8 {
        let alpha_pow_val = alpha_pow(i);
        let elem = x.get_element(i as usize);
        const n: usize = dummy
        // multiply_with_alpha must behave as:
        // - if elem is a scalar bit (0 or 1): return alpha_pow_val if bit=1, else [0;16]
        // - if elem is a field element [u8;16]: return gf128_mul(elem, alpha_pow_val)
        let contribution = <T as ret_value>::multiply_with_alpha(elem, alpha_pow_val);
        res = [[u8; 16]; dummy] as ret_value>::xor_array(&res, &contribution);   //TODO: DONT USE DUMMY
    }
    res
}
 */

pub fn alpha_pow(i : i32) -> [u8;16] {
    if i == 0 {
        [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    } else if i == 1 {
        alpha
    } else {
        gf128_pow(&alpha, i)
    }
}



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