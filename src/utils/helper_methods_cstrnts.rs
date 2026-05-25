use hax_lib::loop_invariant;
use crate::utils::galois_field::gf128_pow;
use crate::utils::types::{ByteOrBytesArray, Word, XorHelper};
use crate::utils::constants::{alpha};

// len of res is 1 / 4 * len of input
pub fn words_to_blocks(x: [Word; 44]) -> [[u8; 16]; 11]
{
    let mut a: [[u8; 16]; 11] = [[0u8; 16]; 11];
    for i in 0..11 {
        loop_invariant!(|i: usize| {
            i <= 11
        });
        let mut acc: usize = 0;
        for j in 0..4 {
            loop_invariant!(|j: usize| {
                j <= 4 &&
                acc == j * 4
            });
            for k in 0..4 { // word len
                loop_invariant!(|k: usize| {
                    k <= 4 &&
                    acc == j * 4 + k
                });
                let index = (i << 2) + j;
                let word = x[index][k];
                a[i][acc] = word;
                acc += 1
            }
        }
    }
    a
}

pub fn byte_combine(x: ByteOrBytesArray<8>) -> [u8; 16] {
    let mut res: [u8; 16] = [0; 16];
    for i in 0usize..x.len() {
        loop_invariant!(|i: usize| {
            i <= x.len()
        });
        let alpha_pow_val = alpha_pow(i as i32);
        hax_lib::assert!(i < x.len());
        let elem = ByteOrBytesArray::get_at_index(&x, i);

        // multiply_with_alpha must behave as:
        // - if elem is a scalar bit (0 or 1): return alpha_pow_val if bit=1, else [0;16]
        // - if elem is a field element [u8;16]: return gf128_mul(elem, alpha_pow_val)
        let contribution = elem.multiply_with_alpha(alpha_pow_val);
        res = <[u8; 16]>::xor_array(&res, &contribution); // 4 is a dummy value
    }
    res
}


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
#[hax_lib::requires(bits.len() >= 8)]
pub fn bits_to_byte(bits: &[u8]) -> u8 {
    let mut result = 0u8;
    for i in 0..8 {
        result |= bits[i] << i;
    }
    result
}