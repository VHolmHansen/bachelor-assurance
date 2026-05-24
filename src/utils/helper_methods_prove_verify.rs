#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::constants::{lambda_bytes, lambda_bytes_times_three, lambda_bytes_times_two};
use crate::utils::galois_field::{gf_lambda_mul};
use crate::utils::math::xor_arrays;

// Implements the ToField conversion from Section 3.2 of the FAEST spec (Figure 3.1).
// Maps a bit string x in {0,1}^{N*K} into a vector of N field elements in F_{2^K},
// each embedded as an element of F_{2^lambda} (stored as lambda_bytes bytes).
//
// Concretely, for each i in 0..N, the i-th field element is:
//   result[i] = sum_{j=0}^{K-1} x[i*K + j] * alpha_K^j
// where alpha_K is the generator of F_{2^K} and the sum is over F_2 (i.e. the bits
// of x select which powers of alpha_K appear in the field element).
//
// The encoding is little-endian: x[i*K + 0] is the coefficient of alpha_K^0
// (the constant term), x[i*K + 1] is the coefficient of alpha_K^1, and so on.
// This matches the little-endian ordering specified in Figure 3.1 of the spec:
//   ToField(x, K) = sum_{i=0}^{K-1} x[i] * alpha_K^i
//
// The field element is stored as a lambda_bytes byte array, where bit j of the
// element is stored at byte j/8, bit position j%8 (little-endian within each byte).
// For K < lambda, only the first K bits are set and the remaining bits are zero,
// reflecting that F_{2^K} is a subfield of F_{2^lambda}.
//
// The const generic parameters are:
//   x_len: the total length of the input bit string (must equal N * K)
//   K:     the size of each field F_{2^K} (the number of bits per field element)
//   N:     the number of field elements to produce (must equal x_len / K)
pub fn to_field<const x_len: usize, const K: usize, const N: usize>(
    x: &[u8; x_len],
) -> [[u8; lambda_bytes]; N] {
    // N should always be equal to x_len / K
    assert!(x.len() % K == 0, "input length must be multiple of k");

    let mut result = [[0u8; lambda_bytes]; N];
    for i in 0..N {
        // field_elem will hold the i-th field element as a lambda_bytes byte array.
        // it starts as zero and we set bits one by one based on the input bits
        let mut field_elem = [0u8; lambda_bytes];
        for j in 0..K {
            // x[i*K + j] is the j-th bit of the i-th group of K input bits,
            // which is the coefficient of alpha_K^j in the i-th field element
            let bit = x[i * K + j];
            if bit == 1 {
                // set the j-th bit of field_elem in little-endian order:
                // bit j lives at byte j/8, at bit position j%8 within that byte
                // (this matches the little-endian ordering of ToField in Figure 3.1)
                let byte_idx = j / 8;
                let bit_idx = j % 8;
                field_elem[byte_idx] |= 1 << bit_idx;
            }
            // if bit is 0, the coefficient of alpha_K^j is 0 so nothing is added
        }
        result[i] = field_elem;
    }
    result
}

// burde være omvendt af den ovenstående funktion
pub fn to_bits<const N: usize, const K: usize, const NK: usize>(
    x: &[[u8; lambda_bytes]; N],
    result: &mut [u8; NK],
) {
    debug_assert_eq!(N * K, NK);
    let mut idx = 0;
    for field_elem in x {
        for j in 0..K {
            result[idx] = (field_elem[j >> 3] >> (j & 7)) & 1;
            idx += 1;
        }
    }
}


// Implements the ZKHash function from Section 4.2.4 of the FAEST spec (Figure 4.4).
// Takes a seed sd, a vector of F_{2^lambda} constraint values x0, and a masking value x1,
// and compresses them into a single F_{2^lambda} element.
// ZKHash is used in AESProve and AESVerify to compress the big_C QuickSilver constraint
// values (A_0, A_1 or B) together with the masking value (u*, v*, or q*) into a single
// field element, saving communication compared to sending all big_C values individually.
pub fn zk_hash(sd: &[u8], x0: &[[u8; lambda_bytes]], x1: &[u8; lambda_bytes]) -> [u8; lambda_bytes] {
    // sd = r0 || r1 || s || t = 16 + 16 + 16 + 8 = 56 bytes
    // Division of the sd
    let r0: [u8; lambda_bytes] = sd[0..lambda_bytes].try_into().unwrap();
    let r1: [u8; lambda_bytes] = sd[lambda_bytes..lambda_bytes_times_two].try_into().unwrap();
    let s:  [u8; lambda_bytes] = sd[lambda_bytes_times_two..lambda_bytes_times_three].try_into().unwrap();
    let t:  [u8;  8] = sd[lambda_bytes_times_three..lambda_bytes_times_three+8].try_into().unwrap();
    // initialize h0 and h1
    let mut h0 = [0u8; lambda_bytes];
    let mut h1 = [0u8; lambda_bytes];
    // update for each constraint value (incremental Horner)
    for v in x0 {
        // h0 = h0 * s + v  (in F_{2^128})
        h0 = xor_arrays(&gf_lambda_mul(&h0, &s), v);
        // h1 = h1 * t + v  (bf128_mul_64: 128-bit * 64-bit)
        h1 = xor_arrays(&gf_lambda_mul_64(&h1, &t), v);
    }
    // finalize: h = r0*h0 + r1*h1 + x1
    let term0 = gf_lambda_mul(&r0, &h0);
    let term1 = gf_lambda_mul(&r1, &h1);
    // instead of using tobits, we just simply return as bytes
    xor_arrays(&xor_arrays(&term0, &term1), x1)
}

pub fn gf_lambda_mul_64(a: &[u8; lambda_bytes], b: &[u8; 8]) -> [u8; lambda_bytes] {
    let mut lhs = *a;
    let mut result = [0u8; lambda_bytes];

    // for each of the 64 bits of b
    for idx in 0..64 {
        // if bit idx of b is set, XOR current lhs into result
        let b_bit = (b[idx >> 3] >> (idx & 7)) & 1;
        if b_bit == 1 {
            for k in 0..lambda_bytes {
                result[k] ^= lhs[k];
            }
        }

        if idx < 63 {
            let top_bit = (lhs[lambda_bytes - 1] >> 7) & 1;
            let mut shifted = [0u8; lambda_bytes];
            for k in (1..lambda_bytes).rev() {
                shifted[k] = (lhs[k] << 1) | (lhs[k-1] >> 7);
            }
            shifted[0] = lhs[0] << 1;
            if top_bit == 1 {
                if lambda_bytes == 16 {
                    // GF(2^128): x^128 + x^7 + x^2 + x + 1 = 0x87
                    shifted[0] ^= 0x87;
                } else if lambda_bytes == 24 {
                    // GF(2^192): x^192 + x^7 + x^2 + x + 1 = 0x87
                    shifted[0] ^= 0x87;
                } else if lambda_bytes == 32 {
                    // GF(2^256): x^256 + x^10 + x^5 + x^2 + 1 = 0x425
                    shifted[0] ^= 0x25;
                    shifted[1] ^= 0x04;
                }
            }
            lhs = shifted;
        }
    }
    result
}