#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::constants::{lambda_bytes, lambda_bytes_times_three, lambda_bytes_times_two};
use crate::utils::galois_field::{gf_lambda_mul};
use crate::utils::math::xor_arrays;

// x er her en liste af u8, men det skal være bits
// k er størrelsen på det field F_{2^k} vi gerne vil have det til
pub fn to_field<const x_len : usize, const K: usize, const N: usize>(x: &[u8;x_len]) -> [[u8; lambda_bytes]; N] { // N should always be equal to X_len / K
    assert!(x.len() % K == 0, "input length must be multiple of k");

    let mut result = [[0u8; lambda_bytes]; N];
    for i in 0..N {
        let mut field_elem = [0u8; lambda_bytes];
        for j in 0..K {
            let bit = x[i * K + j];
            if bit == 1 {
                // Set the j-th bit in the field element (little-endian)
                let byte_idx = j / 8;
                let bit_idx = j % 8;
                field_elem[byte_idx] |= 1 << bit_idx;
            }
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


// funktion brugt af prove og verify
pub fn zk_hash(sd: &[u8], x0: &[[u8; lambda_bytes]], x1: &[u8; lambda_bytes]) -> [u8; lambda_bytes] {
    // sd = r0 || r1 || s || t = 16 + 16 + 16 + 8 = 56 bytes
    let r0: [u8; lambda_bytes] = sd[0..lambda_bytes].try_into().unwrap();
    let r1: [u8; lambda_bytes] = sd[lambda_bytes..lambda_bytes_times_two].try_into().unwrap();
    let s:  [u8; lambda_bytes] = sd[lambda_bytes_times_two..lambda_bytes_times_three].try_into().unwrap();
    let t:  [u8;  8] = sd[lambda_bytes_times_three..lambda_bytes_times_three+8].try_into().unwrap();

    // init
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
    xor_arrays(&xor_arrays(&term0, &term1), x1)
}

// Helper: compute base^exp in GF(2^128)
fn field_pow(base: &[u8; lambda_bytes], exp: usize) -> [u8; lambda_bytes] {
    if exp == 0 {
        let mut one = [0u8; lambda_bytes];
        one[0] = 1;
        return one;
    }
    let mut result = [0u8; lambda_bytes];
    result[0] = 1; // start at 1
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_lambda_mul(&result, &b);
        }
        b = gf_lambda_mul(&b, &b);
        e >>= 1;
    }
    result
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