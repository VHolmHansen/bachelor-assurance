#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::{galois_field::gf128_mul, math};
use crate::utils::math::xor_arrays;

// TODO: K might be known, verify precondition
// x er her en liste af u8, men det skal være bits
// k er størrelsen på det field F_{2^k} vi gerne vil have det til
#[hax_lib::requires(K != 0 && x_len % K == 0 && K <= 128 && N > 0 && N <= usize::MAX / K && x_len == N * K)]
pub fn to_field<const x_len : usize, const K: usize, const N: usize>(x: &[u8;x_len]) -> [[u8; 16]; N] { // N should always be equal to X_len / K
    assert!(x.len() % K == 0, "input length must be multiple of k");

    let mut result = [[0u8; 16]; N];
    for i in 0..N {
        hax_lib::loop_invariant!(|i: usize| {
            i <= N
        });
        let mut field_elem = [0u8; 16];
        for j in 0..K {
            hax_lib::loop_invariant!(|j: usize| {
                j <= K
            });
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

//TODO: K might be known, verify precondition
// burde være omvendt af den ovenstående funktion
#[hax_lib::requires(K > 0 && N <= usize::MAX / K && N * K == NK && K <= 128)]
pub fn to_bits<const N: usize, const K: usize, const NK: usize>(
    x: &[[u8; 16]; N],
    result: &mut [u8; NK],
) {
    debug_assert_eq!(N * K, NK);
    let mut idx = 0;
    for field_elem in 0..N {
        hax_lib::loop_invariant!(|field_elem: usize| {
            field_elem <= N &&
            idx == field_elem * K
        });
        for j in 0..K {
            hax_lib::loop_invariant!(|j: usize| {
                j <= K &&
                idx == field_elem * K + j &&
                j >> 3 <= 16
            });
            result[idx] = (x[field_elem][j >> 3] >> (math::bitand_mod(j as u8, 7))) & 1;
            idx += 1;
        }
    }
}

//TODO: cleanup in input params + preconds

// funktion brugt af prove og verify
#[hax_lib::requires(sd.len() >= 56)]
pub fn zk_hash(sd: &[u8], x0: &[[u8; 16]], x1: &[u8; 16]) -> [u8; 16] {
    // sd = r0 || r1 || s || t = 16 + 16 + 16 + 8 = 56 bytes
    let r0: [u8; 16] = sd[0..16].try_into().unwrap();
    let r1: [u8; 16] = sd[16..32].try_into().unwrap();
    let s:  [u8; 16] = sd[32..48].try_into().unwrap();
    let t:  [u8;  8] = sd[48..56].try_into().unwrap();

    // init
    let mut h0 = [0u8; 16];
    let mut h1 = [0u8; 16];

    // update for each constraint value (incremental Horner)
    for v in x0 {
        // h0 = h0 * s + v  (in F_{2^128})
        h0 = xor_arrays(&gf128_mul(&h0, &s), v);
        // h1 = h1 * t + v  (bf128_mul_64: 128-bit * 64-bit)
        h1 = xor_arrays(&gf128_mul_64(&h1, &t), v);
    }

    // finalize: h = r0*h0 + r1*h1 + x1
    let term0 = gf128_mul(&r0, &h0);
    let term1 = gf128_mul(&r1, &h1);
    xor_arrays(&xor_arrays(&term0, &term1), x1)
}
/*
// Helper: compute base^exp in GF(2^128)
fn field_pow(base: &[u8; 16], exp: usize) -> [u8; 16] {
    if exp == 0 {
        let mut one = [0u8; 16];
        one[0] = 1;
        return one;
    }
    let mut result = [0u8; 16];
    result[0] = 1; // start at 1
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = gf128_mul(&result, &b);
        }
        b = gf128_mul(&b, &b);
        e >>= 1;
    }
    result
}
 */

pub fn gf128_mul_64(a: &[u8; 16], b: &[u8; 8]) -> [u8; 16] {
    // zero-pad b to 16 bytes and use regular gf128_mul
    let mut b_padded = [0u8; 16];
    b_padded[..8].copy_from_slice(b);
    gf128_mul(a, &b_padded)
}