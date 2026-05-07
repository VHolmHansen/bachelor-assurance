#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::utils::galois_field::gf128_mul;
use crate::utils::math::xor_arrays;

// x er her en liste af u8, men det skal være bits
// k er størrelsen på det field F_{2^k} vi gerne vil have det til
pub fn to_field<const x_len : usize, const K: usize, const N: usize>(x: &[u8;x_len]) -> [[u8; 16]; N] { // N should always be equal to X_len / K
    assert!(x.len() % K == 0, "input length must be multiple of k");

    let mut result = [[0u8; 16]; N];
    for i in 0..N {
        let mut field_elem = [0u8; 16];
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
    x: &[[u8; 16]; N],
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
pub fn zk_hash(sd: &[u8], x0: &[[u8; 16]], x1: &[u8; 16]) -> [u8; 16] {
    let lambda = 128;

    // Step 2: Parse sd into r0, r1, s (lambda bits each) and t (64 bits)
    // sd is given as bits, each u8 is 0 or 1
    let r0_bits: &[u8; 128] = sd[0..128].try_into().unwrap();
    let r1_bits: &[u8; 128] = sd[128..256].try_into().unwrap();
    let s_bits:  &[u8; 128] = sd[256..384].try_into().unwrap();
    let t_bits:  &[u8; 64]  = sd[384..448].try_into().unwrap();

    // Convert to field elements
    let r0 = to_field::<128,128,1>(r0_bits)[0];
    let r1 = to_field::<128,128,1>(r1_bits)[0];
    let s  = to_field::<128,128,1>(s_bits)[0];

    // t is 64 bits zero-padded to lambda
    let mut t_padded = [0u8; 128];
    t_padded[..64].copy_from_slice(t_bits);
    let t: [u8; 16] = to_field::<128, 128, 1>(&t_padded)[0];

    let l = x0.len();

    // Step 6: h0 = sum_{i=0}^{l-1} s^{l-1-i} * x0[i]  in F_{2^lambda}
    let mut h0 = [0u8; 16];
    let mut s_pow = field_pow(&s, l - 1); // s^{l-1}
    for i in 0..l {
        let term = gf128_mul(&s_pow, &x0[i]);
        h0 = xor_arrays(&h0, &term);
        if i < l - 1 {
            // divide by s (multiply by s^{-1}) to get next power
            // equivalently recompute: s_pow = s^{l-2-i}
            s_pow = field_pow(&s, l - 2 - i);
        }
    }

    // Step 7: h1 = sum_{i=0}^{l-1} t^{l-1-i} * x0[i]  in F_{2^lambda}
    let mut h1 = [0u8; 16];
    let mut t_pow = field_pow(&t, l - 1);
    for i in 0..l {
        let term = gf128_mul(&t_pow, &x0[i]);
        h1 = xor_arrays(&h1, &term);
        if i < l - 1 {
            t_pow = field_pow(&t, l - 2 - i);
        }
    }

    // Step 8: h = ToBits(r0*h0 + r1*h1 + x1)
    let r0_h0 = gf128_mul(&r0, &h0);
    let r1_h1 = gf128_mul(&r1, &h1);
    let sum   = xor_arrays(&xor_arrays(&r0_h0, &r1_h1), x1);

    sum
}

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