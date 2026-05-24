use crate::protocols::aes;
use crate::utils::constants::{LAMBDA, lambda_bytes};

#[hax_lib::requires(a <= u8::MAX
                    && b <= u8::MAX
                    && a >= 0
                    && b >= 0)]
#[hax_lib::ensures(|result| result <= u8::MAX)]
pub fn gf28_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;

    for _ in 0..8 {
        if (b & 1) != 0 {
            result ^= a;
        }

        if (a & 0x80) != 0 {
            a = (a << 1) ^ 0b00011011;
        } else {
            a <<= 1;
        }

        b >>= 1;
    }

    result
}



#[hax_lib::opaque]
#[hax_lib::requires(a <= u8::MAX
&& a >= 0)]
#[hax_lib::ensures(|result| gf28_multiply(result, a) == 1)]
pub fn gf28_inverse(a: u8) -> u8 {
    if a == 0 {
        return 0;
    };

    #[hax_lib::requires(base <= u8::MAX && exp <= u8::MAX)]
    #[hax_lib::ensures(|result| result <= u8::MAX)]
    fn gf28_pow(mut base: u8, mut exp: u8) -> u8 {
        let mut result = 1;
        while exp > 0 {
            if exp & 1 != 0 {
                result = gf28_multiply(base, result);
            }
            base = gf28_multiply(base, base);
            exp >>= 1;
        }
        result
    }

    let result = gf28_pow(a, 254);
    assert!(result > 0);
    result
}



// Multiplies two elements a and b of F_{2^128}, the finite field used when lambda=128.
// F_{2^128} is defined as F_2[x] / P128, where P128 = x^128 + x^7 + x^2 + x + 1
// is the irreducible polynomial specified in Section 3.2 of the FAEST spec.
//
// The multiplication is done in two steps:
//   1. Carry-less polynomial multiplication: treat a and b as polynomials over F_2
//      and multiply them schoolbook-style, giving a degree-255 polynomial (256 bits)
//   2. Reduction modulo P128: reduce the 256-bit result back down to 128 bits by
//      replacing each high-degree term x^i (for i >= 128) with x^{i-128} * (x^7 + x^2 + x + 1),
//      working from the highest degree down to degree 128
pub fn gf128_mul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    // allocate a 256-bit buffer to hold the unreduced product before reduction
    let mut result = [0u8; 32];

    // step 1: carry-less polynomial multiplication.
    // for each pair of set bits (i, j) in a and b respectively,
    // the product has a contribution at degree i+j, which is a XOR (flip) of that bit.
    // this is equivalent to schoolbook polynomial multiplication over F_2
    for i in 0..128 {
        if get_bit(a, i) == 1 {
            for j in 0..128 {
                if get_bit(b, j) == 1 {
                    flip_bit(&mut result, i + j);
                }
            }
        }
    }

    // step 2: reduce modulo P128 = x^128 + x^7 + x^2 + x + 1.
    // working from degree 255 down to degree 128, for each set bit at degree i we use
    // the relation x^128 = x^7 + x^2 + x + 1 (from P128) to write:
    //   x^i = x^{i-128} * x^128 = x^{i-128} * (x^7 + x^2 + x + 1)
    // so we flip the bits at degrees i-128+7, i-128+2, i-128+1, i-128
    let mut i = 255;
    while i >= 128 {
        if get_bit(&result, i) == 1 {
            flip_bit(&mut result, i - 128 + 7);
            flip_bit(&mut result, i - 128 + 2);
            flip_bit(&mut result, i - 128 + 1);
            flip_bit(&mut result, i - 128);
        }
        i -= 1;
    }

    // return the lower 128 bits, which now hold the reduced product in F_{2^128}
    result[0..16].try_into().unwrap()
}

// Multiplies two elements a and b of F_{2^192}, the finite field used when lambda=192.
// F_{2^192} is defined as F_2[x] / P192, where P192 = x^192 + x^7 + x^2 + x + 1
// is the irreducible polynomial specified in Section 3.2 of the FAEST spec.
//
// Unlike gf128_mul and gf256_mul which separate multiplication and reduction into two passes,
// this uses the shift-and-add algorithm which interleaves them:
//   - iterate over the bits of b one at a time
//   - for each set bit of b, XOR the current value of a (shifted appropriately) into the result
//   - after each step, shift a left by 1 bit; if the top bit was set, immediately reduce
//     by XORing in 0x87 = x^7 + x^2 + x + 1 (the low-degree terms of P192),
//     using the relation x^192 = x^7 + x^2 + x + 1
// this keeps the intermediate value of a within 192 bits throughout, avoiding the need
// for a double-width buffer
pub fn gf192_mul(a: &[u8; 24], b: &[u8; 24]) -> [u8; 24] {
    let mut result = [0u8; 24];
    // lhs holds the current value of a, shifted left by idx positions and reduced mod P192.
    // at iteration idx, lhs = a * x^idx mod P192
    let mut lhs = *a;

    for idx in 0..192 {
        // if bit idx of b is set, add the current shifted a to the result.
        // this accumulates the contribution of a * x^idx to the product a * b
        let b_bit = (b[idx >> 3] >> (idx & 7)) & 1;
        if b_bit == 1 {
            for k in 0..24 { result[k] ^= lhs[k]; }
        }

        // shift lhs left by 1 bit to prepare a * x^{idx+1} for the next iteration,
        // but only if there is a next iteration (idx < 191)
        if idx < 191 {
            // record the top bit before shifting, to know if reduction is needed
            let top_bit = (lhs[23] >> 7) & 1;

            // shift all 24 bytes left by 1 bit, propagating carry bits between bytes
            let mut shifted = [0u8; 24];
            for k in (1..24).rev() {
                shifted[k] = (lhs[k] << 1) | (lhs[k - 1] >> 7);
            }
            shifted[0] = lhs[0] << 1;

            // if the top bit was set before shifting, the degree-192 term appeared.
            // reduce immediately using x^192 = x^7 + x^2 + x + 1, i.e. XOR in
            // 0x87 = 1000 0111 = x^7 + x^2 + x + 1 into the lowest byte
            if top_bit == 1 {
                shifted[0] ^= 0x87;
            }
            lhs = shifted;
        }
    }
    result
}

// Multiplies two elements a and b of F_{2^256}, the finite field used when lambda=256.
// F_{2^256} is defined as F_2[x] / P256, where P256 = x^256 + x^10 + x^5 + x^2 + 1
// is the irreducible polynomial specified in Section 3.2 of the FAEST spec.
//
// Uses the same two-step approach as gf128_mul, but for 256-bit field elements:
//   1. Carry-less polynomial multiplication of two degree-255 polynomials,
//      giving a degree-511 result stored in a 512-bit (64-byte) buffer
//   2. Reduction modulo P256: for each set bit at degree i >= 256, use the relation
//      x^256 = x^10 + x^5 + x^2 + 1 to replace x^i with lower-degree terms,
//      working from degree 511 down to degree 256
pub fn gf256_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // allocate a 512-bit buffer to hold the unreduced product
    let mut result = [0u8; 64];

    // step 1: carry-less polynomial multiplication, same schoolbook approach as gf128_mul
    // but iterating over 256 bits for each of a and b
    for i in 0..256 {
        if get_bit(a, i) == 1 {
            for j in 0..256 {
                if get_bit(b, j) == 1 {
                    flip_bit(&mut result, i + j);
                }
            }
        }
    }

    // step 2: reduce modulo P256 = x^256 + x^10 + x^5 + x^2 + 1.
    // for each set bit at degree i >= 256, use the relation
    // x^256 = x^10 + x^5 + x^2 + 1 to write:
    //   x^i = x^{i-256} * (x^10 + x^5 + x^2 + 1)
    // so we flip the bits at degrees i-256+10, i-256+5, i-256+2, i-256
    // note: P256 has no x^1 term unlike P128 and P192
    let mut i = 511;
    while i >= 256 {
        if get_bit(&result, i) == 1 {
            flip_bit(&mut result, i - 256 + 10);
            flip_bit(&mut result, i - 256 + 5);
            flip_bit(&mut result, i - 256 + 2);
            flip_bit(&mut result, i - 256);
        }
        i -= 1;
    }

    // return the lower 256 bits, which now hold the reduced product in F_{2^256}
    result[0..32].try_into().unwrap()
}

pub fn gf_lambda_pow(base: &[u8; lambda_bytes], pow_of: i32) -> [u8; lambda_bytes] {
    if pow_of == 0 {
        let mut result = [0u8; lambda_bytes];
        result[0] = 1;
        return result;
    }
    if pow_of == 1 {
        return *base;
    }
    let mut res = *base;
    for _ in 2..(pow_of + 1) {
        res = gf_lambda_mul(&res, base);
    }
    res
}
// based on the value of LAMBDA, it switches between the three implementation
pub fn gf_lambda_mul(a: &[u8; lambda_bytes], b: &[u8; lambda_bytes]) -> [u8; lambda_bytes] {
    let mut result = [0u8; lambda_bytes];
    if LAMBDA == 128 {
        gf128_mul_into(a.as_slice(), b.as_slice(), &mut result);
    } else if LAMBDA == 192 {
        gf192_mul_into(a.as_slice(), b.as_slice(), &mut result);
    }
    else {
        gf256_mul_into(a.as_slice(), b.as_slice(), &mut result);
    }
    result
}

fn gf128_mul_into(a: &[u8], b: &[u8], out: &mut [u8]) {
    let a: &[u8; 16] = a.try_into().unwrap();
    let b: &[u8; 16] = b.try_into().unwrap();
    let res = gf128_mul(a, b);
    out.copy_from_slice(&res);
}

fn gf192_mul_into(a: &[u8], b: &[u8], out: &mut [u8]) {
    let a: &[u8; 24] = a.try_into().unwrap();
    let b: &[u8; 24] = b.try_into().unwrap();
    let res = gf192_mul(a, b);
    out.copy_from_slice(&res);
}

fn gf256_mul_into(a: &[u8], b: &[u8], out: &mut [u8]) {
    let a: &[u8; 32] = a.try_into().unwrap();
    let b: &[u8; 32] = b.try_into().unwrap();
    let res = gf256_mul(a, b);
    out.copy_from_slice(&res);
}



#[hax_lib::requires(i >> 3 < a.len())]
fn get_bit(a: &[u8], i: usize) -> u8 {
    (a[i >> 3] >> (aes::bitand_mod(i as u8, 7))) & 1    // where 7 = 8 - 1 (bitand instead of mod trick
}

fn flip_bit(a: &mut [u8], i: usize) {
    a[i >> 3] ^= 1 << (aes::bitand_mod(i as u8, 7));    // where 7 = 8 - 1 (bitand instead of mod trick
}

pub fn gf64_add(a: &[u8;8], b: &[u8;8]) -> [u8;8] {
    let mut result = [0u8;8];
    for i in 0..8 {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub fn gf64_mul(a: &[u8;8], b: &[u8;8]) -> [u8;8] {
    // same carry-less multiplication as gf128 but 64 bits wide
    // reduction modulo x^64 + x^4 + x^3 + x + 1
    let mut result = 0u64;
    let mut a_val = u64::from_le_bytes(*a);
    let mut b_val = u64::from_le_bytes(*b);

    // carry-less multiply
    for _ in 0..64 {
        if b_val & 1 == 1 {
            result ^= a_val;
        }
        let carry = (a_val >> 63) & 1;
        a_val <<= 1;
        if carry == 1 {
            // reduce: x^64 = x^4 + x^3 + x + 1
            a_val ^= 0x1b;
        }
        b_val >>= 1;
    }

    result.to_le_bytes()
}


pub fn field_pow_64(base: &[u8; 8], exp: usize) -> [u8; 8] {
    if exp == 0 {
        let mut one = [0u8; 8];
        one[0] = 1;
        return one;
    }
    let mut result = [0u8; 8];
    result[0] = 1;
    for _ in 0..exp {
        result = gf64_mul(&result, base);
    }
    result
}