use hax_lib::loop_invariant;
use crate::utils::constants::get_alpha;
use crate::utils::galois_field::{gf_lambda_pow};
use crate::utils::types::{AlphaMul, Word, XorHelper};
use crate::utils::types::{ret_value};
use crate::utils::constants::{LAMBDA, lambda_bytes, R};

// len of res is 1 / 4 * len of input
pub fn words_to_blocks(x: [Word; (R+1)*4]) -> [[u8; 16];  R+1]
{
    let mut a: [[u8; 16]; (R+1)] = [[0u8; 16]; (R+1)];
    for i in 0..(R+1) {
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

// Implements the ByteCombine function from Section 3.2 of the FAEST spec (Figure 3.1).
// Takes a vector of exactly 8 elements in F_2 or F_{2^lambda} and combines them into
// a single element of F_{2^lambda} using powers of the F_{2^8} generator alpha_8 within F_{2^lambda}.
//
// Concretely, given input x = (x_0, ..., x_7), this computes:
//   result = sum_{i=0}^{7} x_i * alpha_8^i
// where alpha_8 is the generator of F_{2^8} viewed as a subfield of F_{2^lambda}.
//
// This function is generic over T to support two calling modes:
//   - T = u8 (wire values): each x_i is a single bit (0 or 1), and the contribution
//     of x_i is either alpha_8^i (if x_i=1) or 0 (if x_i=0).
//     This corresponds to interpreting 8 bits as a polynomial in F_{2^8}, i.e.
//     combining 8 F_2 elements into one F_{2^8} element embedded in F_{2^lambda}.
//   - T = [u8; lambda_bytes] (VOLE tags or keys): each x_i is already a full F_{2^lambda}
//     element (a VOLE tag or key), and the contribution of x_i is x_i * alpha_8^i
//     computed as a full F_{2^lambda} multiplication.
//     This corresponds to applying the same linear combination to the tags/keys,
//     which is valid because the VOLE MAC is linearly homomorphic (Section 2.3.1 of spec).
//
// The little-endian ordering means x_0 is the coefficient of alpha_8^0 (the constant term),
// matching the AES standard's interpretation of bytes as polynomials (Section 3.2 of spec).
pub fn byte_combine<T>(x: [T; 8]) -> [u8; lambda_bytes]
where
    T: AlphaMul + XorHelper,
{
    let mut res: [u8; lambda_bytes] = [0; lambda_bytes];
    for i in 0..x.len() {
        loop_invariant!(|i: usize| { i <= x.len() });

        // alpha_pow(i) returns alpha_8^i as an element of F_{2^lambda},
        // i.e. the i-th power of the F_{2^8} generator embedded in F_{2^lambda}
        // (the generator elements are specified per field size in Appendix A of spec)
        let alpha_pow_val = alpha_pow(i as i32);
        hax_lib::assert!(i < x.len());
        let elem = x[i];

        // multiply elem by alpha_8^i:
        //   - if T = u8 (wire value): returns alpha_pow_val if elem=1, else 0
        //     (multiplying a field element by a bit just selects or zeroes it)
        //   - if T = [u8;lambda_bytes] (VOLE tag/key): returns gf_lambda_mul(elem, alpha_pow_val)
        //     (full F_{2^lambda} multiplication, applying the linear combination to the tag/key)
        // this dispatch is handled by the AlphaMul trait implementation for each type
        let contribution = <T>::multiply_with_alpha(elem, alpha_pow_val);

        // accumulate the contribution into the result via XOR (addition in F_{2^lambda})
        res = <[u8; lambda_bytes]>::xor_array(&res, &contribution);
    }
    res
}

// Computes alpha_8^i as an element of F_{2^lambda}, where alpha_8 is the generator
// of F_{2^8} embedded within F_{2^lambda} (specified per field size in Appendix A of spec).
//
// These powers are used by ByteCombine (Figure 3.1) to combine 8 bits into a single
// F_{2^8} element: result = sum_{i=0}^{7} x_i * alpha_8^i
//
// The three cases correspond to:
//   i=0: alpha_8^0 = 1, the multiplicative identity in F_{2^lambda},
//        represented as the byte 0x01 in the least significant position
//   i=1: alpha_8^1 = alpha_8 itself, the generator element whose concrete bit
//        representation depends on lambda (from Appendix A of spec)
//   i>1: alpha_8^i = alpha_8 * alpha_8^{i-1}, computed by repeated multiplication
//        in F_{2^lambda} via gf_lambda_pow
//
// The i=0 and i=1 cases are special-cased for efficiency since they are the most
// common and do not require any field multiplication.
pub fn alpha_pow(i: i32) -> [u8; lambda_bytes] {
    if i == 0 {
        // alpha_8^0 = 1 in F_{2^lambda}: the element 1 is represented as 0x01
        // in the least significant byte, with all other bytes zero
        let mut result = [0u8; lambda_bytes];
        result[0] = 1;
        result
    } else if i == 1 {
        // alpha_8^1 = alpha_8, the generator of F_{2^8} within F_{2^lambda}.
        // the concrete bit representation is looked up from the field-specific
        // generator table specified in Appendix A of the spec
        get_alpha()
    } else {
        // alpha_8^i for i > 1: compute by raising the generator to the i-th power
        // using repeated multiplication in F_{2^lambda}
        gf_lambda_pow(&get_alpha(), i)
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