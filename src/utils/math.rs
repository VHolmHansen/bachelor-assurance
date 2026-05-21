use hax_lib::{assume, ensures, loop_invariant, requires, Int, ToInt};
use crate::utils::galois_field::gf128_mul;
use crate::utils::types::State;
pub fn convert_byte_array_to_int(bytes: &[u8]) -> Int {
    let mut result = 0.to_int();
    let mut multiplier = 1.to_int();

    for i in 0..bytes.len() {
        result = result + (bytes[i] as usize).to_int() * multiplier;
        multiplier = multiplier * 256.to_int();
    }

    result
}

pub fn xor_arrays<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

#[hax_lib::requires(a.len() >= 16)]
pub fn transform_byte_array_to_state(a: &[u8]) -> State {
    let mut state = [[0u8; 4]; 4];

    for col in 0..4 {
        for row in 0..4 {
            state[col][row] = a[(col << 2) + row];
        }
    }

    state
}

pub fn transform_state_to_array(state: &State) -> [u8; 16] {
    let mut bytes = [0u8; 16];

    for col in 0..4 {
        for row in 0..4 {
            bytes[(col << 2) + row] = state[col][row];
        }
    }

    bytes
}

pub fn field_pow(base: &[u8; 16], exp: usize) -> [u8; 16] {
    if exp == 0 {
        let mut one = [0u8; 16];
        one[0] = 0x01;
        return one;
    }
    let mut result = [0u8; 16];
    result[0] = 0x01;
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        hax_lib::loop_decreases!(e);
        if e & 1 == 1 {
            result = gf128_mul(&result, &b);
        }
        b = gf128_mul(&b, &b);
        e >>= 1;
    }
    result
}

#[requires(n <= u8::MAX && modu <= u8::BITS as u8)]
#[ensures(|result| result <= modu)]
pub fn bitand_mod(n: u8, modu: u8) -> u8 {
    n & modu
}

