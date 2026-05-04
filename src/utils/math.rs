use hax_lib::{assume, loop_invariant, Int, ToInt};
use crate::utils::galois_field::gf128_mul;
use crate::utils::types::State;
/*
#[hax_lib::include]
#[hax_lib::requires(y > 0)]
#[hax_lib::ensures(|result| result >= 0 && result < y)]
pub fn modulo(x: i128, y: i128) -> i128 {
    let res = x % y;
    if res < 0 {
        res + y
    } else {
        res
    }
}

#[hax_lib::include]
#[hax_lib::requires(
x >= 0
&& y >= 0
&& x < i128::MAX
&& y < (i128::MAX - x)
)]
#[hax_lib::ensures(|result| result >= 0 && result >= x && result >= y)]
pub fn addition(x: i128, y: i128) -> i128 {
    x + y
}

#[hax_lib::include]
#[hax_lib::requires(
x < i128::MAX
&& y >= 0
&& x >= y)]
#[hax_lib::ensures(|result| result >= 0 && result <= x)]
pub fn subtraction(x: i128, y: i128) -> i128 {
    x - y
}

#[hax_lib::include]
#[hax_lib::requires(
x < i128::MAX / 2
&& x > 0
&& y >= 0
&& y < i128::MAX / x)]
#[hax_lib::ensures(|result| result >= 0 && result < i128::MAX)]
pub fn multiplication(x: i128, y: i128) -> i128 {
    x * y
}
*/

pub fn convert_byte_array_to_int(bytes: &[u8]) -> Int {
    let mut result = 0.to_int();
    let mut multiplier = 1.to_int();

    for i in 0..bytes.len() {
        result = result + (bytes[i] as usize).to_int() * multiplier;
        multiplier = multiplier * 256.to_int();
    }

    result
}

#[hax_lib::requires(vec3.len() <= usize::MAX
                    && vec3.len() > 0
                    && vec2.len() <= usize::MAX - vec3.len()
                    && vec2.len() >= 0
)]
#[hax_lib::ensures(|result| result.len() > 0
                    && result.len() > vec2.len()
                    && result.len() == vec2.len() + vec3.len()
)]
pub fn push_on_vec<T: Clone>(vec2: Vec<T>, vec3: Vec<T>) -> Vec<T> {
    let mut vec1 = vec2.clone();
    /*
    assume!(vec1.len() <= usize::MAX - 1);
    assume!(vec2.len() > 0);

    if vec2.len() > 0 {
    for i in 0..vec2.len() {
        loop_invariant!(|i: usize| {
            i <= vec2.len()
            && vec1.len() == i
        });
        let old_len = vec1.len();
        assume!(i < vec2.len() && vec1.len() < usize::MAX - 1);
        vec1.push(vec2[i].clone());
        assert!(old_len <= usize::MAX - 1);
        assert!(vec1.len() == old_len + 1);
        assert!(old_len == i);
        assert!(vec1.len() == (i + 1));
        assert!(vec1.len() <= usize::MAX);
    }}

     */


    for i in 0..vec3.len() {
        loop_invariant!(|i: usize| {
            i <= vec3.len()
            && vec1.len() == vec2.clone().len() + i
        });
        let old_len = vec1.len();

        vec1.insert(vec2.len() + i, vec3[i].clone());
        //vec1.push(vec3[i].clone());
        assert!(vec2.len() <= usize::MAX - (i + 1));
        assert!(old_len <= usize::MAX - 1);
        //assert!(vec1.len() <= usize::MAX - (vec2.len() + i + 1));
        assert!(vec1.len() == old_len + 1);
        assert!(old_len == vec2.clone().len() + i);
        assert!(vec1.len() == vec2.len() + (i + 1));
    }

    assume!(vec1.len() <= usize::MAX && vec1.len() > 0 && vec1.len() == vec2.len() + vec3.len());
    vec1
}


pub fn xor_arrays<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub fn transform_byte_array_to_state(a: &[u8]) -> State {
    let mut state = [[0u8; 4]; 4];

    for col in 0..4 {
        for row in 0..4 {
            state[col][row] = a[col * 4 + row];
        }
    }

    state
}

pub fn transform_state_to_array(state: &State) -> [u8; 16] {
    let mut bytes = [0u8; 16];

    for col in 0..4 {
        for row in 0..4 {
            bytes[col * 4 + row] = state[col][row];
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
        if e & 1 == 1 {
            result = gf128_mul(&result, &b);
        }
        b = gf128_mul(&b, &b);
        e >>= 1;
    }
    result
}

