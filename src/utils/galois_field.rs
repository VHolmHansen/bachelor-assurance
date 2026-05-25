use crate::utils::math;

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



pub fn gf128_mul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    // carry-less multiplication of two 128-bit polynomials
    // result is 256 bits before reduction
    let mut result = [0u8; 32];

    for i in 0..128 {
        if get_bit(a, i) == 1 {
            for j in 0..128 {
                if get_bit(b, j) == 1 {
                    flip_bit(&mut result, i + j);
                }
            }
        }
    }

    // reduce modulo P128 = x^128 + x^7 + x^2 + x + 1
    let mut i = 255;
    while i >= 128 {
        if get_bit(&result, i) == 1 {
            // x^i = x^(i-128) * (x^7 + x^2 + x + 1)
            flip_bit(&mut result, i - 128 + 7);
            flip_bit(&mut result, i - 128 + 2);
            flip_bit(&mut result, i - 128 + 1);
            flip_bit(&mut result, i - 128);
        }
        i -= 1;
    }

    // return lower 128 bits
    result[0..16].try_into().unwrap()
}

pub fn gf128_pow(base: &[u8; 16], pow_of: i32) -> [u8; 16] {
    if pow_of == 0 {
        return [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    }
    if pow_of == 1 {
        return *base;
    }
    let mut res = *base;
    for _ in 2..(pow_of + 1) {      // range inclusive
        res = gf128_mul(&res, base);
    }
    res
}

#[hax_lib::requires(i >> 3 < a.len())]
fn get_bit(a: &[u8], i: usize) -> u8 {
    (a[i >> 3] >> (math::bitand_mod(i as u8, 7))) & 1    // where 7 = 8 - 1 (bitand instead of mod trick
}

fn flip_bit(a: &mut [u8], i: usize) {
    a[i >> 3] ^= 1 << (math::bitand_mod(i as u8, 7));    // where 7 = 8 - 1 (bitand instead of mod trick
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