use crate::utils::types::{State, Matrix};
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



#[hax_lib::requires(a.len() > 0
                    && a[0].len() > 0
                    && b.len() > 0
                    && b[0].len() > 0)]
#[hax_lib::ensures(|result| result.len() == a.len()
                    && result[0].len() == b.len())]
pub fn gf28_matrix_multiplication(a: Matrix<u8>, b: State) -> Matrix<u8> {
    assert!(a.len() > 0);
    let rows = a.len();
    let columns = b[0].len();
    let n = b.len();

    let mut res: Matrix<u8> = vec![vec![0; columns]; rows];
    assert!(n > 0);
    assert!(res.len() == a.len());
    assert!(res.len() > 0);
    assert!(res[0].len() == b.len());

    for i in 0..rows {
        hax_lib::loop_invariant!(|i: usize| {
            i < res.len()
            && res.len() > 0
            && res[i].len() > 0
            && i < rows
            /*
            && a.len() > 0
            && b.len() > 0
            && i < a.len()

             */
        });
        assert!(res[i].len() > 0);
        hax_lib::assert!(i < a.len());
        hax_lib::assert!(i < res.len());
        for j in 0..columns {
            hax_lib::loop_invariant!(|j: usize| {
                i < res.len()
                && j < res[i].len()
                && j < columns
                && res.len() > 0
                && res[i].len() > 0
                /*
                && a.len() > 0
                && b.len() > 0
                && j < res[i].len()
                && i < a.len()
                && j < b[0].len()

                 */
            });
            hax_lib::assert!(i < a.len());
            hax_lib::assert!(i < res.len() && j < res[i].len());
            let mut temp = 0u8;
            for k in 0..n {
                hax_lib::loop_invariant!(|k: usize| {

                    res.len() > 0
                    && i < res.len()
                    && res[i].len() > 0

                    && a.len() > 0
                    && a[i].len() > 0
                    && b.len() > 0
                    && k < n
                    && k < a[i].len()
                    && k < b.len()
                    /*
                    && a.len() > 0
                    && b.len() > 0
                    && j < res[i].len()
                    && k < res.len()
                    && k < res[i].len()
                    && i < a.len()
                    && k < a[i].len()
                    && k < b.len()
                    && j < b[k].len()

                     */
                });
                //let old_len = res.len();
                hax_lib::assert!(i < res.len() && j < res[i].len());

                hax_lib::assert!(i < a.len() && k < a[i].len() && k < b.len() && j < b[k].len());

                temp ^= gf28_multiply(a[i][k], b[k][j]); // can be optimized with bit trickery

                hax_lib::assert!(res.len() == rows && res.len() == a.len());
                hax_lib::assert!(res[i].len() == columns && res[i].len() == b.len());
            }

            res[i][j] = temp;
        }
    }

    res
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
    for i in (128..256).rev() {
        if get_bit(&result, i) == 1 {
            // x^i = x^(i-128) * (x^7 + x^2 + x + 1)
            flip_bit(&mut result, i - 128 + 7);
            flip_bit(&mut result, i - 128 + 2);
            flip_bit(&mut result, i - 128 + 1);
            flip_bit(&mut result, i - 128);
        }
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
    for _ in 2..=pow_of {
        res = gf128_mul(&res, base);
    }
    res
}

fn get_bit(a: &[u8], i: usize) -> u8 {
    (a[i / 8] >> (i % 8)) & 1
}

fn flip_bit(a: &mut [u8], i: usize) {
    a[i / 8] ^= 1 << (i % 8);
}