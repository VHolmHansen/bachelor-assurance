use crate::utils::types::{State, Word, Matrix, MatrixWrapper};
use crate::utils::hax_helper_functions::*;
#[hax_lib::requires(a <= u8::MAX
                    && b <= u8::MAX
                    && a >= 0
                    && b >= 0)]
#[hax_lib::ensures(|result| result <= u8::MAX)]
pub fn gf28_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    let old_a = a;
    let old_b = b;
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
    //println!("result for {:?} mul {:?} = {:?}", old_a, old_b, result);
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

    let result = gf28_pow(a, 254);
    assert!(result > 0);
    result
}

#[hax_lib::opaque]
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




#[hax_lib::requires(ensure_non_zero_matrix(a)
                    && ensure_non_zero_matrix(b))]
#[hax_lib::ensures(|result| result.len() == a.len()
                    && result[0].len() == b.len())]
pub fn gf28_matrix_multiplication(a: Matrix<u8>, b: Matrix<u8>) -> Matrix<u8> {
    let mut res: Matrix<u8> = vec![vec![0; b[0].len()]; a.len()]; // new matrix with proportions according to rows of a and columns of b
    for i in 0..a.len() {   // rows
        hax_lib::loop_invariant!(|i: usize| {
            ensure_inbounds_indexing(vec![i],
                vec![res.len(), a.len(), res[i].len()])
        });
        for j in 0..b[0].len() {    // columns
            hax_lib::loop_invariant!(|j: usize| {
                ensure_inbounds_indexing(vec![i, j],
                    vec![res.len(), res[i].len()])
            });
            let mut temp = 0u8;     // might not be needed
            for k in 0..b.len() {
                hax_lib::loop_invariant!(|k: usize| {
                    ensure_inbounds_indexing(vec![i, j, k],
                        vec![res.len(), a.len(), b.len()])
                });
                temp ^= gf28_multiply(a[i][k], b[k][j]); // can be optimized with bit trickery
            }
            res[i][j] = temp;
        }
    }
    res
}