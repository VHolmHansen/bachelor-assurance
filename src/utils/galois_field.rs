use crate::utils::types::{State, Word, Matrix, MatrixWrapper, BoundedU64};
use crate::utils::hax_helper_functions::*;
use hax_lib as hax;
use hax_lib::{Prop as prop, Refinement};
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


// TODO: Transpose for safe indexing fix?
/*
#[hax_lib::requires(prop::from(!a.is_empty() && !b.is_empty())
                    .and(hax::forall(|i: usize| hax::implies( i < a.len(), !a[i].is_empty())))
                    .and(hax::forall(|i: usize| hax::implies( i < b.len(), !b[i].is_empty())))
                    .and(ensure_non_zero_matrix(a)
                    && ensure_non_zero_matrix(b)))]

 */
#[hax_lib::requires(prop::from(!a.is_empty() && !b.is_empty())

                    )]
#[hax_lib::ensures(|result| prop::from(!result.is_empty()
                    && result.len() == a.len())
                    .and(hax::forall(
                    |i: usize| i >= result.len() || result[i].len() == b.len()))
                    )]
pub fn gf28_matrix_multiplication(a: Matrix<u8>, b: Matrix<u8>) -> Matrix<u8> {
    //let a: Matrix<u8> = a.get();
    //let b: Matrix<u8> = hax::Refinement::get(b);
    let mut res: Matrix<u8> = vec![vec![0; b[0].len()]; a.len()]; // new matrix with proportions according to rows of a and columns of b
    assert_eq!(res.len(), a.len());
    //let a_clone: Matrix<u8> = a.clone();
    let v = vec![0, 1, 2];

    //let nz_a: MatrixWrapper<u8> = hax_lib::RefineAs::into_checked(a_clone as Matrix<u8>);
    //hax::assert_prop!(<MatrixWrapper<u8> as hax::Refinement>::invariant(a.clone()));
    //let nz_b: MatrixWrapper<u8> = hax_lib::RefineAs::into_checked(b.clone());
    //let nz_res: MatrixWrapper<u8> = hax_lib::RefineAs::into_checked(res.clone());
    //let y: BoundedU64<0, 100> = hax_lib::RefineAs::into_checked(v.len() as u64);
    //let z: macro::NewTypeAsRefinement = hax_lib::
    //let prop = hax::Refinement::invariant(142);
    //hax::assert_prop!(prop);
    let lengths = vec![res.len(), a.len(), b.len()];
    //assert_eq!(res.len(), hax_lib::Refinement::get(nz_a.cloned()).len());
    for i in 0..a.len() {   // rows
        hax::loop_invariant!(|i: usize| i <= a.len() && res.len() == a.len());
        let mut inner_lengths = lengths.clone();
        assert_eq!(res.len(), a.len());
        inner_lengths.push(res[i].len());
        let indices = vec![i];
        //hax::assert_prop!(hax::forall(|i: usize| hax::implies(i < b.len(), {let len = b[0].len(); b[i].len() == len})));
        for j in 0..b[0].len() {    // columns
            hax::loop_invariant!(|j: usize| j <= b[0].len()
            );
            let mut temp = 0u8;     // might not be needed
            let indices = vec![i, j];

            for k in 0..b.len() {
                hax::loop_invariant!(|k: usize|
                    k <= b.len()
                    && j <= b[k].len()
                    && k <= a[i].len());

                //hax::assert!(i < res.len());
                let indices = vec![i, j, k];

                //ensure_inbounds_indexing(vec![i, j, k], vec![res.len(), a.len(), b.len(), res[i].len()]);
                temp ^= gf28_multiply(a[i][k], b[k][j]); // can be optimized with bit trickery
            }
            res[i][j] = temp;
        }
    }
    res
}