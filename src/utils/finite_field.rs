use std::ops::Add;
use crate::utils::math;
use hax_lib::{assume, Int, ToProp};
use hax_lib::int::*;
use crate::utils::types::Matrix;

#[hax_lib::include]
pub struct Field {
    pub p: Int
}



pub struct MatrixStruct {
    pub field: Field
}

#[hax_lib::attributes]
//#[hax_lib::requires(p > 0.to_int())]
//#[hax_lib::ensures(|result| result.p > 0.to_int())]
pub const fn new(p: Int) -> Field {
    Field {p}
}


#[hax_lib::include]
#[hax_lib::attributes]
impl Field {

    #[hax_lib::requires(x < self.p
                        && y < self.p
                        && self.p > 0.to_int())]
    #[hax_lib::ensures(|result| result == (x + y).rem_euclid(self.p)
                        && result < self.p)]
    pub fn addition(&self, x: Int, y: Int) -> Int {
        (x + y).rem_euclid(self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x >= 0.to_int()
                        && self.p > 0.to_int())]
    #[hax_lib::ensures(|result| result >= 0.to_int()
                        && result < self.p
                        && (x + result).rem_euclid(self.p) == 0.to_int())]
    pub fn additive_inverse(&self, x: Int) -> Int {
        (self.p - x).rem_euclid(self.p)
    }

    #[hax_lib::requires(x < self.p
                        && y < self.p
                        && self.p > 0.to_int())]
    #[hax_lib::ensures(|result| result == (x * y).rem_euclid(self.p)
                        && result < self.p
                        )]
    pub fn multiplication(&self, x: Int, y: Int) -> Int {
        (x * y).rem_euclid(self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x > 0.to_int()
                        && self.p > 0.to_int())]
    #[hax_lib::ensures(|result| result < self.p)]
    // Burde vi have result * x == 1?
    pub fn multiplicative_inverse(&self, x: Int) -> Int {

        #[hax_lib::requires(a > 0.to_int()
                            && b >= 0.to_int())]
        #[hax_lib::decreases(b)]
        #[hax_lib::ensures(|(gcd, x, y)| gcd > 0.to_int())]
        fn egcd(a: Int, b: Int) -> (Int, Int, Int) {
            if b == 0.to_int() {
                (a, 1.to_int(), 0.to_int())
            } else {
                assert!(a.rem_euclid(b) < b);
                let (gcd, x, y) = egcd(b, a.rem_euclid(b));
                //hax_lib::assume!(gcd == 1.to_int());
                (gcd, y, x - ( a / b) * y)
            }
        }

        let (gcd, x, _) = egcd(x.rem_euclid(self.p), self.p);
        //assert_eq!(gcd, 1.to_int());

        x.rem_euclid(self.p)
    }

    #[hax_lib::requires(x.len() > 0
                        && self.p > 0.to_int()
                        && x.len() < 29999
                        && x.len() == y.len()
                        && check_less_than_vec(x, self.p)
                        && check_less_than_vec(y, self.p)
                        )]
    #[hax_lib::ensures(|result| result.len() == x.len())]
    pub fn vector_multiply(&self, x: Vec<Int>, y: Vec<Int>) -> Vec<Int> {
        let mut combined = Vec::with_capacity(x.len());

        for i in 0..x.len() {
            hax_lib::loop_invariant!(|i: usize| {
                combined.len() == i
                && i <= x.len()

            });
            hax_lib::assume!(x[i] < self.p);
            hax_lib::assume!(y[i] < self.p);
            combined.push(self.multiplication(x[i], y[i]));
        }

        combined
    }

    #[hax_lib::requires(x.len() > 0
                        && self.p > 0.to_int()
                        && x.len() == y.len()
                        && check_less_than_vec(x, self.p)
                        && check_less_than_vec(y, self.p)
                        )]
    #[hax_lib::ensures(|result| result.len() == x.len())]
    pub fn vector_add(&self, x: Vec<Int>, y: Vec<Int>) -> Vec<Int> {
        let mut combined = Vec::with_capacity(x.len());

        for i in 0..x.len() {
            hax_lib::loop_invariant!(|i: usize| {
                combined.len() == i
                && i <= x.len()

            });
            hax_lib::assume!(x[i] < self.p);
            hax_lib::assume!(y[i] < self.p);
            combined.push(self.addition(x[i], y[i]));
        }
        combined
    }

    #[hax_lib::requires(x.len() > 0
                        && self.p > 0.to_int()
                        && check_less_than_vec(x, self.p)
                        && alpha < self.p)]
    #[hax_lib::ensures(|result| result.len() > 0
                        && result.len() == x.len())]
    pub fn vector_scalar(&self, x: Vec<Int>, alpha: Int) -> Vec<Int> {
        let mut combined = Vec::with_capacity(x.len());

        for i in 0..x.len() {
            hax_lib::loop_invariant!(|i: usize| {
                combined.len() == i
                && i <= x.len()
            });
            hax_lib::assume!(x[i] < self.p);
            combined.push(self.multiplication(x[i], alpha));
            hax_lib::assert!(combined[i] < self.p);
        }

        combined
    }
}

impl MatrixStruct {
    pub fn matrix_addition(&self, a: Matrix<Int>, b: Matrix<Int>) -> Matrix<Int> {
        let rows = a.len();
        let columns = b[0].len();
        let k = b.len();

        let mut res: Matrix<Int> = vec![vec![0.to_int(); columns]; rows];

        for i in 0..rows {
            for j in 0..columns {
                res[i][j] = self.field.addition(a[i][j], b[j][k]);
            }
        }

        res
    }

    pub fn matrix_multiplication(&self, a: Matrix<Int>, b: Matrix<Int>) -> Matrix<Int> {
        let rows = a.len();
        let columns = b[0].len();
        let k = b.len();

        let mut res: Matrix<Int> = vec![vec![0.to_int(); columns]; rows];

        for i in 0..rows {
            for j in 0..columns {
                for k in 0..k {
                    res[i][j] = self.field.addition(res[i][j], (self.field.multiplication(a[i][k], b[k][j])));
                }
            }
        }

        res
    }

    pub fn matrix_modulo(&self, input: Matrix<Int>) -> Matrix<Int> {
        let mut m = input.clone();
        for i in 0..input.len() {
            for j in 0..input[i].len() {
                m[i][j] = input[i][j].rem_euclid(self.field.p);
            }
        }
        m
    }
}

#[hax_lib::include]
#[hax_lib::requires(v.len() > 0
                    && x > 0.to_int())]
#[hax_lib::ensures(|result| (0..v.len()).fold(true, |acc, i| {
                            hax_lib::assume!(i < v.len());
                            acc && v[i] < x})
)]
pub fn check_less_than_vec(v: Vec<Int>, x: Int) -> bool {
    (0..v.len()).fold(true, |acc, i| {
        hax_lib::assume!(i < v.len());
        acc && v[i] < x})
}




