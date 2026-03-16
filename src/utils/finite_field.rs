use crate::utils::math;
use hax_lib::Int;
use hax_lib::int::*;

#[hax_lib::include]
pub struct Field {
    pub p: Int
}

#[hax_lib::include]
#[hax_lib::attributes]
impl Field {

    #[hax_lib::requires(x < self.p
                        && y < self.p
                        && self.p > 0.to_int())]
    #[hax_lib::ensures(|result| result == (x + y).rem_euclid(self.p))]
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
    #[hax_lib::ensures(|result| result == (x * y).rem_euclid(self.p))]
    pub fn multiplication(&self, x: Int, y: Int) -> Int {
        (x * y).rem_euclid(self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x > 0.to_int()
                        && self.p > 0.to_int()
                        && self.p < (i128::MAX / 2).to_int())]
    #[hax_lib::ensures(|result| result < self.p)]
    // Burde vi have result * x == 1?
    pub fn multiplicative_inverse(&self, x: Int) -> Int {

        #[hax_lib::requires(a > 0.to_int()
                    && a < (i128::MAX / 2).to_int()
                    && b >= 0.to_int()
                    && b < (i128::MAX / 2).to_int())]
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
                        && x.len() == y.len()
                        //&& hax_lib::forall(|i: usize| hax_lib::implies(i < y.len(), y[i] > 0.to_int() && y[i] < self.p))
                        && check_less_than_vec(x, self.p)
                        && check_less_than_vec(y, self.p))]
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
                        //&& hax_lib::forall(|i: usize| hax_lib::implies(i < y.len(), y[i] > 0.to_int() && y[i] < self.p))
                        && check_less_than_vec(x, self.p)
                        && check_less_than_vec(y, self.p))]
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
                        //&& hax_lib::forall(|i: usize| hax_lib::implies(i < y.len(), y[i] > 0.to_int() && y[i] < self.p))
                        && check_less_than_vec(x, self.p)
                        && alpha < self.p)]
    #[hax_lib::ensures(|result| result.len() == x.len())]
    pub fn vector_scalar(&self, x: Vec<Int>, alpha: Int) -> Vec<Int> {
        let mut combined = Vec::with_capacity(x.len());

        for i in 0..x.len() {
            hax_lib::loop_invariant!(|i: usize| {
                combined.len() == i
                && i <= x.len()

            });
            hax_lib::assume!(x[i] < self.p);
            combined.push(self.multiplication(x[i], alpha));
        }

        combined
    }

}

#[hax_lib::include]
#[hax_lib::requires(v.len() > 0)]
fn check_less_than_vec(v: Vec<Int>, x: Int) -> bool {
    for i in 0..v.len() {
        if v[i] >= x {
            return false;
        }
    }
    //hax_lib::assert_prop!(hax_lib::forall(|i: usize| hax_lib::implies(i < v.len(), v[i] > 0.to_int() && v[i] < x)));
    true
}

