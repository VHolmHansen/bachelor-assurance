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
                        && x >= 0.to_int()
                        && x < self.p
                        && y < self.p
                        && y >= 0.to_int()
                        && self.p > 0.to_int()
                        && self.p < (i128::MAX / 2).to_int())]
    #[hax_lib::ensures(|result| result == (x + y).rem_euclid(self.p))]
    pub fn addition(&self, x: Int, y: Int) -> Int {
        (x + y).rem_euclid(self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x >= 0.to_int()
                        && self.p > 0.to_int()
                        && self.p < (i128::MAX / 2).to_int())]
    #[hax_lib::ensures(|result| result >= 0.to_int()
                        && result < self.p
                        && (x + result).rem_euclid(self.p) == 0.to_int())]
    pub fn additive_inverse(&self, x: Int) -> Int {
        (self.p - x).rem_euclid(self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x > 0.to_int()
                        && y < self.p
                        && y < (i128::MAX.to_int() / x)
                        && y > 0.to_int()
                        && self.p > 0.to_int()
                        && self.p < (i128::MAX / 2).to_int())]
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
                hax_lib::assert!(a.rem_euclid(b) < b);
                let (gcd, x, y) = egcd(b, a.rem_euclid(b));
                (gcd, y, x - ( a / b) * y)
            }
        }

        let (gcd, x, _) = egcd(x.rem_euclid(self.p), self.p);

        //hax_lib::assert!(gcd == 1.to_int());

        x.rem_euclid(self.p)
    }

    /*

    pub fn vector_multiply(&self, x: Vec<i128>, y: Vec<i128>) -> Vec<i128> {
        let combined: Vec<i128> = x.iter()
            .zip(y.iter())
            .map(|(a, b)| self.multiplication(*a, *b))
            .collect();
        combined
    }

    pub fn vector_add(&self, x: Vec<i128>, y: Vec<i128>) -> Vec<i128> {
        let combined: Vec<i128> = x.iter()
            .zip(y.iter())
            .map(|(a, b)| self.addition(*a, *b))
            .collect();
        combined
    }

    pub fn vector_scalar(&self, x: Vec<i128>, alpha: i128) -> Vec<i128> {
        x.iter().map(|x| self.multiplication(*x, alpha)).collect()
    }

     */
}




