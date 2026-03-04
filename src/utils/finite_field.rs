use crate::utils::math;

#[hax_lib::include]
pub struct Field {
    pub p: i128
}

#[hax_lib::attributes]
impl Field {

    #[hax_lib::requires(x < self.p
                        && x >= 0
                        && x < self.p
                        && y < self.p
                        && y >= 0
                        && self.p > 0
                        && self.p < i128::MAX / 2)]
    #[hax_lib::ensures(|result| result == math::modulo(x + y, self.p))]
    pub fn addition(&self, x: i128, y: i128) -> i128 {
        math::modulo(x + y, self.p)
    }

    #[hax_lib::include]
    #[hax_lib::requires(x < self.p
                        && x >= 0
                        && self.p > 0
                        && self.p < i128::MAX / 2)]
    #[hax_lib::ensures(|result| result >= 0
                        && result < self.p
                        && math::modulo(x + result, self.p) == 0)]
    pub fn additive_inverse(&self, x: i128) -> i128 {
        math::modulo(self.p - x, self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x > 0
                        && y < self.p
                        && y > 0
                        && self.p > 0)]
    #[hax_lib::ensures(|result| result == math::modulo(x * y, self.p)
                        && result < self.p
                        && result >= 0)]
    pub fn multiplication(&self, x: i128, y: i128) -> i128 {
        math::modulo(x * y, self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x > 0
                        && self.p > 0)]
    #[hax_lib::ensures(|result| result * x == 1
                        && result < self.p
                        && result > 0)]
    pub fn multiplicative_inverse(&self, x: i128) -> i128 {
        fn egcd(a: i128, b: i128) -> (i128, i128, i128) {
            if b == 0 {
                (a, 1, 0)
            } else {
                let (gcd, x, y) = egcd(b, a % b);
                (gcd, y, x - ( a / b) * y)
            }
        }

        let (gcd, x, _) = egcd(math::modulo(x, self.p), self.p);

        hax_lib::assert!(gcd == 1);

        math::modulo(x, self.p)
    }

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
}




