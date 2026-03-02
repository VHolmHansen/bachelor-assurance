use crate::utils::math;

pub struct Field {
    pub p: i128
}

impl Field {

    // fn run

    #[hax_lib::requires(x < self.p
                        && x >= 0
                        && y < self.p
                        && y >= 0
                        && self.p > 0
                        && self.p <= i128::MAX)]
    #[hax_lib::ensures(|result| result == math::modulo(x + y, self.p))]
    fn addition(self, x: i128, y: i128) -> i128 {
        let x_plus_y = x + y;
        hax_lib::assert!(x_plus_y <= i128::MAX);
        hax_lib::assert!(y >= i128::MIN);
        hax_lib::assert!(self.p <= i128::MAX);
        hax_lib::assert!(self.p > 0);

        math::modulo(x_plus_y, self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x >= 0
                        && self.p > 0)]
    #[hax_lib::ensures(|result| math::modulo(x + result, self.p) == 0
                        && result < self.p
                        && result >= 0)]
    fn additive_inverse(self, x: i128) -> i128 {
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
    fn multiplication(self, x: i128, y: i128) -> i128 {
        math::modulo(x * y, self.p)
    }

    #[hax_lib::requires(x < self.p
                        && x > 0
                        && self.p > 0)]
    #[hax_lib::ensures(|result| result * x = 1
                        && result < self.p
                        && result > 0)]
    pub fn multiplicative_inverse(self, x: i128) -> i128 {
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
}




