
#[hax_lib::requires(x <= i128::MAX
                    && x >= i128::MIN
                    && y <= i128::MAX
                    && y > 0)]
#[hax_lib::ensures(|result| result == ((x % y) + y) % y)]
pub fn modulo(x: i128, y: i128) -> i128 {
    ((x % y) + y) % y
}