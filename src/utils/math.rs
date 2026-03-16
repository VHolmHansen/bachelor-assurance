/*
#[hax_lib::include]
#[hax_lib::requires(y > 0)]
#[hax_lib::ensures(|result| result >= 0 && result < y)]
pub fn modulo(x: i128, y: i128) -> i128 {
    let res = x % y;
    if res < 0 {
        res + y
    } else {
        res
    }
}

#[hax_lib::include]
#[hax_lib::requires(
x >= 0
&& y >= 0
&& x < i128::MAX
&& y < (i128::MAX - x)
)]
#[hax_lib::ensures(|result| result >= 0 && result >= x && result >= y)]
pub fn addition(x: i128, y: i128) -> i128 {
    x + y
}

#[hax_lib::include]
#[hax_lib::requires(
x < i128::MAX
&& y >= 0
&& x >= y)]
#[hax_lib::ensures(|result| result >= 0 && result <= x)]
pub fn subtraction(x: i128, y: i128) -> i128 {
    x - y
}

#[hax_lib::include]
#[hax_lib::requires(
x < i128::MAX / 2
&& x > 0
&& y >= 0
&& y < i128::MAX / x)]
#[hax_lib::ensures(|result| result >= 0 && result < i128::MAX)]
pub fn multiplication(x: i128, y: i128) -> i128 {
    x * y
}
*/
