
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