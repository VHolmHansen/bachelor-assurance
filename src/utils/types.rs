#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::galois_field::gf128_mul;
use crate::utils::math::xor_arrays;

use crate::utils::constants::{nst, nk, k_0, k_1, k_0_pow, k_1_pow, ell};

pub type Word = [u8; 4];
pub type Matrix<T, const N: usize, const M: usize> = [[T; M]; N];

pub type State = [[u8; nst]; nk];
pub type sized_array_16<const size: usize> = [[u8;16];size];
pub type sized_array_32<const size: usize> = [[u8;32];size];
pub type sized_array_234<const size: usize> = [[u8;ell];size];

pub type sized_option_array<const size: usize> = [Option<[u8;16]>;size];

pub const value_of_one_in_bytes: [u8; 16] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const value_of_two_in_bytes: [u8; 16] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const value_of_three_in_bytes: [u8; 16] = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Clone, Copy, Debug)]
pub enum sized_array_for_cop {
    sized_array_1(sized_array_16<k_0>),
    sized_array_2(sized_array_16<k_1>)
}
#[derive(Clone, Copy)]
pub enum sized_array_for_coms {
    sized_array_1(sized_array_32<k_0_pow>),
    sized_array_2(sized_array_32<k_1_pow>)
}
#[derive(Clone, Copy)]
pub enum sized_array_for_sds {
    sized_array_1(sized_array_16<k_0_pow>),
    sized_array_2(sized_array_16<k_1_pow>)
}
#[derive(Clone,Copy)]
pub enum sized_array_for_q_v{
    sized_array_1(sized_array_234<k_0>),
    sized_array_2(sized_array_234<k_1>)
}

#[hax_lib::attributes]
impl sized_array_for_q_v {

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        match self {
            sized_array_for_q_v::sized_array_1(_) => 12,
            sized_array_for_q_v::sized_array_2(_) => 11,
        }
    }
    #[hax_lib::requires(index < self.len())]
    pub fn get(&self, index: usize) -> &[u8; ell] {
        match self {
            sized_array_for_q_v::sized_array_1(arr) => &arr[index],
            sized_array_for_q_v::sized_array_2(arr) => &arr[index],
        }
    }

    #[hax_lib::requires(index < self.len())]
    pub fn set(self, index: usize, value: [u8; ell]) -> Self {
        match self {
            sized_array_for_q_v::sized_array_1(mut arr) => {arr[index] = value; sized_array_for_q_v::sized_array_1(arr)},
            sized_array_for_q_v::sized_array_2(mut arr) => {arr[index] = value; sized_array_for_q_v::sized_array_2(arr)},
        }
    }
    pub fn get_all(&self) -> &[[u8; ell]] {
        match self {
            sized_array_for_q_v::sized_array_1(arr) => arr,
            sized_array_for_q_v::sized_array_2(arr) => arr,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Log2Number {
    zero,
    one,
    two,
    four,
    eight,
    sixteen,
    thirtytwo,
    sixtyfour,
    onehundredandtwentyeight,
    twohundredandfiftysix,
    fivehundredandtwelve,
    onethousandandtwentyfour,
    twothousandsandfortyeight,
    fourthousandsandninetysix
}

#[hax_lib::attributes]
impl Log2Number {
    #[hax_lib::ensures(|result| result == 0 || result == 1 || result == 2 || result == 4 || result == 8
                        || result == 16 || result == 32 || result == 64 || result == 128
                        || result == 256 || result == 512 || result == 1024 || result == 2048 || result == 4096)]
    pub fn value(self) -> usize {
        match self {
            Self::zero => 0,
            Self::one => 1,
            Self::two => 2,
            Self::four => 4,
            Self::eight => 8,
            Self::sixteen => 16,
            Self::thirtytwo => 32,
            Self::sixtyfour => 64,
            Self::onehundredandtwentyeight => 128,
            Self::twohundredandfiftysix => 256,
            Self::fivehundredandtwelve => 512,
            Self::onethousandandtwentyfour => 1024,
            Self::twothousandsandfortyeight => 2048,
            Self::fourthousandsandninetysix => 4096,
        }
    }

    #[hax_lib::requires(n == 0 || n == 1 || n == 2 || n == 4 || n == 8
                        || n == 16 || n == 32 || n == 64 || n == 128
                        || n == 256 || n == 512 || n == 1024 || n == 2048 || n == 4096)]
    #[hax_lib::ensures(|result| result == Log2Number::zero || result == Log2Number::one || result == Log2Number::two || result == Log2Number::four || result == Log2Number::eight
                        || result == Log2Number::sixteen || result == Log2Number::thirtytwo || result == Log2Number::sixtyfour || result == Log2Number::onehundredandtwentyeight
                        || result == Log2Number::twohundredandfiftysix || result == Log2Number::fivehundredandtwelve
                        || result == Log2Number::onethousandandtwentyfour || result == Log2Number::twothousandsandfortyeight || result == Log2Number::fourthousandsandninetysix)]
    pub fn wrap(n: usize) -> Log2Number {
        match n {
            0 => Self::zero,
            1 => Self::one,
            2 => Self::two,
            4 => Self::four,
            8 => Self::eight,
            16 => Self::sixteen,
            32 => Self::thirtytwo,
            64 => Self::sixtyfour,
            128 => Self::onehundredandtwentyeight,
            256 => Self::twohundredandfiftysix,
            512 => Self::fivehundredandtwelve,
            1024 => Self::onethousandandtwentyfour,
            2048 => Self::twothousandsandfortyeight,
            4096 => Self::fourthousandsandninetysix,
            _ => panic!("Invalid log2 number")
        }
    }

    #[hax_lib::requires(self.value() == 0 || self.value() == 1 || self.value() == 2 || self.value() == 4 || self.value() == 8
    || self.value() == 16 || self.value() == 32 || self.value() == 64 || self.value() == 128
    || self.value() == 256 || self.value() == 512 || self.value() == 1024 || self.value() == 2048 || self.value() == 4096)]
    #[hax_lib::ensures(|result| result == Log2Number::zero || result == Log2Number::one || result == Log2Number::two || result == Log2Number::four || result == Log2Number::eight
                                || result == Log2Number::sixteen || result == Log2Number::thirtytwo || result == Log2Number::sixtyfour || result == Log2Number::onehundredandtwentyeight
                                || result == Log2Number::twohundredandfiftysix || result == Log2Number::fivehundredandtwelve || result == Log2Number::onethousandandtwentyfour || result == Log2Number::twothousandsandfortyeight || result == Log2Number::fourthousandsandninetysix)]
    pub fn log_reduce(&mut self) -> Self {
        Self::wrap(self.value() >> 1)
    }

    /*
    #[hax_lib::requires(n == 1 || n == 2 || n == 4 || n == 8
                        || n == 16 || n == 32 || n == 64 || n == 128
                        || n == 256 || n == 512 || n == 1024 || n == 2048)]
    #[hax_lib::ensures(|result| n == 1 || n == 2 || n == 4 || n == 8
                        || n == 16 || n == 32 || n == 64 || n == 128
                        || n == 256 || n == 512 || n == 1024 || n == 2048)]
    pub fn is_log2_number(n: usize) -> bool{
        match n {
            1 => true,
            2 => true,
            4 => true,
            8 => true,
            16 => true,
            32 => true,
            64 => true,
            128 => true,
            256 => true,
            512 => true,
            1024 => true,
            2048 => true,
            _ => false
        }
    }
     */


}



pub trait ret_value {
    type Elem: Copy + XorHelper + AlphaMul;
    const dummy_value : Self::Elem;
    const value_of_one : Self::Elem;
    const value_of_two : Self::Elem;
    const value_of_three : Self::Elem;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem];
    fn get_element(&self, x : usize) -> Self::Elem;
    fn set_element(&mut self, index : usize, value : &Self::Elem);
    fn new_with_size(value: Self::Elem) -> Self;
    //fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16];
    fn turn_array_to_T(x : &[Self::Elem]) -> Self;
}

#[hax_lib::attributes]
impl<const N: usize> ret_value for [[u8;16]; N] {
    type Elem = [u8;16];
    const dummy_value : Self::Elem = [0;16];
    const value_of_one : Self::Elem = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const value_of_two : Self::Elem = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const value_of_three : Self::Elem = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    #[hax_lib::requires(x < y && y < self.len())]
    fn get_slice(&self, x : usize, y: usize) -> &[[u8; 16]] {
        &self[x..y]
    }
    #[hax_lib::requires(x < self.len())]
    fn get_element(&self, x : usize) -> [u8;16] {
        self[x]
    }
    #[hax_lib::requires(index < self.len())]
    fn set_element(&mut self, index : usize, value : &[u8; 16]) {
        self[index] = *value;
    }
    fn new_with_size(value: Self::Elem) -> Self {
        [value; N]
    }
    #[hax_lib::requires(x.len() == N)]
    fn turn_array_to_T(x : &[[u8; 16]]) -> [[u8; 16]; N] {
        x.try_into().unwrap()
    }

}

#[hax_lib::attributes]
impl<const N: usize> ret_value for [u8; N] {
    type Elem = u8;
    const dummy_value : Self::Elem = 0;
    const value_of_one : Self::Elem = 1;
    const value_of_two: Self::Elem = 2;
    const value_of_three : Self::Elem = 3;
    #[hax_lib::requires(x < y && y < self.len())]
    fn get_slice(&self, x : usize, y: usize) -> &[u8] {
        &self[x..y]
    }
    #[hax_lib::requires(x < self.len())]
    fn get_element(&self, x : usize) -> u8 {
        self[x]
    }
    #[hax_lib::requires(index < self.len())]
    fn set_element(&mut self, index : usize, value : &u8) {
        self[index] = *value;
    }
    fn new_with_size(value: Self::Elem) -> Self {
        [value; N]
    }
    #[hax_lib::requires(x.len() == N)]
    fn turn_array_to_T(x : &[u8]) -> [u8; N] {
        x.try_into().unwrap()
    }

}
/*
pub trait RetElem:  {}

impl RetElem for u8 {}
impl RetElem for [u8; 16] {}

 */

pub trait XorHelper: Sized {
    fn xor_array(x : &Self, y : &Self) -> Self;
    fn xor_two_array(x: &[Self], y: &[Self]) -> [Self; 8];
}

#[hax_lib::attributes]
impl XorHelper for u8 {
    fn xor_array(x : &u8, y : &u8) -> u8{
        x ^ y
    }
    #[hax_lib::requires(x.len() >= 8 && y.len() >= 8)]
    fn xor_two_array(x : &[u8], y : &[u8]) -> [u8; 8] {
        let mut res: [u8; 8] = [0u8; 8];
        for i in 0..8 {
            hax_lib::loop_invariant!(|i: usize| {
                i <= 8
            });
            let value_to_push = x[i] ^ y[i];
            //let value_to_push: u8 = xor_helper(&x[i], &y[i]);
            res[i] = value_to_push;
        }
        res
    }
}
#[hax_lib::attributes]
impl XorHelper for [u8; 16] {
    fn xor_array(x : &[u8;16], y : &[u8;16]) -> [u8;16]{
        xor_arrays::<16>(x, y)
    }

    #[hax_lib::opaque]
    #[hax_lib::requires(x.len() >= 8 && y.len() >= 8)]
    fn xor_two_array(x : &[[u8; 16]], y : &[[u8; 16]]) -> [[u8; 16]; 8] {
        let mut res: [[u8;16]; 8] = [[0u8; 16]; 8];
        for i in 0..8usize {
            hax_lib::loop_invariant!(|i: usize| {
                i <= 8
            });
            let value_to_push: [u8; 16] = xor_arrays(&x[i], &y[i]);
            //let value_to_push: [u8; 16] = xor_helper(&x[i], &y[i]);
            res[i] = value_to_push;
        }
        res
    }
}
pub trait AlphaMul: Copy {
    fn mul_with_alpha(x : Self, alpha_val : [u8;16]) -> [u8;16];
}


impl AlphaMul for u8 {
    fn mul_with_alpha(x: u8, alpha_val: [u8; 16]) -> [u8; 16] {
        // x is a scalar bit (0 or 1)
        // result is either 0 or alpha_val
        if x == 0 {
            [0u8; 16]
        } else {
            alpha_val
        }
    }
}

impl AlphaMul for [u8; 16] {
    fn mul_with_alpha(x : Self, alpha_val : [u8;16]) -> [u8;16] {
        gf128_mul(&x, &alpha_val)
    }
}
#[derive(Clone, Copy)]
pub struct BytesArray<const N: usize>(pub [[u8; 16]; N]);
#[derive(Clone, Copy)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

/*
#[hax_lib::requires()]
pub fn bytes_array_wrap<const SIZE: usize>(arr: ByteOrBytesArray<SIZE>) -> BytesArray<SIZE> {
    let mut res: BytesArray<SIZE> = [BytesElem([0; 16]); SIZE];
    array::from_fn(|i: usize| res[i] = arr[i]);
    res
}
 */
#[derive(Clone, Copy)]
pub enum ByteOrBytesArray<const N: usize> {
    Byte(ByteArray<N>),
    Bytes(BytesArray<N>),
}

#[hax_lib::attributes]
impl<const N: usize> ByteOrBytesArray<N> {
    #[hax_lib::ensures(|result| matches!(x, result))]
    pub fn dummy(x: &ByteOrBytesElem) -> Self {
        match x {
            ByteOrBytesElem::Byte(_) => {let res = ByteOrBytesArray::Byte(ByteArray([0u8; N]));
                hax_lib::assert!(matches!(x, res)); res},
            ByteOrBytesElem::Bytes(_) => {let res = ByteOrBytesArray::Bytes(BytesArray([[0u8; 16]; N]));
                hax_lib::assert!(matches!(x, res)); res},
        }

    }

    #[hax_lib::ensures(|result| result.is_bytes())]
    pub fn zero_bytes() -> Self {
        ByteOrBytesArray::Bytes(BytesArray([[0u8; 16]; N]))
    }

    //TODO: Er den her nødvendig??
    #[hax_lib::ensures(|result| matches!(result, x))]
    pub fn ones(x: &Self) -> Self {
        match x {
            ByteOrBytesArray::Byte(_) => ByteOrBytesArray::Byte(ByteArray([1u8; N])),
            ByteOrBytesArray::Bytes(_) => ByteOrBytesArray::Bytes(BytesArray([[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; N]))
        }
    }

    #[hax_lib::ensures(|result| matches!(result, ByteOrBytesArray::Bytes(_)))]
    pub fn one_bytes() -> Self {
        ByteOrBytesArray::Bytes(BytesArray([[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; N]))
    }

    #[hax_lib::requires(N > 0 && ByteOrBytesArray::same_variant(x, y))]
    #[hax_lib::ensures(|result| matches!(result, x) && matches!(result, y))]
    pub fn xor_array(x : &ByteOrBytesArray<{ N }>, y : &ByteOrBytesArray<{ N }>) -> ByteOrBytesArray<{ N }> {
        match (x, y) {
            (ByteOrBytesArray::Byte(x), ByteOrBytesArray::Byte(y)) => {
                let mut res: [u8; N] = [0u8; N];
                for i in 0..N {
                    hax_lib::loop_invariant!(|i: usize| {
                        i <= N
                    });
                    res[i] = u8::xor_array(&x.0[i], &y.0[i])
                }
            ByteOrBytesArray::Byte(ByteArray(res))
            },
            (ByteOrBytesArray::Bytes(x), ByteOrBytesArray::Bytes(y)) => {
                let mut res: [[u8; 16]; N] = [[0u8; 16]; N];
                for i in 0..N {
                    hax_lib::loop_invariant!(|i: usize| {
                        i <= N
                    });
                    res[i] = <[u8; 16]>::xor_array(&x.0[i], &y.0[i])
                }
                ByteOrBytesArray::Bytes(BytesArray(res))
            }
            _ => panic!("type mismatch for xor_array")
        }
    }

    #[hax_lib::ensures(|result| result == (x.is_byte() == y.is_byte()))]
    pub fn same_variant<const M: usize>(x: &ByteOrBytesArray<N>, y: &ByteOrBytesArray<M>) -> bool {
        matches!(
            (x, y),
            (ByteOrBytesArray::Byte(_), ByteOrBytesArray::Byte(_))
            | (ByteOrBytesArray::Bytes(_), ByteOrBytesArray::Bytes(_))
        )
    }

    pub fn len(&self) -> usize { N }

    #[hax_lib::requires(self.is_byte())]
    pub fn get_byte(&self) -> [u8; N] {
        match self {
            ByteOrBytesArray::Byte(res) => res.0,
            _ => unreachable!()
        }
    }
    #[hax_lib::requires(self.is_bytes())]
    pub fn get_bytes(&self) -> [[u8; 16]; N] {
        match self {
            ByteOrBytesArray::Bytes(res) => res.0,
            _ => unreachable!()
        }
    }

    #[hax_lib::requires(from <= to && to <= N && SIZE == to - from)]
    #[hax_lib::ensures(|result| matches!(result, x))]
    pub fn get_slice<const SIZE: usize>(x: &ByteOrBytesArray<N>, from: usize, to: usize) -> ByteOrBytesArray<SIZE> {
        match x {
            ByteOrBytesArray::Byte(arr) => ByteOrBytesArray::Byte(ByteArray(arr.0[from..to].try_into().unwrap())),
            ByteOrBytesArray::Bytes(arr) => ByteOrBytesArray::Bytes(BytesArray(arr.0[from..to].try_into().unwrap()))
        }
    }

    #[hax_lib::requires(index < x.len())]
    #[hax_lib::ensures(|result| result.is_byte() == x.is_byte())]
    pub fn get_at_index(x: &Self, index: usize) -> ByteOrBytesElem {
        match x {
            ByteOrBytesArray::Byte(arr) => ByteOrBytesElem::Byte(ByteElem(arr.0[index])),
            ByteOrBytesArray::Bytes(arr) => ByteOrBytesElem::Bytes(BytesElem(arr.0[index]))
        }
    }

    #[hax_lib::requires(index < x.len() && (x.is_byte() == elem.is_byte()))]
    #[hax_lib::ensures(|result| ByteOrBytesArray::same_variant(&result, &x))]
    pub fn set_at_index(x: ByteOrBytesArray<N>, index: usize, elem: ByteOrBytesElem) -> ByteOrBytesArray<N> {
        match x {
            ByteOrBytesArray::Byte(mut arr) => {
                let v = ByteOrBytesElem::get_byte(&elem);
                arr.0[index] = v;
                ByteOrBytesArray::Byte(arr)
            }
            ByteOrBytesArray::Bytes(mut arr) => {
                let v = ByteOrBytesElem::get_bytes(&elem);
                arr.0[index] = v;
                ByteOrBytesArray::Bytes(arr)
            }
        }
    }

    #[hax_lib::ensures(|result| matches!(result, ByteOrBytesArray::Byte(_)))]
    pub fn from_byte_array(arr: [u8; N]) -> ByteOrBytesArray<{ N }> {
        ByteOrBytesArray::Byte(ByteArray(arr))
    }

    #[hax_lib::ensures(|result| matches!(result, ByteOrBytesArray::Bytes(_)))]
    pub fn from_bytes_array(arr: [[u8; 16]; N]) -> ByteOrBytesArray<{ N }> {
        ByteOrBytesArray::Bytes(BytesArray(arr))
    }

    pub fn is_byte(&self) -> bool {
        matches!(self, ByteOrBytesArray::Byte(_))
    }

    pub fn is_bytes(&self) -> bool {
        matches!(self, ByteOrBytesArray::Bytes(_))
    }
}

#[derive(Clone, Copy)]
pub enum ByteOrBytesElem {
    Byte(ByteElem),
    Bytes(BytesElem),
}
#[derive(Clone, Copy)]
pub struct ByteElem(pub u8);
#[derive(Clone, Copy)]
pub struct BytesElem(pub [u8; 16]);
#[hax_lib::attributes]
impl ByteOrBytesElem {

    #[hax_lib::requires(matches!(x, ByteOrBytesElem::Byte(_)))]
    pub fn get_byte(x: &Self) -> u8 {
        match x {
            ByteOrBytesElem::Byte(ByteElem(y)) => *y,
            _ => panic!("get_byte called on non-byte elem")
        }
    }

    #[hax_lib::requires(matches!(x, ByteOrBytesElem::Bytes(_)))]
    pub fn get_bytes(x: &Self) -> [u8; 16] {
        match x {
            ByteOrBytesElem::Bytes(BytesElem(y)) => *y,
            _ => panic!("get_bytes called on non-bytes elem")
        }
    }

    #[hax_lib::ensures(|result| matches!(x, result))]
    pub fn dummy(x: &Self) -> Self {
        match x {
            ByteOrBytesElem::Byte(_) => {let res = ByteOrBytesElem::Byte(ByteElem(0));
                hax_lib::assert!(matches!(x, res)); res},
            ByteOrBytesElem::Bytes(_) => {let res = ByteOrBytesElem::Bytes(BytesElem([0u8; 16]));
                hax_lib::assert!(matches!(x, res)); res},
        }

    }

    #[hax_lib::ensures(|result| matches!(result, ByteOrBytesElem::Bytes(_)))]
    pub fn zero_bytes() -> Self {
        ByteOrBytesElem::Bytes(BytesElem([0u8; 16]))
    }

    pub fn ones(x: &Self) -> Self {
        match x {
            ByteOrBytesElem::Byte(_) => ByteOrBytesElem::Byte(ByteElem(1)),
            ByteOrBytesElem::Bytes(_) => ByteOrBytesElem::Bytes(BytesElem([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        }
    }

    pub fn one_bytes() -> Self {
        ByteOrBytesElem::Bytes(BytesElem([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    }

    #[hax_lib::requires(ByteOrBytesElem::same_variant(x, y))]
    #[hax_lib::ensures(|result| ByteOrBytesElem::same_variant(&result, x) && ByteOrBytesElem::same_variant(&result, y))]
    pub fn xor_array(x : &ByteOrBytesElem, y : &ByteOrBytesElem) -> ByteOrBytesElem {
        match (x, y) {
            (ByteOrBytesElem::Byte(x), ByteOrBytesElem::Byte(y)) => ByteOrBytesElem::Byte(ByteElem(u8::xor_array(&x.0, &y.0))),
            (ByteOrBytesElem::Bytes(x), ByteOrBytesElem::Bytes(y)) => ByteOrBytesElem::Bytes(BytesElem(<[u8; 16]>::xor_array(&x.0, &y.0))),
            _ => panic!("type mismatch for xor_array")
        }
    }
    #[hax_lib::ensures(|result| matches!(x, y) && x.is_byte() == y.is_byte())]
    pub fn same_variant(x: &Self, y: &Self) -> bool {
        matches!(
            (x, y),
            (ByteOrBytesElem::Byte(_), ByteOrBytesElem::Byte(_))
            | (ByteOrBytesElem::Bytes(_), ByteOrBytesElem::Bytes(_))
        )
    }

    /*
    pub fn turn_array_to_T(x: &Self) -> Self {
        match x {
            ByteOrBytesElem::Byte(y) => y.try_into().unwrap(),
            ByteOrBytesElem::Bytes(y) => ByteOrBytesElem::Bytes(BytesElem([1u8; 16]))
        }
    }

     */

    /*
    pub fn get_slice(self, from: usize, to: usize) -> ByteOrBytesElem {
        match self {
            ByteOrBytesElem::Byte(x) => ByteOrBytesElem::Byte(x[from..to]),
            ByteOrBytesElem::Bytes(x) => ByteOrBytesElem::Bytes(x),
        }
    }

     */
    pub fn multiply_with_alpha(self, alpha: [u8;16]) -> [u8;16] {
        match self {
            ByteOrBytesElem::Byte(x) => <u8 as AlphaMul>::mul_with_alpha(x.0, alpha),
            ByteOrBytesElem::Bytes(x) => <[u8;16] as AlphaMul>::mul_with_alpha(x.0, alpha),
        }
    }

    #[hax_lib::requires(N > 0)]
    #[hax_lib::ensures(|result| hax_lib::forall(|i: usize| i >= N || matches!(result[i], ByteOrBytesElem::Byte(_))))]
    pub fn from_byte_array<const N: usize>(x: &[u8; N]) -> [ByteOrBytesElem; N] {
        let mut res: [ByteOrBytesElem; N] = [ByteOrBytesElem::Byte(ByteElem(0)); N];
        for i in 0..N {
            hax_lib::loop_invariant!(|i: usize| {
                hax_lib::Prop::from(i <= N).and(
                hax_lib::forall(|i: usize| i >= N || matches!(res[i], ByteOrBytesElem::Byte(_))))
            });
            ByteOrBytesElem::set_elem(&mut res, i, ByteOrBytesElem::Byte(ByteElem(x[i])));
        };
        res
    }

    #[hax_lib::requires(N > 0)]
    #[hax_lib::ensures(|result| hax_lib::forall(|i: usize| i >= N || matches!(result[i], ByteOrBytesElem::Bytes(_))))]
    pub fn from_bytes_array<const N: usize>(x: &[[u8; 16]; N]) -> [ByteOrBytesElem; N] {
        let mut res: [ByteOrBytesElem; N] = [ByteOrBytesElem::Bytes(BytesElem([0u8; 16])); N];
        for i in 0..N {
            hax_lib::loop_invariant!(|i: usize| {
                hax_lib::Prop::from(i <= N).and(
                hax_lib::forall(|i: usize| i >= N || matches!(res[i], ByteOrBytesElem::Bytes(_))))
            });
            ByteOrBytesElem::set_elem(&mut res, i, ByteOrBytesElem::Bytes(BytesElem(x[i])));
        };
        res
    }

    #[hax_lib::requires(hax_lib::Prop::from(index < N)
                        .and(hax_lib::forall(|i: usize| i >= N || matches!(arr[i], elem))))]
    #[hax_lib::ensures(|result| hax_lib::forall(|i: usize| i >= N || matches!(arr[i], elem)))]
    pub fn set_elem<const N: usize>(arr: &mut [ByteOrBytesElem; N], index: usize, elem : ByteOrBytesElem) {
        arr[index] = elem
    }

    /*
    #[hax_lib::requires(N > 0)]
    #[hax_lib::ensures(|result| hax_lib::forall(|i: usize| i >= N || matches!(x[i], elem)))]
    pub fn same_for_all<const N: usize>(x: [ByteOrBytesElem; N]) -> bool {
        for i in 0..N {
            hax_lib::loop_invariant!(|i: usize| {
                hax_lib::Prop::from(i <= N)
                .and(hax_lib::forall(|j: usize| {
                    j >= i || ByteOrBytesElem::same_variant(&x[j], &x[0])
                }))
            });
            if !ByteOrBytesElem::same_variant(&x[i], &x[0]) {
                return false
            }
        }
        true
    }

     */
    pub fn is_byte(&self) -> bool {
        matches!(self, ByteOrBytesElem::Byte(_))
    }

    pub fn is_bytes(&self) -> bool {
        matches!(self, ByteOrBytesElem::Bytes(_))
    }
}


