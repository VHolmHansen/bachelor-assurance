#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use hax_lib::requires;
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
    fn len(&self) -> usize {
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
#[derive(Clone, Copy, Debug)]
pub enum Log2Number {
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
    twothousandsandfortyeight
}

#[hax_lib::attributes]
impl Log2Number {
    #[hax_lib::ensures(|result| result == 1 || result == 2 || result == 4 || result == 8
                        || result == 16 || result == 32 || result == 64 || result == 128
                        || result == 256 || result == 512 || result == 1024 || result == 2048)]
    pub fn value(self) -> usize {
        match self {
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
        }
    }

    #[hax_lib::requires(n == 1 || n == 2 || n == 4 || n == 8
                        || n == 16 || n == 32 || n == 64 || n == 128
                        || n == 256 || n == 512 || n == 1024 || n == 2048)]
    pub fn wrap(n: usize) -> Log2Number {
        match n {
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
            _ => panic!("Invalid log2 number")
        }
    }

    #[hax_lib::requires(self.value() > 1)]
    pub fn log_reduce(&mut self) -> Self {
        Self::wrap(self.value() >> 1)
    }
}



pub trait ret_value {
    type Elem: Clone;
    const dummy_value : Self::Elem;
    const value_of_one : Self::Elem;
    const value_of_two : Self::Elem;
    const value_of_three : Self::Elem;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem];
    fn get_element(&self, x : usize) -> Self::Elem;
    fn xor_array(x : &Self::Elem, y : &Self::Elem) -> Self::Elem;
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> [Self::Elem; 8];
    fn set_element(&mut self, index : usize, value : &Self::Elem);
    fn new_with_size(value: Self::Elem) -> Self;
    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16];
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
    fn xor_array(x : &[u8;16], y : &[u8;16]) -> [u8;16]{
        xor_arrays::<16>(x, y)
    }

    #[hax_lib::requires(x.len() >= 8 && y.len() >= 8)]
    fn xor_two_array(x : &[[u8; 16]], y : &[[u8; 16]]) -> [[u8; 16]; 8] {
        let mut res: [[u8;16]; 8] = [[0u8; 16]; 8];
        for i in 0..8usize {
            hax_lib::loop_invariant!(|i: usize| {
                i <= 8
            });
            //let value_to_push: [u8; 16] = Self::xor_array(&x[i], &y[i]);
            let value_to_push: [u8; 16] = xor_helper(&x[i], &y[i]);
            res[i] = value_to_push;
        }
        res
    }

    #[hax_lib::requires(index < self.len())]
    fn set_element(&mut self, index : usize, value : &[u8; 16]) {
        self[index] = *value;
    }
    fn new_with_size(value: Self::Elem) -> Self {
        [value; N]
    }
    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16]{
        gf128_mul(&x, &alpha_val)
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
            //let value_to_push = Self::xor_array(&x[i], &y[i]);
            let value_to_push: u8 = xor_helper(&x[i], &y[i]);
            res[i] = value_to_push;
        }
        res
    }

    #[hax_lib::requires(index < self.len())]
    fn set_element(&mut self, index : usize, value : &u8) {
        self[index] = *value;
    }
    fn new_with_size(value: Self::Elem) -> Self {
        [value; N]
    }

    fn multiply_with_alpha(x: u8, alpha_val: [u8; 16]) -> [u8; 16] {
        // x is a scalar bit (0 or 1)
        // result is either 0 or alpha_val
        if x == 0 {
            [0u8; 16]
        } else {
            alpha_val
        }
    }

    #[hax_lib::requires(x.len() == N)]
    fn turn_array_to_T(x : &[u8]) -> [u8; N] {
        x.try_into().unwrap()
    }

}

/*
#[hax_lib::requires(x.len() >= 8 && y.len() >= 8)]
fn xor_helper<T: ret_value>(x : &[[u8; 16]], y : &[[u8; 16]]) -> [[u8; 16]; 8] {
    let mut res: [[u8;16]; 8] = [[0u8; 16]; 8];
    for i in 0..8 {
        hax_lib::loop_invariant!(|i: usize| {
                i <= 8
            });
        let value_to_push: [u8; 16] = T::xor_array(&x[i], &y[i]);
        res[i] = value_to_push;
    }
    res
}
*/

trait XorHelper: Sized {
    fn xor_helper(x: &Self, y: &Self) -> Self;

    fn length(&self) -> usize;
}

impl XorHelper for u8 {
    #[hax_lib::opaque]
    fn xor_helper(x: &u8, y: &u8) -> u8 {
        x^y
    }

    fn length(&self) -> usize {
        1
    }
}

impl XorHelper for [u8; 16] {
    #[hax_lib::opaque]
    fn xor_helper(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
        xor_arrays::<16>(x, y)
    }

    fn length(&self) -> usize {self.len()}
}

//TODO: non-trivial refactor to make non-opaque
#[hax_lib::opaque]
fn xor_helper<T: XorHelper>(x : &T, y : &T) -> T {
    T::xor_helper(x, y)
}



/*
fn turn_array_to<const N: usize, T: ret_value>(&[T::Elem]) -> [[u8; 16]; N] {

}
 */


