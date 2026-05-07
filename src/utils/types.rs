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

impl sized_array_for_q_v {
    pub fn get(&self, index: usize) -> &[u8; ell] {
        match self {
            sized_array_for_q_v::sized_array_1(arr) => &arr[index],
            sized_array_for_q_v::sized_array_2(arr) => &arr[index],
        }
    }
    pub fn set(&mut self, index: usize, value: [u8; ell]) {
        match self {
            sized_array_for_q_v::sized_array_1(arr) => arr[index] = value,
            sized_array_for_q_v::sized_array_2(arr) => arr[index] = value,
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

impl Log2Number {
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
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self;
    fn set_element(&mut self, index : usize, value : &Self::Elem);
    fn new_with_size(value: Self::Elem) -> Self;
    fn len(&self) -> usize;
    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16];
    fn turn_array_to_T(x : &[Self::Elem]) -> Self;
}

impl<const N: usize> ret_value for [[u8;16]; N] {
    type Elem = [u8;16];
    const dummy_value : Self::Elem = [0;16];
    const value_of_one : Self::Elem = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const value_of_two : Self::Elem = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const value_of_three : Self::Elem = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem] {
        &self[x..y]
    }
    fn get_element(&self, x : usize) -> [u8;16] {
        self[x]
    }
    fn xor_array(x : &[u8;16], y : &[u8;16]) -> [u8;16]{
        xor_arrays(x, y)
    }

    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self {
        let mut res: [[u8;16]; N] = [[0u8; 16]; N];
        for i in 0..8 {
            let value_to_push = Self::xor_array(&x[i], &y[i]);
            res[i] = value_to_push;
        }
        res
    }

    fn set_element(&mut self, index : usize, value : &Self::Elem) {
        self[index] = *value;
    }
    fn new_with_size(value: Self::Elem) -> Self {
        [value; N]
    }
    fn len(&self) -> usize{
        <[_]>::len(self)
    }
    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16]{
        gf128_mul(&x, &alpha_val)
    }
    fn turn_array_to_T(x : &[Self::Elem]) -> [[u8; 16]; N] {
        x.try_into().unwrap()
    }

}

impl<const N: usize> ret_value for [u8; N] {
    type Elem = u8;
    const dummy_value : Self::Elem = 0;
    const value_of_one : Self::Elem = 1;
    const value_of_two: Self::Elem = 2;
    const value_of_three : Self::Elem = 3;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem] {
        &self[x..y]
    }
    fn get_element(&self, x : usize) -> u8 {
        self[x]
    }
    fn xor_array(x : &u8, y : &u8) -> u8{
        x ^ y
    }
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self {
        let mut res: [u8; N] = [0u8; N];
        for i in 0..8 {
            let value_to_push = Self::xor_array(&x[i], &y[i]);
            res[i] = value_to_push;
        }
        res
    }

    fn set_element(&mut self, index : usize, value : &Self::Elem) {
        self[index] = *value;
    }
    fn new_with_size(value: Self::Elem) -> Self {
        [value; N]
    }
    fn len(&self) -> usize{
        <[_]>::len(self)
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

    fn turn_array_to_T(x : &[Self::Elem]) -> [u8; N] {
        x.try_into().unwrap()
    }

}