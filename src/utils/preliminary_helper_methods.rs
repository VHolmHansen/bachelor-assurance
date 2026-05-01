use crate::utils::constants::{k_0, k_1};

pub fn num_rec(b: Vec<u8>, d: u64) -> u64{
    let d_minus_one = d-1;
    let mut j_star = 0u64;
    for i in 0..=d_minus_one{
        j_star += (b[i as usize] as u64) * (2_i32.pow(i as u32) as u64);
    }
    j_star
}

pub fn num_rec_k0(b: &[u8; k_0]) -> u64 {
    let mut j_star = 0u64;
    for i in 0..k_0 {
        j_star += (b[i] as u64) * (1u64 << i);
    }
    j_star
}

pub fn num_rec_k1(b: &[u8; k_1]) -> u64 {
    let mut j_star = 0u64;
    for i in 0..k_1 {
        j_star += (b[i] as u64) * (1u64 << i);
    }
    j_star
}

/*
fn array_num_rec<const dummy_n: usize>(b: [u8; dummy_n], d: u64) -> u64 {
    let d_minus_one = d-1;
    let mut j_star = 0u64;
    for i in 0..(d_minus_one + 1) {                 // range inclusive
        j_star += (b[i as usize] as u64) * (2_i32.pow(i as u32) as u64);
    }
    j_star
}
 */

// i think when there is a line over it, it should be the complement
pub fn get_complement_of_b(b: Vec<bool>, d: u64) -> u64{
    if b[d as usize] {
        return 0
    }
    1
}

/*
fn array_get_complement_of_b<const dummy_n: usize>(b: [bool; dummy_n]>, d: u64) -> u64{
    if b[d as usize] {
        return 0
    }
    1
}
 */

// this just extract the bit
pub fn get_b(b: Vec<bool>, d: u64) -> u64{
    if b[d as usize] {
        return 1;
    }
    0
}

/*
fn array_get_b<const dummy_n: usize>(b: [bool; dummy_n], d: u64) -> u64{
    if b[d as usize] {
        return 1;
    }
    0
}
 */
