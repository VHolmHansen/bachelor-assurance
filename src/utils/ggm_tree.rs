#![allow(non_upper_case_globals)]
use crate::utils::prg::prg;
use crate::utils::constants::{k_1};
use crate::utils::types::{sized_array_16, sized_option_array, Log2Number};

pub fn get_leaves_node_from_root<const size_pow: usize>(r: &[u8; 16], iv: [u8; 16], d: i128) -> sized_array_16<size_pow>{
    let mut leaves = [[0u8;16]; size_pow];
    leaves[0] = *r;
    for i in 1..(d + 1) {
        let current_leaves = leaves;
        for j in 0..(2_i32.pow(i as u32) >> 1) {
            // get parent value for prg
            let ran_value = current_leaves[j as usize];

            let mut nodes = [0u8; 32];
            prg(ran_value, iv, &mut nodes);

            // get child values for left and right
            let left_node_value : [u8;16]= nodes[..16].try_into().unwrap();
            let right_node_value : [u8;16] = nodes[16..].try_into().unwrap();

            // insert child values
            leaves[(j << 1) as usize].copy_from_slice(&left_node_value);
            leaves[((j << 1) + 1) as usize].copy_from_slice(&right_node_value);
        }
    }
    // returns correct size
    leaves
}

pub fn get_cop<const size: usize>(r: [u8;16], iv: [u8;16], b: u64, d: i128) -> sized_array_16<size> {
    let mut cop = [[0u8; 16]; size];
    let mut current_node = r;

    let mut i = d-1;

    while i >= 0 {
        let is_left = get_if_left(i, b as i128);

        let mut nodes = [0u8; 32];
        prg(current_node, iv, &mut nodes);

        // get child values for left and right
        let left_node_value : [u8;16]= nodes[..16].try_into().unwrap();
        let right_node_value : [u8;16] = nodes[16..].try_into().unwrap();

        // move right direction
        if is_left {
            current_node = left_node_value;
            cop[(d-i-1) as usize] = right_node_value;
        } else {
            current_node = right_node_value;
            cop[(d-i-1) as usize] = left_node_value;
        }
        i -= 1;
    }
    cop
}

// ensure level < tree size
pub fn get_if_left(level : i128, index : i128) -> bool{
    let mut index = index;
    let mut i = level;
    while i > 0 {
        if index % 2 == 1 {
            index = (index - 1) >> 1
        } else {
            index = (index) >> 1
        }
        i -= 1;
    }

    if index % 2 == 1 {
        false
    } else {
        true
    }
}

pub fn get_leaves_from_cop_and_b<const size : usize, const size_pow : usize>(cop : &sized_array_16<size>, iv : [u8;16], b: u64) -> sized_option_array<size_pow> {
    let mut leaves = [None; size_pow];
    let mut current_start = 0;
    let mut current_end = size_pow;
    let mut match_value = Log2Number::wrap(size_pow >> 1);

    fn cop_helper<const N: usize, const size_pow: usize>(c: &[u8; 16], leaves: &mut [Option<[u8; 16]>; size_pow], iv: [u8; 16], b: u64, current_start: &mut usize, current_end: &mut usize) {
        let d = N.ilog2() as i128;
        let leaves_to_add = get_leaves_node_from_root::<N>(c, iv, d);
        if get_if_left(d, b as i128){
            for i in (*current_start+N)..*current_end {
                leaves[i] = Some(leaves_to_add[i-(*current_start+N)]);
            }
            *current_end -= N;
        } else {
            for i in 0..N {
                leaves[i+*current_start] = Some(leaves_to_add[i]);
            }
            *current_start += N;
        }
    }

    for c in cop {
        match match_value {
            Log2Number::one => {cop_helper::<1, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::two => {cop_helper::<2, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::four => {cop_helper::<4, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::eight => {cop_helper::<8, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::sixteen => {cop_helper::<16, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::thirtytwo => {cop_helper::<32, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::sixtyfour => {cop_helper::<64, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::onehundredandtwentyeight => {cop_helper::<128, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::twohundredandfiftysix => {cop_helper::<256, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::fivehundredandtwelve => {cop_helper::<512, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::onethousandandtwentyfour => {cop_helper::<1024, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
            Log2Number::twothousandsandfortyeight => {cop_helper::<2048, size_pow>(c, &mut leaves, iv, b, &mut current_start, &mut current_end);}
        }
        if match_value.value() > 1 { match_value = match_value.log_reduce() }
    }
    leaves
}



pub fn main(){
    const pow_of_k_1 : usize = 2048;
    let leaves1 = get_leaves_node_from_root::<pow_of_k_1>(&[1;16], [0;16], k_1 as i128);

    let cop = get_cop::<k_1>([1;16], [0;16], 2047, k_1 as i128);

    let leaves = get_leaves_from_cop_and_b::<k_1,pow_of_k_1>(&cop, [0;16], 2047);


    for i in 0..2048{
        match leaves[i] {
            Some(leaf) => {
                assert!(leaf == leaves1[i]);
            }
            None => {}
        }
    }

}
