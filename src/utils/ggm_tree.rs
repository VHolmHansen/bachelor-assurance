use crate::utils::prg::prg;
use crate::utils::constants::{k_0, k_1, twothousandsandfortyeight,onethousandandtwentyfour, fivehundredandtwelve, twohundredandfiftysix, onehundredandtwentyeight, sixtyfour, thirtytwo, sixteen, eight, four, two, one};
use crate::utils::types::{sized_array_16, sized_option_array};

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
            leaves[(2*j) as usize].copy_from_slice(&left_node_value);
            leaves[(2*j+1) as usize].copy_from_slice(&right_node_value);
        }
    }
    // returns correct size
    leaves
}
/*
pub fn get_some_leaves<const size_pow: usize>(r: [u8; 16], iv: [u8; 16], d: i128) -> sized_option_array<size_pow>{
    let mut leaves = [None; size_pow];
    leaves[0] = Some(r);
    for i in 1..(d + 1) {
        let current_leaves = leaves;
        for j in 0..(2_i32.pow(i as u32) >> 1) {
            // get parent value for prg
            let ran_value = current_leaves[j as usize];

            let mut nodes = [0u8; 32];
            prg(ran_value.unwrap(), iv, &mut nodes);

            // get child values for left and right
            let left_node_value : Some([u8;16])= nodes[..16].try_into().unwrap();
            let right_node_value : Some([u8;16]) = nodes[16..].try_into().unwrap();

            // insert child values
            leaves[(2*j) as usize] = left_node_value;
            leaves[(2*j+1) as usize] = right_node_value;
        }
    }
    // returns correct size
    leaves
}

 */

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
            index = (index - 1) / 2
        } else {
            index = (index) / 2
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

    let mut match_value = size_pow / 2;

    for c in cop {
        match match_value {
             twothousandsandfortyeight => {
                 let d =  11; // should be log_2(2048)
                 let leaves_to_add = get_leaves_node_from_root::<twothousandsandfortyeight>(c, iv, d);
                 if get_if_left(d, b as i128){
                     for i in (current_start+twothousandsandfortyeight)..current_end {
                         leaves[i] = Some(leaves_to_add[i-twothousandsandfortyeight]);
                     }
                     current_end -= twothousandsandfortyeight;
                     match_value = match_value / 2;
                 } else {
                     for i in 0..twothousandsandfortyeight {
                         leaves[i+current_start] = Some(leaves_to_add[i]);
                     }
                     current_start += twothousandsandfortyeight;
                     match_value = match_value / 2;
                 }
             }
            onethousandandtwentyfour => {
                let d =  10; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<onethousandandtwentyfour>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+onethousandandtwentyfour)..current_end {
                        leaves[i] = Some(leaves_to_add[i-onethousandandtwentyfour-current_start]);
                    }
                    current_end -= onethousandandtwentyfour;
                    match_value = match_value / 2;
                } else {
                    for i in 0..onethousandandtwentyfour {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += onethousandandtwentyfour;
                    match_value = match_value / 2;
                }
            }
            fivehundredandtwelve => {
                let d =  9; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<fivehundredandtwelve>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+fivehundredandtwelve)..current_end {
                        leaves[i] = Some(leaves_to_add[i-fivehundredandtwelve-current_start]);
                    }
                    current_end -= fivehundredandtwelve;
                    match_value = match_value / 2;
                } else {
                    for i in 0..fivehundredandtwelve {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += fivehundredandtwelve;
                    match_value = match_value / 2;
                }
            }
            twohundredandfiftysix => {
                let d =  8; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<twohundredandfiftysix>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+twohundredandfiftysix)..current_end {
                        leaves[i] = Some(leaves_to_add[i-twohundredandfiftysix-current_start]);
                    }
                    current_end -= twohundredandfiftysix;
                    match_value = match_value / 2;
                } else {
                    for i in 0..twohundredandfiftysix {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += twohundredandfiftysix;
                    match_value = match_value / 2;
                }
            }
            onehundredandtwentyeight => {
                let d =  7; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<onehundredandtwentyeight>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+onehundredandtwentyeight)..current_end {
                        leaves[i] = Some(leaves_to_add[i-onehundredandtwentyeight-current_start]);
                    }
                    current_end -= onehundredandtwentyeight;
                    match_value = match_value / 2;
                } else {
                    for i in 0..onehundredandtwentyeight {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += onehundredandtwentyeight;
                    match_value = match_value / 2;
                }
            }
            sixtyfour => {
                let d =  6; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<sixtyfour>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+sixtyfour)..current_end {
                        leaves[i] = Some(leaves_to_add[i-sixtyfour-current_start]);
                    }
                    current_end -= sixtyfour;
                    match_value = match_value / 2;
                } else {
                    for i in 0..sixtyfour {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += sixtyfour;
                    match_value = match_value / 2;
                }
            }
            thirtytwo => {
                let d =  5; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<thirtytwo>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+thirtytwo)..current_end {
                        leaves[i] = Some(leaves_to_add[i-thirtytwo-current_start]);
                    }
                    current_end -= thirtytwo;
                    match_value = match_value / 2;
                } else {
                    for i in 0..thirtytwo {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += thirtytwo;
                    match_value = match_value / 2;
                }
            }
            sixteen => {
                let d =  4; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<sixteen>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+sixteen)..current_end {
                        leaves[i] = Some(leaves_to_add[i-sixteen-current_start]);
                    }
                    current_end -= sixteen;
                    match_value = match_value / 2;
                } else {
                    for i in 0..sixteen {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += sixteen;
                    match_value = match_value / 2;
                }
            }
            eight => {
                let d =  3; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<eight>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+eight)..current_end {
                        leaves[i] = Some(leaves_to_add[i-eight-current_start]);
                    }
                    current_end -= eight;
                    match_value = match_value / 2;
                } else {
                    for i in 0..eight {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += eight;
                    match_value = match_value / 2;
                }
            }
            four => {
                let d =  2; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<four>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+four)..current_end {
                        leaves[i] = Some(leaves_to_add[i-four-current_start]);
                    }
                    current_end -= four;
                    match_value = match_value / 2;
                } else {
                    for i in 0..four {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += four;
                    match_value = match_value / 2;
                }
            }
            two => {
                let d =  1; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<two>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+two)..current_end {
                        leaves[i] = Some(leaves_to_add[i-two-current_start]);
                    }
                    current_end -= two;
                    match_value = match_value / 2;
                } else {
                    for i in 0..two {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += two;
                    match_value = match_value / 2;
                }
            }
            one => {
                let d =  0; // should be log_2(2048)
                let leaves_to_add = get_leaves_node_from_root::<one>(c, iv, d);
                if get_if_left(d, b as i128){
                    for i in (current_start+one)..current_end {
                        leaves[i] = Some(leaves_to_add[i-one-current_start]);
                    }
                    current_end -= one;
                    match_value = match_value / 2;
                } else {
                    for i in 0..one {
                        leaves[i+current_start] = Some(leaves_to_add[i]);
                    }
                    current_start += one;
                    match_value = match_value / 2;
                }
            }
            _ => panic!("what the f")
        }
    }

    leaves
}



pub fn main(){
    const pow_of_k_1 : usize = 2048;
    let leaeves1 = get_leaves_node_from_root::<pow_of_k_1>(&[1;16], [0;16], k_1 as i128);

    let cop = get_cop::<k_1>([1;16], [0;16], 2047, k_1 as i128);

    let leaves = get_leaves_from_cop_and_b::<k_1,pow_of_k_1>(&cop, [0;16], 2047);


    for i in 0..2048{
        match leaves[i] {
            Some(leaf) => {
                assert!(leaf == leaeves1[i]);
            }
            None => {}
        }
    }

}
