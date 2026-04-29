use crate::utils::prg::prg;
use crate::utils::constants::{k_0, k_1};
use crate::utils::types::{sized_array};

pub fn get_leaves_node_from_root<const size: usize>(r: [u8; 16], iv: [u8; 16], d: i128) -> sized_array<size>{
    let mut leaves = [[0u8;16]; size];
    leaves[0] = r;
    for i in 1..d {
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

pub fn main(){
    let leaves = get_leaves_node_from_root::<{ 2_i32.pow(k_1 as u32) as usize }>([0u8;16], [0u8;16], k_1 as i128);
    println!("{:?}", leaves);
    println!("{:?}", leaves.len());
}
