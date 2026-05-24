#![allow(non_upper_case_globals)]


use crate::utils::constants::{k_0, k_1, k_0_pow, k_1_pow, iv_bytes, lambda_bytes, lambda_bytes_times_two};
use crate::utils::ggm_tree::{get_cop, get_leaves_from_cop_and_b, get_leaves_node_from_root};
use crate::utils::hash_functions::{h_0, h_1_k1,h_1_k0};
use crate::utils::preliminary_helper_methods::{num_rec_k0, num_rec_k1};
use crate::utils::types::{sized_array_for_cop, sized_array_for_coms, sized_array_for_sds, sized_option_array};

// commiting to random values, of 2^k0
pub fn vec_commit_k0(r: [u8; lambda_bytes], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], ([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), sized_array_for_sds){
    // generating all the values used to generate seeds and commitments
    let leaves = get_leaves_node_from_root::<k_0_pow>(&r, iv, k_0);
    // list for seeds
    let mut sds: [[u8; lambda_bytes];k_0_pow] = [[0;lambda_bytes];k_0_pow];
    // list for commits
    let mut coms: [[u8; lambda_bytes_times_two];k_0_pow] = [[0;lambda_bytes_times_two];k_0_pow];
    for i in 0..k_0_pow{        // leaves.len
        // using h_0, to generate a seed and a commit
        let (sd, com) : ([u8;lambda_bytes], [u8;lambda_bytes_times_two]) = h_0(leaves[i], iv);
        // placing seed
        sds[i] = sd;
        // placing commit
        coms[i] = com;
    }
    // using h_1, to generate a commit of all commits
    let h: [u8;lambda_bytes_times_two] = h_1_k0(&coms);
    // wrapping commitments in a special type for returning (two different commits)
    let coms_to_return = sized_array_for_coms::sized_array_1(coms);
    // wrapping seeds in a special type for returning (two different commits)
    let sds_to_return = sized_array_for_sds::sized_array_1(sds);
    // making decom return type used by open
    let decom = (r, iv, coms_to_return);
    // returning, hash, decom and the seeds
    (h, decom, sds_to_return)
}
// commiting to random values, of 2^k1
pub fn vec_commit_k1(r: [u8; lambda_bytes], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], ([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), sized_array_for_sds){
    // generating all the values used to generate seeds and commitments
    let leaves = get_leaves_node_from_root::<k_1_pow>(&r, iv, k_1);
    // list for seeds
    let mut sds: [[u8; lambda_bytes];k_1_pow] = [[0;lambda_bytes];k_1_pow];
    // list for commits
    let mut coms: [[u8; lambda_bytes_times_two];k_1_pow] = [[0;lambda_bytes_times_two];k_1_pow];
    for i in 0..k_1_pow{        // leaves.len
        // using h_0, to generate a seed and a commit
        let (sd, com) : ([u8;lambda_bytes], [u8;lambda_bytes_times_two]) = h_0(leaves[i], iv);
        // placing seed
        sds[i] = sd;
        // placing commit
        coms[i] = com;
    }
    // using h_1, to generate a commit of all commits
    let h : [u8;lambda_bytes_times_two] = h_1_k1(&coms);
    // wrapping commitments in a special type for returning (two different commits)
    let coms_to_return = sized_array_for_coms::sized_array_2(coms);
    // wrapping seeds in a special type for returning (two different commits)
    let sds_to_return = sized_array_for_sds::sized_array_2(sds);
    // making decom return type used by open
    let decom = (r, iv, coms_to_return);
    // returning, hash, decom and the seeds
    (h, decom, sds_to_return)
}

// The open functionality, this returns a pdecom, that is to be used by reconstruct to generate all-but-one random values
// pdecom also contains the commitment of the hidden value, such that the commitment h, can be regenerated and thereby checked
pub fn vec_open_k0(decom: &([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), b: &[u8; k_0]) -> (sized_array_for_cop, [u8; lambda_bytes_times_two]){
    // getting the root of the ggm tree
    let r = decom.0;
    // getting the iv used with random generation
    let iv = decom.1;
    // getting all commitments
    let coms = &decom.2;
    // this returns all sibling nodes, from the path of root to hidden value
    let cop = get_cop::<k_0>(r, iv, num_rec_k0(b));
    // wrapping the cop value in a type, since two open functions
    let cop_to_return = sized_array_for_cop::sized_array_1(cop);
    // getting commitment of hidden value
    let com_value: [u8; lambda_bytes_times_two] = match &coms {
        sized_array_for_coms::sized_array_1(inner) => inner[num_rec_k0(b) as usize],
        _ => panic!("should never happen")
    };
    // creating return value
    let pdecom:(sized_array_for_cop, [u8; lambda_bytes_times_two]) = (cop_to_return, com_value);
    // returning return value
    pdecom
}
// The open functionality, this returns a pdecom, that is to be used by reconstruct to generate all-but-one random values
// pdecom also contains the commitment of the hidden value, such that the commitment h, can be regenerated and thereby checked
pub fn vec_open_k1(decom: &([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), b: &[u8; k_1]) -> (sized_array_for_cop, [u8; lambda_bytes_times_two]){
    // getting the root of the ggm tree
    let r = decom.0;
    // getting the iv used with random generation
    let iv = decom.1;
    // getting all commitments
    let coms = &decom.2;
    // this returns all sibling nodes, from the path of root to hidden value
    let cop = get_cop::<k_1>(r, iv, num_rec_k1(b));
    // wrapping the cop value in a type, since two open functions
    let cop_to_return = sized_array_for_cop::sized_array_2(cop);
    // getting commitment of hidden value  
    let com_value: [u8; lambda_bytes_times_two] = match &coms {
        sized_array_for_coms::sized_array_2(inner) => inner[num_rec_k1(b) as usize],
        _ => panic!("should never happen")
    };
    // creating return value
    let pdecom:(sized_array_for_cop, [u8; lambda_bytes_times_two]) = (cop_to_return, com_value);
    // returning return value
    pdecom
}

// a function for reconstruction of the opened all but one values
pub fn vec_reconstruct_k0(pdecom: &(sized_array_for_cop, [u8; lambda_bytes_times_two]), b: [u8;k_0], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], sized_array_for_sds) {
    // gets cop from pdecom, should contain all the values need to generate all-but-one
    let cop = match pdecom.0 {
        sized_array_for_cop::sized_array_1(arr) => arr,
        _ => panic!("expected k0 array")
    };
    //  a place to store seeds and commitments
    let mut sds: [[u8; lambda_bytes]; k_0_pow] = [[0u8; lambda_bytes]; k_0_pow];
    let mut coms: [[u8; lambda_bytes_times_two]; k_0_pow] = [[0u8; lambda_bytes_times_two]; k_0_pow];
    // the index of the hidden value
    let value_of_b = num_rec_k0(&b);
    // getting all but one leaves
    let leaves : sized_option_array<k_0_pow> = get_leaves_from_cop_and_b(&cop, iv, value_of_b);
    // finding all seeds and commitments to all but one value, using the, leaves iv, and the hidden commitment
    regen_tree_from_pdecom::<k_0_pow>(&leaves, &mut sds, &mut coms, &iv, &pdecom.1);
    // generating the same hash as in commit
    let h = h_1_k0(&coms);
    // wrapping the seed value, because two functions
    let seeds_to_return = sized_array_for_sds::sized_array_1(sds);
    // returning the hash and the seeds
    (h, seeds_to_return)
}

pub fn vec_reconstruct_k1(pdecom: &(sized_array_for_cop, [u8; lambda_bytes_times_two]), b: [u8;k_1], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], sized_array_for_sds) {
    // gets cop from pdecom, should contain all the values need to generate all-but-one
    let cop = match pdecom.0 {
        sized_array_for_cop::sized_array_2(arr) => arr,
        _ => panic!("expected k1 array")
    };
    //  a place to store seeds and commitments
    let mut sds: [[u8; lambda_bytes]; k_1_pow] = [[0u8; lambda_bytes]; k_1_pow];
    let mut coms: [[u8; lambda_bytes_times_two]; k_1_pow] = [[0u8; lambda_bytes_times_two]; k_1_pow];
    // the index of the hidden value
    let value_of_b = num_rec_k1(&b);
    // getting all but one leaves
    let leaves : sized_option_array<k_1_pow> = get_leaves_from_cop_and_b(&cop, iv, value_of_b);
    // finding all seeds and commitments to all but one value, using the, leaves iv, and the hidden commitment
    regen_tree_from_pdecom::<k_1_pow>(&leaves, &mut sds, &mut coms, &iv, &pdecom.1);
    // generating the same hash as in commit
    let h = h_1_k1(&coms);
    // wrapping the seed value, because two functions
    let seeds_to_return = sized_array_for_sds::sized_array_2(sds);
    // returning the hash and the seeds
    (h, seeds_to_return)
}

// used by reconstruct, when having all but one of the leaves, we want to generate the commitments and seeds
// it therefore gets the index and commitment of the unknown value
fn regen_tree_from_pdecom<const size: usize>(leaves: &sized_option_array<size>, sds: &mut [[u8; lambda_bytes]; size], coms: &mut [[u8; lambda_bytes_times_two]; size], iv: &[u8; iv_bytes], pdecom1: &[u8; lambda_bytes_times_two]) {
    let mut i = 0;
    // for each leaf, if it is one that we have, use h_0, to generate commit and seed
    // if it is the one we don't have, add the commitment, and a zero seed instead
    for l in 0..leaves.len() {
        match leaves[l] {
            Some(leaf) => {
                let (sd, com) = h_0(leaf, *iv);
                sds[i] = sd;
                coms[i] = com;
                i += 1;
            },
            None => {
                coms[i] = *pdecom1;
                sds[i] = [0;lambda_bytes];
                i += 1;
            },
        }
    }
}


