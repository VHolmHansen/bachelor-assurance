#![allow(non_upper_case_globals)]


use crate::utils::constants::{k_0, k_1, k_0_pow, k_1_pow, iv_bytes, lambda_bytes, lambda_bytes_times_two};
use crate::utils::ggm_tree::{get_cop, get_leaves_from_cop_and_b, get_leaves_node_from_root};
use crate::utils::hash_functions::{h_0, h_1_k1,h_1_k0};
use crate::utils::preliminary_helper_methods::{num_rec_k0, num_rec_k1};
use crate::utils::types::{sized_array_for_cop, sized_array_for_coms, sized_array_for_sds, sized_option_array};

// n_d should be 128
// don't know if it is a little fucked, lot of mutability and stuff
pub fn vec_commit_k0(r: [u8; lambda_bytes], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], ([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), sized_array_for_sds){
    let leaves = get_leaves_node_from_root::<k_0_pow>(&r, iv, k_0);
    let mut sds: [[u8; lambda_bytes];k_0_pow] = [[0;lambda_bytes];k_0_pow];
    let mut coms: [[u8; lambda_bytes_times_two];k_0_pow] = [[0;lambda_bytes_times_two];k_0_pow];
    for i in 0..k_0_pow{        // leaves.len
        let (sd, com) : ([u8;lambda_bytes], [u8;lambda_bytes_times_two]) = h_0(leaves[i], iv);
        sds[i] = sd;
        coms[i] = com;
    }

    let h: [u8;lambda_bytes_times_two] = h_1_k0(&coms);

    let coms_to_return = sized_array_for_coms::sized_array_1(coms);
    let sds_to_return = sized_array_for_sds::sized_array_1(sds);
    let decom = (r, iv, coms_to_return);

    (h, decom, sds_to_return)
}
pub fn vec_commit_k1(r: [u8; lambda_bytes], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], ([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), sized_array_for_sds){
    let leaves = get_leaves_node_from_root::<k_1_pow>(&r, iv, k_1);
    let mut sds: [[u8; lambda_bytes];k_1_pow] = [[0;lambda_bytes];k_1_pow];
    let mut coms: [[u8; lambda_bytes_times_two];k_1_pow] = [[0;lambda_bytes_times_two];k_1_pow];
    for i in 0..k_1_pow{        // leaves.len
        let (sd, com) : ([u8;lambda_bytes], [u8;lambda_bytes_times_two]) = h_0(leaves[i], iv);
        sds[i] = sd;
        coms[i] = com;
    }
    let h : [u8;lambda_bytes_times_two] = h_1_k1(&coms);
    let coms_to_return = sized_array_for_coms::sized_array_2(coms);
    let sds_to_return = sized_array_for_sds::sized_array_2(sds);
    let decom = (r, iv, coms_to_return);
    
    (h, decom, sds_to_return)
}

// the indexing structure, needs to be some kind of bytes, im very confusing of what it should be
// for a start im just going to use a vector of booleans, where index 0, means bit representing 2^0
// the decom, is what is returned by the vec_commit function
// there must be a smarter way to this that to get the bits
pub fn vec_open_k0(decom: &([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), b: &[u8; k_0]) -> (sized_array_for_cop, [u8; lambda_bytes_times_two]){
    let r = decom.0;
    let iv = decom.1;
    let coms = &decom.2;
    let cop = get_cop::<k_0>(r, iv, num_rec_k0(b));
    let cop_to_return = sized_array_for_cop::sized_array_1(cop);

    let com_value: [u8; lambda_bytes_times_two] = match &coms {
        sized_array_for_coms::sized_array_1(inner) => inner[num_rec_k0(b) as usize],
        _ => panic!("should never happen")
    };

    let pdecom:(sized_array_for_cop, [u8; lambda_bytes_times_two]) = (cop_to_return, com_value);
    pdecom
}
pub fn vec_open_k1(decom: &([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms), b: &[u8; k_1]) -> (sized_array_for_cop, [u8; lambda_bytes_times_two]){
    let r = decom.0;
    let iv = decom.1;
    let coms = &decom.2;
    let cop = get_cop::<k_1>(r, iv, num_rec_k1(b));
    let cop_to_return = sized_array_for_cop::sized_array_2(cop);

    let com_value: [u8; lambda_bytes_times_two] = match &coms {
        sized_array_for_coms::sized_array_2(inner) => inner[num_rec_k1(b) as usize],
        _ => panic!("should never happen")
    };

    let pdecom:(sized_array_for_cop, [u8; lambda_bytes_times_two]) = (cop_to_return, com_value);
    pdecom
}

// we want to know using the pdecom, to reconstruct all the committed seeds, except the j* one
// we should still be able to check if we have the right values, using the commitments, and the saved commitment for jstar
// i have no idea if this works
pub fn vec_reconstruct_k0(pdecom: &(sized_array_for_cop, [u8; lambda_bytes_times_two]), b: [u8;k_0], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], sized_array_for_sds) {
    let cop = match pdecom.0 {
        sized_array_for_cop::sized_array_1(arr) => arr,
        _ => panic!("expected k0 array")
    };

    let mut sds: [[u8; lambda_bytes]; k_0_pow] = [[0u8; lambda_bytes]; k_0_pow];
    let mut coms: [[u8; lambda_bytes_times_two]; k_0_pow] = [[0u8; lambda_bytes_times_two]; k_0_pow];
    let value_of_b = num_rec_k0(&b);

    let leaves : sized_option_array<k_0_pow> = get_leaves_from_cop_and_b(&cop, iv, value_of_b);
    regen_tree_from_pdecom::<k_0_pow>(&leaves, &mut sds, &mut coms, &iv, &pdecom.1);

    let h = h_1_k0(&coms);

    let seeds_to_return = sized_array_for_sds::sized_array_1(sds);

    (h, seeds_to_return)
}

pub fn vec_reconstruct_k1(pdecom: &(sized_array_for_cop, [u8; lambda_bytes_times_two]), b: [u8;k_1], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes_times_two], sized_array_for_sds) {
    let cop = match pdecom.0 {
        sized_array_for_cop::sized_array_2(arr) => arr,
        _ => panic!("expected k1 array")
    };
    let mut sds: [[u8; lambda_bytes]; k_1_pow] = [[0u8; lambda_bytes]; k_1_pow];
    let mut coms: [[u8; lambda_bytes_times_two]; k_1_pow] = [[0u8; lambda_bytes_times_two]; k_1_pow];
    let value_of_b = num_rec_k1(&b);

    let leaves : sized_option_array<k_1_pow> = get_leaves_from_cop_and_b(&cop, iv, value_of_b);
    regen_tree_from_pdecom::<k_1_pow>(&leaves, &mut sds, &mut coms, &iv, &pdecom.1);

    let h = h_1_k1(&coms);

    let seeds_to_return = sized_array_for_sds::sized_array_2(sds);

    (h, seeds_to_return)
}


fn regen_tree_from_pdecom<const size: usize>(leaves: &sized_option_array<size>, sds: &mut [[u8; lambda_bytes]; size], coms: &mut [[u8; lambda_bytes_times_two]; size], iv: &[u8; iv_bytes], pdecom1: &[u8; lambda_bytes_times_two]) {
    let mut i = 0;
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


// vec_verify should help us do some testing, basically it takes the hash of the commitments from
// commit, then it reconstruct using the pdecom, from vec_open to the commitments, and checks that those
// two hashes are teh same
/*
pub fn vec_verify<const size : usize>(h: [u8; 56], pdecom: (sized_array_for_cop, [u8; 32]), b: [u8;size], iv: [u8; 16], d : i128) -> bool{
    let (rec_com, _rec_sd) = if size == k_0 {vec_reconstruct_k0(&pdecom, b, iv, d)} else {vec_reconstruct_k1(&pdecom, b, iv, d)};
    if rec_com == h {
        true
    } else {
        false
    }
}

 */
