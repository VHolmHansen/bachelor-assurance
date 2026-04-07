use crate::utils::hash_functions::{h_0, h_1};
use crate::utils::prg::{prg};
use crate::utils::preliminary_helper_methods::{num_rec,get_complement_of_b,get_b};
use crate::utils::types::{construct_tree, get_all_leaf_nodes, Tree, get_cop, get_leaves_from_cop_and_b};

// n_d should be 128
// don't know if it is a little fucked, lot of mutability and stuff
pub fn vec_commit(r: [u8; 16], iv: [u8; 16], n_d: i128) -> ([u8; 56], (Tree, Vec<[u8; 32]>), Vec<[u8; 16]>){

    let k_tree = construct_tree(r, iv);
    let leaves = get_all_leaf_nodes(&k_tree);

    let mut sds: Vec<[u8; 16]> = vec![];
    let mut coms: Vec<[u8; 32]> = vec![];
    for ks in leaves{
        let (mut sd, mut com) = h_0(ks, iv);
        sds.push(sd);
        coms.push(com);
    }
    let h = h_1(&coms);
    let decom = (k_tree, coms);

    (h, decom, sds)
}
// the indexing structure, needs to be some kind of bytes, im very confusing of what it should be
// for a start im just going to use a vector of booleans, where index 0, means bit representing 2^0
// the decom, is what is returned by the vec_commit function
// there must be a smarter way to this that to get the bits
pub fn vec_open(decom: (Tree, Vec<[u8; 32]>), b: u8, d: u64) -> (Vec<[u8; 16]>,[u8; 32]){
    let k = decom.0;
    let coms = decom.1;
    let cop = get_cop(b, k);
    let pdecom:(Vec<[u8; 16]>,[u8; 32]) = (cop, coms[b as usize]);
    pdecom
}

// we want to know using the pdecom, to reconstruct all the committed seeds, except the j* one
// we should still be able to check if we have the right values, using the commitments, and the saved commitment for jstar
// i have no idea if this works
pub fn vec_reconstruct(pdecom: (Vec<[u8; 16]>,[u8; 32]), b: u8, iv: [u8; 16]) -> ([u8;56],Vec<[u8;16]>)
{
    let mut sds: Vec<[u8; 16]> = vec![];
    let mut coms: Vec<[u8; 32]> = vec![];

    let cop = pdecom.0;
    let com_star = pdecom.1;

    // it just works
    let leaves = get_leaves_from_cop_and_b(b, cop, iv);
    for l in leaves {
        match l {
            Some(leaf) => {
                let (sd, com) = h_0(leaf, iv);
                sds.push(sd);
                coms.push(com);
            },
            None => {
                coms.push(com_star);
            },
        }
    }



    let h = h_1(&coms);
    (h, sds)
}
// vec_verify should help us do some testing, basically it takes the hash of the commitments from
// commit, then it reconstruct using the pdecom, from vec_open to the commitments, and checks that those
// two hashes are teh same
pub fn vec_verify(h: [u8; 56], pdecom: (Vec<[u8; 16]>,[u8; 32]), b: u8, iv: [u8; 16]) -> bool{
    let (rec_com, rec_sd) = vec_reconstruct(pdecom, b, iv);
    if rec_com == h {
        true
    } else {
        false
    }
}