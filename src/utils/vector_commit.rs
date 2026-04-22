use crate::utils::hash_functions::{h_0, h_1};
use crate::utils::preliminary_helper_methods::{num_rec};
use crate::utils::types::{Tree};

// n_d should be 128
// don't know if it is a little fucked, lot of mutability and stuff
pub fn vec_commit(r: [u8; 16], iv: [u8; 16], d: i128) -> ([u8; 56], (Tree, Vec<[u8; 32]>), Vec<[u8; 16]>){
    let k_tree = Tree::construct_tree(r, iv, d);
    let leaves = Tree::get_all_leaf_nodes(&k_tree);
    let mut sds: Vec<[u8; 16]> = vec![];
    let mut coms: Vec<[u8; 32]> = vec![];
    for ks in leaves{
        let (sd, com) = h_0(ks, iv);
        sds.push(sd);
        coms.push(com);
    }
    
    let h = h_1(&coms);
    let decom = (k_tree, coms);

    (h, decom, sds)
}
/*
fn array_vec_commit<const dummy_n: usize, const dummy_m: usize>(r: [u8; 16], iv: [u8; 16], d: i128) -> ([u8; 56], (Tree, [[u8; 32]; dummy_n]), [[u8; 16]; dummy_m]) {
    let k_tree = Tree::construct_tree(r, iv, d);
    let leaves = Tree::get_all_leaf_nodes(&k_tree).as_array().unwrap(); //TODO: function needs to be converted to return array
    let mut sds: [[u8; 16]; dummy_m] = [[0u8; 16]; dummy_m];
    let mut coms: [[u8; 32]; dummy_n] = [[0u8; 32]; dummy_n];

    let mut i = 0;
    for ks in leaves{
        let (sd, com) = h_0(*ks, iv);
        sds[acc] = sd;
        coms[acc] = com;
        i += 1;
    }

    let h = h_1(&coms.to_vec());    // TODO: NO VEC when integrating
    let decom = (k_tree, coms);

    (h, decom, sds)
}

 */

// the indexing structure, needs to be some kind of bytes, im very confusing of what it should be
// for a start im just going to use a vector of booleans, where index 0, means bit representing 2^0
// the decom, is what is returned by the vec_commit function
// there must be a smarter way to this that to get the bits
pub fn vec_open(decom: (Tree, Vec<[u8; 32]>), b: Vec<u8>, d: i128) -> (Vec<[u8; 16]>,[u8; 32]){
    let k = decom.0;
    let coms = decom.1;
    let cop = Tree::get_cop(b.clone(), k, d);
    let pdecom:(Vec<[u8; 16]>,[u8; 32]) = (cop, coms[num_rec(b, d as u64) as usize]);
    pdecom
}
/*
fn array_vec_open<const dummy_n: usize, const dummy_m: usize, const dummy_o: usize>(decom: (Tree, [[u8; 32]; dummy_n]), b: [u8; dummy_m], d: i128) -> ([[u8; 16]; dummy_o],[u8; 32]){
    let k = decom.0;
    let coms = decom.1;
    let cop = Tree::get_cop(b.clone().to_vec(), k, d).as_array().unwrap();      //TODO: NO VEC PLEASE
    let pdecom:([[u8; 16]; dummy_o],[u8; 32]) = (*cop, coms[num_rec(b.to_vec(), d as u64) as usize]);     //TODO VEC VEC VEC
    pdecom
}

 */

// we want to know using the pdecom, to reconstruct all the committed seeds, except the j* one
// we should still be able to check if we have the right values, using the commitments, and the saved commitment for jstar
// i have no idea if this works
pub fn vec_reconstruct(pdecom: (Vec<[u8; 16]>,[u8; 32]), b: Vec<u8>, iv: [u8; 16], d : i128) -> ([u8;56],Vec<[u8;16]>)
{
    let mut sds: Vec<[u8; 16]> = vec![];
    let mut coms: Vec<[u8; 32]> = vec![];

    let cop = pdecom.0;
    let com_star = pdecom.1;
    // get b
    let value_of_b = num_rec(b, d as u64);
    // it just works
    let leaves = Tree::get_leaves_from_cop_and_b(value_of_b, cop, iv);
    for l in leaves {
        match l {
            Some(leaf) => {
                let (sd, com) = h_0(leaf, iv);
                sds.push(sd);
                coms.push(com);
            },
            None => {
                coms.push(com_star);
                sds.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
            },
        }
    }


    let h = h_1(&coms);
    (h, sds)
}

/*
fn array_vec_reconstruct<const dummy_n: usize, const dummy_m: usize, const dummy_o: usize>(pdecom: ([[u8; 16]; dummy_n], [u8; 32]), b: [u8; dummy_m], iv: [u8; 16], d : i128) -> ([u8;56],[[u8;16]; dummy_o])
{
    let mut sds: [[u8; 16]; dummy_o] = [[0u8; 16]; dummy_o];
    let mut coms: [[u8; 32]; dummy_m] = [[0u8; 32]; dummy_m];

    let cop = pdecom.0;
    let com_star = pdecom.1;
    // get b
    let value_of_b = num_rec(b.to_vec(), d as u64);     // TODO: Get dat vec outta here
    // it just works
    let leaves = Tree::get_leaves_from_cop_and_b(value_of_b, cop.to_vec(), iv);     // TODO: Vec
    let mut i = 0;
    for l in leaves {
        match l {
            Some(leaf) => {
                let (sd, com) = h_0(leaf, iv);
                sds[i] = (sd);
                coms[i] = (com);
                i += 1;
            },
            None => {
                coms[i] = (com_star);
                sds[i] = ([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
                i += 1;
            },
        }
    }


    let h = h_1(&coms.to_vec());        // TODO: Vec
    (h, sds)
}

 */



// vec_verify should help us do some testing, basically it takes the hash of the commitments from
// commit, then it reconstruct using the pdecom, from vec_open to the commitments, and checks that those
// two hashes are teh same
pub fn vec_verify(h: [u8; 56], pdecom: (Vec<[u8; 16]>,[u8; 32]), b: Vec<u8>, iv: [u8; 16], d : i128) -> bool{
    let (rec_com, _rec_sd) = vec_reconstruct(pdecom, b, iv, d);
    if rec_com == h {
        true
    } else {
        false
    }
}

/*
fn array_vec_verify<const dummy_n: usize, const dummy_m: usize>(h: [u8; 56], pdecom: ([[u8; 16]; dummy_n],[u8; 32]), b: [u8; dummy_m], iv: [u8; 16], d : i128) -> bool{
    let (rec_com, _rec_sd) = vec_reconstruct((pdecom.0.to_vec(), pdecom.1), b.to_vec(), iv, d);     // TODO: Vec
    if rec_com == h {
        true
    } else {
        false
    }
}
 */