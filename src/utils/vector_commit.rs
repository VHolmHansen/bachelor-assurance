use crate::utils::hash_functions::{h_0, h_1};
use crate::utils::prg::{prg};
use crate::utils::preliminary_helper_methods::{num_rec,get_complement_of_b,get_b};

// n_d should be 128
// don't know if it is a little fucked, lot of mutability and stuff
fn vec_commit(r: [u8; 16], iv: [u8; 16], n_d: i128) -> ([u8; 56], (Vec<Vec<[u8; 16]>>, Vec<[u8; 32]>), Vec<[u8; 16]>){
    let d = n_d.ilog(2);
    let mut k: Vec<Vec<[u8; 16]>> = vec![vec![]; (d + 1) as usize];
    k[0].push(r);

    // should give us the GGM tree construction
    for i in 1..=d as usize{
        let priv_k = k[i-1].clone();
        for ks in priv_k{
            // use prg to make two k's, the next to nodes of the tree
            let new_k = prg(ks.clone(), iv);

            // prepare places to store each part of the new_k
            let mut first_k = [0u8; 16];
            let mut second_k = [0u8; 16];

            // get each part of the first k and then the seond k
            first_k.copy_from_slice(&new_k[..16]);
            second_k.copy_from_slice(&new_k[16..]);

            // push first and second k
            k[i].push(first_k);
            k[i].push(second_k);
        }
    }

    let leafs = k[d as usize].clone();
    let mut sds: Vec<[u8; 16]> = vec![];
    let mut coms: Vec<[u8; 32]> = vec![];
    for ks in leafs{
        let (mut sd, mut com) = h_0(ks, iv);
        sds.push(sd);
        coms.push(com);
    }
    let h = h_1(coms.clone());

    let decom = (k, coms);
    (h, decom, sds)
}
// the indexing structure, needs to be some kind of bytes, im very confusing of what it should be
// for a start im just going to use a vector of booleans, where index 0, means bit representing 2^0
// the decom, is what is returned by the vec_commit function
// there must be a smarter way to this that to get the bits
fn vec_open(decom: (Vec<Vec<[u8; 16]>>, Vec<[u8; 32]>), b: Vec<bool>, d: u64) -> (Vec<Vec<[u8; 16]>>,[u8; 32]){
    let j_star = num_rec(b.clone(), d);
    let k = decom.0;
    let coms = decom.1;
    let mut a = 0;
    let mut cop: Vec<Vec<[u8; 16]>> = vec![vec![]; (d + 1) as usize];
    for i in 1..=d{
        cop[i as usize].push(k[i as usize][(2*a+get_complement_of_b(b.clone(),d-i)) as usize]);
        a = 2*a+get_b(b.clone(), d-i);
    }
    let pdecom:(Vec<Vec<[u8; 16]>>,[u8; 32]) = (cop, coms[j_star as usize]);
    pdecom
}


