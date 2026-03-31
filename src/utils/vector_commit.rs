use crate::utils::hash_functions::{h_0, h_1};
use crate::utils::prg::{prg};

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



