use crate::utils::finite_field::new;
use crate::utils::hash_functions::h_1;
use crate::utils::math::xor_arrays;
use crate::utils::types::{ell, k_0, k_1, tau, tau_0, Tree};
use crate::utils::prg::{prg_convert_to_vole, prg_vole_commit_r};
use crate::utils::vector_commit::vec_commit;

pub fn convert_to_VOLE(sds: Vec<[u8;16]>, iv: [u8; 16]) -> ([u8; ell],Vec<[u8; ell]>) {
    // the r structure:
    let d = (sds.len()).ilog2();
    let mut r : Vec<Vec<Option<[u8; ell]>>> = vec![vec![]; (d+1) as usize];
    // if we are verifier
    if sds[0] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] {
        r[0].push(Some([0;ell]));
    } else { // if we are prover
        r[0].push(Some(prg_convert_to_vole(sds[0], iv)));
    }

    // fill r with the first row of seeds
    for i in 1..sds.len() {
        r[0].push(Some(prg_convert_to_vole(sds[i], iv)));
    }

    let zero_v = [0;ell];
    let mut v: Vec<[u8;ell]> = vec![zero_v; d as usize];
        for j in 0..d as usize {
            let i_range : usize = sds.len() / 2_i32.pow((j + 1) as u32) as usize;
            for i in 0..i_range {
                if let (Some(r1), Some(r2)) = (r[j][2*i], r[j][2*i+1]) {
                    v[j] = xor_arrays(&v[j], &r2);

                    let new_r: [u8; ell] = xor_arrays(&r1, &r2);
                    r[j+1].push(Some(new_r));
                }
            }
        }
    let u = r[d as usize][0];
    (u.expect("Should be some"), v)
}


pub fn FAEST_VOLE_commit(r: [u8; 16], iv: [u8; 16]) -> ([u8; 56], Vec<(Tree, Vec<[u8;32]>)>, Vec<[u8;234]>, [u8; 234], Vec<Vec<[u8; 234]>>) {
    let new_r = prg_vole_commit_r(r, iv);
    // extract all r's
    let vec_of_rs: Vec<[u8;16]> = new_r.chunks_exact(16).map(|chunk| chunk.try_into().unwrap()).collect();
    // big V
    let mut big_v:  Vec<Vec<[u8; 234]>> =  vec![vec![];tau];
    let mut big_u: Vec<[u8;234]>;
    let mut all_coms : Vec<Vec<[u8;32]>> = vec![vec![];tau];
    let mut all_decoms : Vec<(Tree, Vec<[u8;32]>)>;
    // iterate over r's
    for i in 0..tau{
        let b = if i < tau_0 { k_0 } else { k_1 };
        let n_d : i128 = 2.pow(b as i128);
        let (h, decoms, seeds) = vec_commit(r[i], iv, n_d);
        let (u,v) = convert_to_VOLE(seeds, iv);
        big_v[i] = v;
        big_u.push(u);
        all_coms[i] = decoms.1;
        all_decoms.push(decoms);
    }
    let u_0 = big_u[0];

    let mut big_c: Vec<[u8;234]>;
    for i in 0..tau{
        big_c.push(xor_arrays(u_0, big_u[i]));
    }
    let all_coms_flat = all_coms.into_iter().flatten().collect();
    let hash = h_1(all_coms_flat);

    (hash, all_decoms, big_c, u_0,big_v)
}