#![allow(non_snake_case)]

use crate::utils::types::sizeds_array;
use crate::utils::hash_functions::{h_1_for_non_specific_size};
use crate::utils::math::xor_arrays;
use crate::utils::preliminary_helper_methods::num_rec;
use crate::utils::types::{Tree};
use crate::utils::prg::{prg_convert_to_vole, prg_vole_commit_r};
use crate::utils::vector_commit::{vec_commit, vec_reconstruct_k0, vec_reconstruct_k1};
use crate::utils::constants::{ell, k_0, k_1, tau, tau_0, k_0_pow, k_1_pow};


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

/*
fn array_convert_to_VOLE<const dummy_n: usize, const dummy_m: usize>(sds: [[u8;16]; dummy_n], iv: [u8; 16]) -> ([u8; ell],[[u8; ell]; dummy_m]) {
    // the r structure:
    let d = (sds.len()).ilog2();
    let mut r : [[[Option<[u8; ell]>; (d + 1) as usize]; sds.len()]; d] = [[[None; (d+1) as usize]; sds.len()]; d];  //TODO: is r[i] = sds.len() ? - derived from for loop below is r.len() = d? derived further below

    // if we are verifier
    if sds[0] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] {
        r[0][0] = Some([0;ell]);
    } else { // if we are prover
        r[0][0] = Some(prg_convert_to_vole(sds[0], iv));
    }


    // fill r with the first row of seeds
    for i in 1..sds.len() {
        r[0][i] = Some(prg_convert_to_vole(sds[], iv));

    }

    let zero_v = [0;ell];
    let mut v: [[u8;ell]; d as usize]> = [zero_v; d as usize];
        for j in 0..d as usize {
            let i_range : usize = sds.len() / 2_i32.pow((j + 1) as u32) as usize;
            for i in 0..i_range {
                if let (Some(r1), Some(r2)) = (r[j][2*i], r[j][2*i+1]) {
                    v[j] = xor_arrays(&v[j], &r2);

                    let new_r: [u8; ell] = xor_arrays(&r1, &r2);
                    r[j+1][i] = Some(new_r);
                }
            }
        }
    let u = r[d as usize][0];
    (u.expect("Should be some"), v)
}
 */


pub fn FAEST_VOLE_commit(r: [u8; 16], iv: [u8; 16]) -> ([u8; 56], Vec<([u8;16], [u8;16], Vec<[u8;32]>)>, Vec<[u8;234]>, [u8; 234], Vec<Vec<[u8; 234]>>) {
    let new_r = prg_vole_commit_r(r, iv);
    // extract all r's
    let vec_of_rs: Vec<[u8;16]> = new_r.chunks_exact(16).map(|chunk| chunk.try_into().unwrap()).collect();
    // big V
    let mut big_v:  Vec<Vec<[u8; 234]>> =  vec![vec![];tau];
    let mut big_u: Vec<[u8;234]> = vec![];
    let mut all_decoms : Vec<([u8;16], [u8;16], Vec<[u8;32]>)> = vec![];
    let mut commitments : Vec<[u8; 56]> = vec![];
    // iterate over r's
    for i in 0..tau{
        let (h, decoms, seeds) = if i < tau_0 {
            vec_commit::<k_0_pow>(vec_of_rs[i], iv, k_0 as i128)
        } else {
            vec_commit::<k_1_pow>(vec_of_rs[i], iv, k_1 as i128)
        };
        let (u,v) = convert_to_VOLE(seeds, iv);
        big_v[i] = v;
        big_u.push(u);
        all_decoms.push(decoms);
        commitments.push(h);
    }
    let u_0 = big_u[0];

    let mut big_c: Vec<[u8;234]> = vec![];
    for i in 0..tau{
        big_c.push(xor_arrays(&u_0, &big_u[i]));
    }
    let coms_flat : Vec<u8> = commitments.into_iter().flatten().collect();
    let hash = h_1_for_non_specific_size(coms_flat);

    (hash, all_decoms, big_c, u_0, big_v)
}

/*
fn array_FAEST_VOLE_commit<const dummy_n: usize, const dummy_m: usize, const dummy_a: usize, const dummy_b: usize, const dummy_c: usize>(r: [u8; 16], iv: [u8; 16]) ->
([u8; 56], [(Tree, [[u8;32]; dummy_m]); dummy_n], [[u8;234]; dummy_a], [u8; 234], [[[u8; 234]; dummy_b]; dummy_c]) {
    let new_r = prg_vole_commit_r(r, iv);
    // extract all r's
    let mut vec_of_rs = [[0u8; 16]; tau];       //TODO: beware inital zeroes & verify length
    for i in 0..tau {
        vec_of_rs[i] = chunk.copy_from_slice(&new_r[(i * 16)..(i * 16) + 16]);
    }

    // big V
    let mut big_v:  [[[u8; 234]; dummy_b]; dummy_c] =  [[[0u8; 234]; dummy_b]; tau];     //TODO: beware intial zeroes, is dummy_c = tau? & verify length
    let mut big_u: [[u8;234]; tau] = [[0u8; 234]; tau];      //TODO: beware initial zeroes, is len = tau? & verify length
    let mut all_decoms : [(Tree, [[u8;32]; dummy_m]); dummy_n] = [[[0u8; 32]; dummy_m]; dummy_n]       //TODO: beware initial zeroes, is dummy_n = tau?
    let mut commitments : [[u8; 56]; tau]> = [[0u8; 56;] tau];       //TODO: beware initial zeroes & verify length
    // iterate over r's
    for i in 0..tau{
        let b = if i < tau_0 { k_0 } else { k_1 };
        let (h, decoms, seeds) = vec_commit(vec_of_rs[i], iv, b as i128);
        let (u,v) = convert_to_VOLE(seeds, iv);
        big_v[i] = v;
        big_u[i] = u;
        all_decoms[i] = decoms;
        commitments[i] = h;
    }
    let u_0 = big_u[0];

    let mut big_c: [[u8;234]; dummy_a]> = [[0u8; 234]; dummy_a];   //TODO: beware initial zeroes & verify length & is dummy_a = tau?
    for i in 0..tau{
        big_c[i] = xor_arrays(&u_0, &big_u[i]);
    }

    let mut coms_flat = [0u8; 56 * tau];
    for i in 0..tau {
        for j in 0..56 {
            coms_flat[i * 56 + j] = commitments[i][j];
        }
    }

    let hash = h_1_for_non_specific_size(coms_flat);
    (hash, all_decoms, big_c, u_0, big_v)
}
 */

pub fn chall_dec(chall : [u8;16], i : usize) -> Vec<u8>{
    if i > tau || i < 0 {
        panic!("i is not in right index");
    }
    let lo : usize;
    let hi : usize;
    if i < tau_0 {
        lo = i * k_0;
        hi = (i+1)*k_0-1;
    } else {
        let t = i- tau_0;
        lo = tau_0 * k_0 + t* k_1;
        hi = tau_0 * k_0 + (t+1) * k_1 - 1;
    }
    let mut bits = Vec::with_capacity(hi - lo + 1);

    for b in lo..=hi {
        let byte_index = b / 8;
        let bit_index = b % 8;

        let bit = (chall[byte_index] >> bit_index) & 1;
        bits.push(bit);
    }
    bits
}

/*
fn array_chall_dec<const dummy_n: usize>(chall : [u8;16], i : usize) -> [u8; dummy_n]>{     //TODO: verify length (& streamline)
    if i > tau || i < 0 {       //TODO: unnecessary?
        panic!("i is not in right index");
    }
    let lo : usize;
    let hi : usize;
    if i < tau_0 {
        lo = i * k_0;
        hi = (i+1)*k_0-1;
    } else {
        let t = i- tau_0;
        lo = tau_0 * k_0 + t* k_1;
        hi = tau_0 * k_0 + (t+1) * k_1 - 1;
    }
    let mut bits: [u8; hi - lo + 1] = [u8; hi - lo + 1];

    for b in lo..=hi {
        let byte_index = b / 8;
        let bit_index = b % 8;

        let bit = (chall[byte_index] >> bit_index) & 1;
        bits[b] = bit;
    }
    bits
}
 */

pub fn FAEST_VOLE_reconstruct(chall: [u8;16], pdecoms:Vec<(sizeds_array, [u8; 32])>, iv : [u8;16]) -> ([u8;56], Vec<Vec<[u8;234]>>){
    let mut commitments : Vec<[u8; 56]> = vec![];
    let mut big_q:  Vec<Vec<[u8; 234]>> =  vec![vec![];tau];

    for i in 0..tau{
        let b = chall_dec(chall, i);
        let current_k = if i < tau_0 { k_0 } else {k_1};
        let (com,seeds) = if i < tau_0 {
            vec_reconstruct_k0(pdecoms[i].clone(), b.clone(), iv, k_0 as i128)
        } else {
            vec_reconstruct_k1(pdecoms[i].clone(), b.clone(), iv, k_1 as i128)
        };
        let N_b = seeds.len();
        let delta = num_rec(b.clone(), current_k as u64);
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];N_b];
        for j in 1..N_b {
            sd_updated_verifier[j] = seeds[(j as u64 ^ delta) as usize]
        }

        let (_u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        commitments.push(com);
        big_q[i] = q;
    }
    let coms_flat : Vec<u8> = commitments.into_iter().flatten().collect();
    let hash = h_1_for_non_specific_size(coms_flat);
    (hash, big_q)
}

/*
fn array_FAEST_VOLE_reconstruct<const dummy_n: usize, const dummy_m: usize, const dummy_a: usize, const dummy_b: usize>(chall: [u8;16], pdecoms: [([[u8; 16]>,[u8; 32]; dummy_m]); dummy_n], iv : [u8;16]) -> ([u8;56], [[[u8;234]; dummy_a]; dummy_b]){
    let mut commitments : [[u8; 56]; tau] = [[0u8; 56]; tau];         //TODO: beware initial zeroes & verify length
    let mut big_q:  [[[u8; 234]; dummy_a]; dummy_b] =  [[[0u8; 234]; dummy_a]; tau];       //TODO: beware initial zeroes & verify length & is dummy_b = tau? - derived below

    for i in 0..tau{
        let b = chall_dec(chall, i);
        let current_k;
        if i < tau_0 {
            current_k = k_0;
        } else {
            current_k = k_1;
        }
        let delta = num_rec(b.clone(), current_k as u64);
        let (com, seeds) = vec_reconstruct(pdecoms[i].clone(), b, iv, current_k as i128);
        let N_b = seeds.len();
        let mut sd_updated_verifier : [[u8;16]; N_v] = [[0;16]; N_b];
        for j in 1..N_b {
            sd_updated_verifier[j] = seeds[(j as u64 ^ delta) as usize]
        }

        let (_u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        commitments[i] = com;
        big_q[i] = q;
    }

    let mut coms_flat = [0u8; 56 * tau];
    for i in 0..tau {
        for j in 0..56 {
            coms_flat[i * 56 + j] = commitments[i][j];
        }
    }

    let hash = h_1_for_non_specific_size(coms_flat);
    (hash, big_q)
}
 */