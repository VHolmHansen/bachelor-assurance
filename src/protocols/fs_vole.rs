#![allow(non_snake_case, non_upper_case_globals)]


use crate::utils::types::{sized_array_234, sized_array_for_q_v, sized_array_for_sds};
use crate::utils::types::{sized_array_for_coms, sized_array_for_cop};
use crate::utils::hash_functions::{h_1_for_352};
use crate::utils::math::xor_arrays;
use crate::utils::preliminary_helper_methods::{flatten, num_rec_k0, num_rec_k1};
use crate::utils::prg::{prg_convert_to_vole, prg_vole_commit_r};
use crate::utils::vector_commit::{vec_commit_k0, vec_commit_k1, vec_reconstruct_k0, vec_reconstruct_k1};
use crate::utils::constants::{ell, k_0, k_1, tau, tau_0, k_0_pow, k_1_pow, tau_minus_one};


pub fn convert_to_VOLE<const d : usize>(sds: &sized_array_for_sds, iv: [u8; 16]) -> ([u8; ell], sized_array_234<d>) {
    let sds: &[[u8; 16]] = match &sds {
        sized_array_for_sds::sized_array_1(inner) => inner.as_slice(),
        sized_array_for_sds::sized_array_2(inner) => inner.as_slice(),
    };

    hax_lib::assert!(sds.len() == 2048 || sds.len() == 4096);
    // the r structure:
    let mut r: Vec<Vec<Option<[u8; ell]>>> = vec![vec![None; sds.len()]; d + 1];    // keeping as vec, annoying rewrite, plus sugar for report

    // if we are verifier
    if sds[0] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] {
        r[0][0] = Some([0u8;ell]);
    } else { // if we are prover
        r[0][0] = Some(prg_convert_to_vole(sds[0], iv));
    }

    // fill r with the first row of seeds
    for i in 1..sds.len() {
        r[0][i] = Some(prg_convert_to_vole(sds[i], iv));

    }


    let zero_v = [0;ell];
    let mut v: [[u8;ell]; d] = [zero_v; d];
    for j in 0..d {
        let i_range : usize = sds.len() >> (j + 1); // prev: sds.len() / 2_i32.pow(j + 1)
        for i in 0..i_range {
            if let (Some(r1), Some(r2)) = (r[j][2*i], r[j][2*i+1]) {
                v[j] = xor_arrays(&v[j], &r2);

                let new_r: [u8; ell] = xor_arrays(&r1, &r2);
                r[j+1][i] = Some(new_r);
            }
        }
    }
    let u = r[d][0];
    (u.expect("Should be some"), v)
}


pub fn FAEST_VOLE_commit(r: [u8; 16], iv: [u8; 16]) -> ([u8; 32], [([u8;16], [u8;16], sized_array_for_coms); tau], [[u8;234]; tau_minus_one], [u8; 234], [sized_array_for_q_v;tau]) {
    let new_r = prg_vole_commit_r(r, iv);
    // extract all r's
    let arr_of_rs: [[u8; 16]; 11] = std::array::from_fn(|i| {
        new_r[i << 4..(i + 1) << 4].try_into().unwrap()
    });
    // big V
    let mut big_v:  [sized_array_for_q_v;tau] = [sized_array_for_q_v::sized_array_1([[0u8;234];k_0]);tau];
    let mut big_u: [[u8;234];tau] = [[0;234];tau];
    let mut all_decoms : [([u8;16], [u8;16], sized_array_for_coms);tau] = [([0;16], [0;16], sized_array_for_coms::sized_array_1([[0u8;32];k_0_pow]));tau];
    let mut commitments : [[u8; 32];tau] = [[0;32];tau];
    // iterate over r's
    // this loop should be made able to be threaded
    for i in 0..tau{
        let (h, decoms, u, v) = if i < tau_0 {
            let (h, decoms, seeds) = vec_commit_k0(arr_of_rs[i], iv, k_0 as i128);
            let (u,v) = convert_to_VOLE::<k_0>(&seeds, iv);
            (h, decoms, u, sized_array_for_q_v::sized_array_1(v))
        } else {
            let (h, decoms, seeds) = vec_commit_k1(arr_of_rs[i], iv, k_1 as i128);
            let (u,v) = convert_to_VOLE::<k_1>(&seeds, iv);
            (h, decoms, u, sized_array_for_q_v::sized_array_2(v))
        };

        big_v[i] = v;
        big_u[i] = u;
        all_decoms[i] = decoms;
        commitments[i] = h;
    }
    let u_0 = big_u[0];

    let mut big_c: [[u8;234]; tau_minus_one] = [[0u8; 234]; tau_minus_one];
    for i in 0..tau{
        if i > 0 {
            big_c[i-1] = xor_arrays(&u_0, &big_u[i]);
        }
    }
    let coms_flat: [u8; tau * 32] = flatten::<tau, 32, {tau * 32}>(commitments);

    let hash = h_1_for_352(&coms_flat);



    (hash, all_decoms, big_c, u_0, big_v)
}

pub fn chall_dec_k0(chall: [u8; 16], i: usize) -> [u8; k_0] {
    assert!(i < tau_0, "i must be < tau_0 for k_0 variant");
    let lo = i * k_0;
    let hi = (i + 1) * k_0 - 1;

    let mut bits = [0u8; k_0];
    for (idx, b) in (lo..(hi + 1)).enumerate() {     //inclusive range
        let byte_index = b >> 3;
        let bit_index = b % 8;
        bits[idx] = (chall[byte_index] >> bit_index) & 1;
    }
    bits
}

pub fn chall_dec_k1(chall: [u8; 16], i: usize) -> [u8; k_1] {
    assert!(i >= tau_0 && i < tau, "i must be in [tau_0, tau) for k_1 variant");
    let t = i - tau_0;
    let lo = tau_0 * k_0 + t * k_1;
    let hi = tau_0 * k_0 + (t + 1) * k_1 - 1;

    let mut bits = [0u8; k_1];
    for (idx, b) in (lo..(hi + 1)).enumerate() {     //inclusive range
        let byte_index = b >> 3;
        let bit_index = b % 8;
        bits[idx] = (chall[byte_index] >> bit_index) & 1;
    }
    bits
}

pub fn FAEST_VOLE_reconstruct(chall: [u8;16], pdecoms: &[(sized_array_for_cop, [u8; 32]); 11], iv : [u8;16]) -> ([u8;32], [sized_array_for_q_v;tau]){
    let mut commitments : [[u8; 32];tau] = [[0;32];tau];
    let mut big_q:  [sized_array_for_q_v;tau] =  [sized_array_for_q_v::sized_array_1([[0u8;234];k_0]);tau];

    for i in 0..tau{
        let _loop_start = std::time::Instant::now();

        if i < tau_0 {
            let b = chall_dec_k0(chall, i);
            let (com,sds) = vec_reconstruct_k0(&pdecoms[i], b.clone(), iv);
            let sds: &[[u8; 16]] = match &sds {
                sized_array_for_sds::sized_array_1(inner) => inner.as_slice(),
                sized_array_for_sds::sized_array_2(inner) => inner.as_slice(),
            };
            let N_b = sds.len();
            let delta = num_rec_k0(&b);
            let mut sd_updated_verifier: [[u8;16];k_0_pow] = [[0;16];k_0_pow];
            for j in 1..N_b {
                sd_updated_verifier[j] = sds[(j as u64 ^ delta) as usize]
            }
            let sds_for_later_use :  sized_array_for_sds = sized_array_for_sds::sized_array_1(sd_updated_verifier);
            let (_u_mark, q) = convert_to_VOLE::<k_0>(&sds_for_later_use, iv);
            let (_u_mark, q) = (_u_mark, sized_array_for_q_v::sized_array_1(q));

            commitments[i] = com;
            big_q[i] = q;

        } else {
            let b = chall_dec_k1(chall, i);
            let (com,sds) = vec_reconstruct_k1(&pdecoms[i], b.clone(), iv);
            let sds: &[[u8; 16]] = match &sds {
                sized_array_for_sds::sized_array_1(inner) => inner.as_slice(),
                sized_array_for_sds::sized_array_2(inner) => inner.as_slice(),
            };
            let N_b = sds.len();
            let delta = num_rec_k1(&b);

            let mut sd_updated_verifier: [[u8;16];k_1_pow] = [[0;16];k_1_pow];
            for j in 1..N_b {
                sd_updated_verifier[j] = sds[(j as u64 ^ delta) as usize]
            }
            let sds_for_later_use :  sized_array_for_sds = sized_array_for_sds::sized_array_2(sd_updated_verifier);
            let (_u_mark, q) = convert_to_VOLE::<k_1>(&sds_for_later_use, iv);
            let (_u_mark, q) = (_u_mark, sized_array_for_q_v::sized_array_2(q));

            commitments[i] = com;
            big_q[i] = q;
        };


        // println!("end of loop_reconstruct took: {:?}", loop_start.elapsed());
    }

    let coms_flat: [u8; tau * 32] = flatten::<tau, 32, {tau * 32}>(commitments);
    let hash = h_1_for_352(&coms_flat);
    (hash, big_q)
}