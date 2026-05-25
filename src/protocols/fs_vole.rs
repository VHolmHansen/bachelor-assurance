#![allow(non_snake_case, non_upper_case_globals)]

use crate::utils::types::{sized_array_234, sized_array_for_q_v, sized_array_for_sds, Log2Number};
use crate::utils::types::{sized_array_for_coms, sized_array_for_cop};
use crate::utils::hash_functions::{h_1_for_352};
use crate::utils::{math::xor_arrays, math};
use crate::utils::preliminary_helper_methods::{flatten, num_rec_k0, num_rec_k1, xor_with_bound};
use crate::utils::prg::{prg_convert_to_vole, prg_vole_commit_r};
use crate::utils::vector_commit::{vec_commit_k0, vec_commit_k1, vec_reconstruct_k0, vec_reconstruct_k1};
use crate::utils::constants::{ell, k_0, k_1, tau, tau_0, k_0_pow, k_1_pow, tau_minus_one};

#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::requires((d == k_0 || d == k_1))]
pub fn convert_to_VOLE<const d : usize>(sds: &sized_array_for_sds, iv: [u8; 16]) -> ([u8; ell], sized_array_234<d>) {
    let sds: &[[u8; 16]] = match &sds {
        sized_array_for_sds::sized_array_1(inner) => inner.as_slice(),
        sized_array_for_sds::sized_array_2(inner) => inner.as_slice(),
    };

    hax_lib::assert!(sds.len() == 2048 || sds.len() == 4096);
    // the r structure:
    let mut r: Vec<Vec<[u8; ell]>> = vec![vec![[0u8; ell]; sds.len()]; d + 1];    // keeping as vec, annoying rewrite, plus sugar for report
    //hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= r.len() || r[i].len() == sds.len()));
    // if we are verifier
    if sds[0] == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] {
        r[0][0] = [0u8;ell];
    } else { // if we are prover
        r[0][0] = prg_convert_to_vole(sds[0], iv);
    }
    //hax_lib::assert!(r[0][0].is_some());
    hax_lib::assert!(r.len() == d + 1);
    hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= r.len() || r[i].len() == sds.len()));
    // fill r with the first row of seeds
    for i in 1..sds.len() {
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::Prop::from(i <= sds.len())
            .and(hax_lib::Prop::from(i >= 1))
            .and(hax_lib::Prop::from(r.len() == d + 1))
            .and(hax_lib::Prop::from(i <= r[0].len()))
            .and(hax_lib::forall(|j: usize| {j >= r.len() || r[j].len() == sds.len()}))
        });
        hax_lib::assert!(r.len() == d + 1);
        hax_lib::assert!(i < sds.len());
        hax_lib::assert_prop!(hax_lib::forall(|j: usize| {j >= r.len() || r[j].len() == sds.len()}));
        hax_lib::assert_prop!(hax_lib::implies(hax_lib::forall(|j: usize| {j >= r.len() || r[j].len() == sds.len()}).and(i < sds.len()), i < r[0].len()));
        hax_lib::assert!(i < r[0].len());
        r[0][i] = prg_convert_to_vole(sds[i], iv);
        //hax_lib::assert!(r[0][i].is_some());
        hax_lib::assert!(r[0].len() == sds.len());
        hax_lib::assert!(r.len() == d + 1);

    }
    hax_lib::assert!(r.len() == d + 1);
    let zero_v = [0;ell];
    let mut v: [[u8;ell]; d] = [zero_v; d];
    for j in 0..d {
        hax_lib::loop_invariant!(|j: usize| {
            hax_lib::Prop::from(j <= d)
            .and(hax_lib::Prop::from(r.len() == d + 1))
            .and(hax_lib::forall(|k: usize| {k >= r.len() || r[k].len() == sds.len()}))
            //.and(hax_lib::forall(|l: usize| {l >= j || r[l][0].is_some()}))
        });
        let i_range : usize = sds.len() >> (j + 1); // prev: sds.len() / 2_i32.pow(j + 1)
        hax_lib::assert!(i_range < sds.len());
        for i in 0..i_range {
            hax_lib::loop_invariant!(|i: usize| {
                hax_lib::Prop::from(i <= i_range)
                .and(hax_lib::Prop::from(r.len() == d + 1))
                .and(hax_lib::forall(|k: usize| {k >= r.len() || r[k].len() == sds.len()}))
                .and(hax_lib::Prop::from(2 * i <= r[j].len()))
                .and(hax_lib::Prop::from(i <= r[j + 1].len()))
            });
            hax_lib::assert!(2 * i + 1 < r[j].len());
            hax_lib::assert!(i < r[j + 1].len());
            if let (r1, r2) = (r[j][2*i], r[j][2*i+1]) {
                v[j] = xor_arrays(&v[j], &r2);

                let new_r: [u8; ell] = xor_arrays(&r1, &r2);
                r[j+1][i] = new_r;
                //hax_lib::assert!(r[j+1][i].is_some());
            }
            hax_lib::assert!(r.len() == d + 1);
            hax_lib::assert_prop!(hax_lib::forall(|k: usize| {k >= r.len() || r[k].len() == sds.len()}));
            hax_lib::assert!(2 * i + 1 < r[j].len());
            hax_lib::assert!(i < r[j + 1].len());
        }
        hax_lib::assert_prop!(hax_lib::forall(|k: usize| {k >= r.len() || r[k].len() == sds.len()}));
        hax_lib::assert!(r.len() == d + 1);
        //hax_lib::assert_prop!(hax_lib::forall(|i: usize| {i > j || r[i][0].is_some()}));
        //hax_lib::assert_prop!(hax_lib::implies(j == d - 1, hax_lib::forall(|i: usize| {i >= r.len() || r[i][0].is_some()})))
    }
    //hax_lib::assert_prop!(hax_lib::forall(|i: usize| {i >= r.len() || r[i][0].is_some()}));
    hax_lib::assert!(r.len() == d + 1);
    hax_lib::assert_prop!(hax_lib::implies(r.len() == d + 1, hax_lib::forall(|i: usize| {i >= r.len() || r[i].len() == sds.len()})));
    hax_lib::assert!(r[d].len() == sds.len());
    let u = r[d][0];
    //hax_lib::assert!(u.is_some());
    //(u.expect("Should be some"), v)
    (u, v)
}

#[hax_lib::opaque] // opaque when verifying sign
#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::ensures(|result| hax_lib::forall(|i: usize|
        i >= result.4.len()
        || (i < tau_0 && result.4[i].len() == k_0)
        || (i >= tau_0 && result.4[i].len() == k_1))
.and(hax_lib::forall(|i: usize|
        i >= result.4.len()
        || (i < tau_0 && matches!(result.1[i].2, sized_array_for_coms::sized_array_1(_)))
        || (i >= tau_0 && matches!(result.1[i].2, sized_array_for_coms::sized_array_2(_)))))
)]
pub fn FAEST_VOLE_commit(r: [u8; 16], iv: [u8; 16]) -> ([u8; 32], [([u8;16], [u8;16], sized_array_for_coms); tau], [[u8;234]; tau_minus_one], [u8; 234], [sized_array_for_q_v;tau]) {
    let new_r = prg_vole_commit_r(r, iv);
    // extract all r's

    let mut arr_of_rs: [[u8; 16]; 11] = [[0; 16]; 11];

    for i in 0..11 {
        hax_lib::loop_invariant!(|i: usize| {
            i <= 11
            && i << 4 <= new_r.len()
        });
        hax_lib::assert!((i + 1) << 4 <= new_r.len());
        arr_of_rs[i] = new_r[i << 4..(i + 1) << 4].try_into().unwrap();
        hax_lib::assert!((i + 1) << 4 <= new_r.len());
    }
    // big V
    let mut big_v:  [sized_array_for_q_v;tau] = [sized_array_for_q_v::sized_array_1([[0u8;234];k_0]);tau];

    let mut big_u: [[u8;234];tau] = [[0;234];tau];
    let mut all_decoms : [([u8;16], [u8;16], sized_array_for_coms);tau] = [([0;16], [0;16], sized_array_for_coms::sized_array_1([[0u8;32];k_0_pow]));tau];

    hax_lib::assert_prop!(hax_lib::forall(|j: usize| j >= all_decoms.len()
                    || matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_))));

    let mut commitments : [[u8; 32];tau] = [[0;32];tau];
    // iterate over r's
    // this loop should be made able to be thread

    for i in 0..tau_0 {
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::forall(|j: usize|
            hax_lib::Prop::from(j >= i)
            .or(hax_lib::Prop::from((j < tau_0 && big_v[j].len() == k_0)))
            .or(hax_lib::Prop::from((j >= tau_0 && big_v[j].len() == k_1))))
            .and(hax_lib::forall(|j: usize| j >= all_decoms.len()
                    || matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_))))
        });

        let (h, decoms, u, v) = {
            let (h, decoms, seeds) = vec_commit_k0(arr_of_rs[i], iv, k_0 as i128);
            let (u,v) = convert_to_VOLE::<k_0>(&seeds, iv);
            (h, decoms, u, sized_array_for_q_v::sized_array_1(v)) };

        hax_lib::assert!(matches!(decoms.2, sized_array_for_coms::sized_array_1(_)));

        big_v[i] = v;
        big_u[i] = u;
        all_decoms[i] = decoms;
        commitments[i] = h;
        hax_lib::assert_prop!(hax_lib::forall(|j: usize|
            j > i
            || (j < tau_0 && big_v[j].len() == k_0)
            || (j >= tau_0 && big_v[j].len() == k_1)));
        hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= all_decoms.len() || (matches!(all_decoms[i].2, sized_array_for_coms::sized_array_1(_)))));
    }
    hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= all_decoms.len() || (matches!(all_decoms[i].2, sized_array_for_coms::sized_array_1(_)))));

    //hax_lib::assert_prop!(hax_lib::forall(|j: usize| hax_lib::Prop::from(j >= all_decoms.len())
    //                .or((hax_lib::Prop::from(j < tau_0).and(hax_lib::implies(j < tau_0, matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_))))))));

    for i in tau_0..tau {
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::forall(|j: usize|
            hax_lib::Prop::from(j >= i)
            .or(hax_lib::Prop::from((j < tau_0 && big_v[j].len() == k_0)))
            .or(hax_lib::Prop::from((j >= tau_0 && big_v[j].len() == k_1))))
            .and(hax_lib::forall(|j: usize| j >= i
                || (j < tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_)))
                || (j >= tau_0 && j < i && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_2(_)))))
        });

        let (h, decoms, u, v) = {
            let (h, decoms, seeds) = vec_commit_k1(arr_of_rs[i], iv, k_1 as i128);
            let (u,v) = convert_to_VOLE::<k_1>(&seeds, iv);
            (h, decoms, u, sized_array_for_q_v::sized_array_2(v)) };

        hax_lib::assert!(matches!(decoms.2, sized_array_for_coms::sized_array_2(_)));

        big_v[i] = v;
        big_u[i] = u;
        all_decoms[i] = decoms;
        commitments[i] = h;
        hax_lib::assert_prop!(hax_lib::forall(|j: usize|
            j > i
            || (j < tau_0 && big_v[j].len() == k_0)
            || (j >= tau_0 && big_v[j].len() == k_1)));
        hax_lib::assert_prop!(hax_lib::forall(|j: usize|
            j > i
            || (j < tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_)))
            || (j >= tau_0 && j <= i && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_2(_)))));
        hax_lib::assert_prop!(hax_lib::implies(
            hax_lib::Prop::from(i == tau - 1).and(
                hax_lib::forall(|j: usize|
                    j > i
                    || (j < tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_)))
                    || (j >= tau_0 && j <= i && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_2(_))))),
            hax_lib::forall(|j: usize|
                j >= all_decoms.len()
                || (j < tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_)))
                || (j >= tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_2(_))))))
    }

    hax_lib::assert_prop!(hax_lib::forall(|j: usize|
            j >= all_decoms.len()
            || (j < tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_)))
            || (j >= tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_2(_)))));

    let u_0 = big_u[0];

    let mut big_c: [[u8;234]; tau_minus_one] = [[0u8; 234]; tau_minus_one];
    for i in 0..tau{
        if i > 0 {
            big_c[i-1] = xor_arrays(&u_0, &big_u[i]);
        }
    }
    let coms_flat: [u8; tau * 32] = flatten::<tau, 32, {tau * 32}>(commitments);

    let hash = h_1_for_352(&coms_flat);


    hax_lib::assert_prop!(hax_lib::forall(|i: usize|
        i >= big_v.len()
        || (i < tau_0 && big_v[i].len() == k_0)
        || (i >= tau_0 && big_v[i].len() == k_1)));
    hax_lib::assert_prop!(hax_lib::forall(|j: usize|
            j >= all_decoms.len()
            || (j < tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_1(_)))
            || (j >= tau_0 && matches!(all_decoms[j].2, sized_array_for_coms::sized_array_2(_)))));
    (hash, all_decoms, big_c, u_0, big_v)
}

#[hax_lib::requires(i < tau_0)]
#[hax_lib::ensures(|result| hax_lib::forall(|i: usize| i >= result.len() || result[i] <= 1))]
pub fn chall_dec_k0(chall: [u8; 16], i: usize) -> [u8; k_0] {
    let lo = i * k_0;

    let mut bits = [0u8; k_0];

    hax_lib::assert_prop!(hax_lib::forall(|j: usize| j >= bits.len() || bits[j] <= 1));
    for idx in 0..k_0 {
        hax_lib::loop_invariant!(
            hax_lib::Prop::from(idx <= k_0)
            .and(hax_lib::Prop::from(lo + k_0 - 1 < 128))
            .and(hax_lib::Prop::from((lo + k_0 - 1) >> 3 < 16))
            .and(hax_lib::Prop::from(
                hax_lib::forall(|j: usize| j >= idx || bits[j] <= 1)
            ))
            .and(hax_lib::Prop::from(
                hax_lib::forall(|j: usize| j < idx || j >= k_0 || bits[j] == 0)
            ))
        );

        let b = lo + idx;
        let byte_index = b >> 3;
        let bit_index = b % 8;
        let val = math::bitand_mod(chall[byte_index] >> bit_index, 1);
        assert!(val <= 1);
        bits[idx] = val;
    }
    hax_lib::assume!(hax_lib::forall(|j: usize| j >= bits.len() || bits[j] <= 1));
    bits
}

#[hax_lib::requires(i >= tau_0 && i < tau)]
#[hax_lib::ensures(|result| hax_lib::forall(|i: usize| i >= result.len() || result[i] <= 1))]
pub fn chall_dec_k1(chall: [u8; 16], i: usize) -> [u8; k_1] {
    let t = i - tau_0;
    let lo = tau_0 * k_0 + t * k_1;

    let mut bits = [0u8; k_1];

    hax_lib::assert_prop!(hax_lib::forall(|j: usize| j >= bits.len() || bits[j] <= 1));
    for idx in 0..11 {
        hax_lib::loop_invariant!(
            hax_lib::Prop::from(idx <= 12)
            .and(hax_lib::Prop::from((lo + idx) >> 3 < 16))
            .and(hax_lib::Prop::from(
                hax_lib::forall(|j: usize| j >= idx || bits[j] <= 1)
            ))
            .and(hax_lib::Prop::from(
                hax_lib::forall(|j: usize| j < idx || j >= k_0 || bits[j] == 0)
            ))
        );

        let b = lo + idx;
        let byte_index = b >> 3;
        let bit_index = b % 8;
        let val = math::bitand_mod(chall[byte_index] >> bit_index, 1);
        assert!(val <= 1);
        bits[idx] = val;
    }
    hax_lib::assume!(hax_lib::forall(|j: usize| j >= bits.len() || bits[j] <= 1));
    bits
}

#[hax_lib::opaque] // opaque when verifying verify
#[hax_lib::fstar::options("--z3rlimit 750")]
#[hax_lib::requires(hax_lib::forall(|i: usize|
        i >= pdecoms.len()
        || (i < tau_0 && matches!(pdecoms[i].0, sized_array_for_cop::sized_array_1(_)))
        || (i >= tau_0 && matches!(pdecoms[i].0, sized_array_for_cop::sized_array_2(_)))
))]
#[hax_lib::ensures(|result| hax_lib::forall(
        |i: usize| i >= result.1.len()
        || (i < tau_0 && result.1[i].len() == k_0)
        || (i >= tau_0 && result.1[i].len() == k_1)))]
pub fn FAEST_VOLE_reconstruct(chall: [u8;16], pdecoms: &[(sized_array_for_cop, [u8; 32]); 11], iv : [u8;16]) -> ([u8;32], [sized_array_for_q_v;tau]){
    let mut commitments : [[u8; 32];tau] = [[0;32];tau];
    let mut big_q:  [sized_array_for_q_v;tau] =  [sized_array_for_q_v::sized_array_1([[0u8;234];k_0]);tau];

    for i in 0..tau{
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::Prop::from(i <= tau)
            .and(hax_lib::forall(|j: usize|
                j >= i
                || (j < tau_0 && matches!(big_q[j], sized_array_for_q_v::sized_array_1(_)))
                || (j >= tau_0 && matches!(big_q[j], sized_array_for_q_v::sized_array_2(_)))))
            .and(hax_lib::forall(|j: usize|
                j >= i
                || (j < tau_0 && big_q[j].len() == k_0)
                || (j >= tau_0 && big_q[j].len() == k_1)))
        });
        #[cfg(not(hax))]
        let _loop_start = std::time::Instant::now();
        //hax_lib::Prop::from(matches!(pdecom.0, sized_array_for_cop::sized_array_1(_)))
        //                     .and(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1)))]
        if i < tau_0 {
            let b = chall_dec_k0(chall, i);
            hax_lib::assert!(matches!(pdecoms[i].0, sized_array_for_cop::sized_array_1(_)));
            hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1));
            let (com,sds) = vec_reconstruct_k0(&pdecoms[i], b.clone(), iv);
            let sds: &[[u8; 16]] = match &sds {
                sized_array_for_sds::sized_array_1(inner) => inner.as_slice(),
                _ => panic!("unreachable")
            };
            let N_b = sds.len();
            hax_lib::assert!(N_b == 4096);
            hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1));
            let delta = num_rec_k0(&b);
            hax_lib::assert!(delta < 4096);
            let mut sd_updated_verifier: [[u8;16];k_0_pow] = [[0;16];k_0_pow];
            for j in 1..N_b {
                hax_lib::loop_invariant!(|j: usize| {
                    j <= N_b
                });
                sd_updated_verifier[j] = sds[xor_with_bound(j, delta as usize, Log2Number::wrap(4096))];
            }
            let sds_for_later_use :  sized_array_for_sds = sized_array_for_sds::sized_array_1(sd_updated_verifier);
            let (_u_mark, q) = convert_to_VOLE::<k_0>(&sds_for_later_use, iv);
            let (_u_mark, q) = (_u_mark, sized_array_for_q_v::sized_array_1(q));

            commitments[i] = com;
            big_q[i] = q;
            hax_lib::assert_prop!(matches!(big_q[i], sized_array_for_q_v::sized_array_1(_)));
            hax_lib::assert!(big_q[i].len() == k_0);

        } else {
            hax_lib::assert!(i >= tau_0);
            let b = chall_dec_k1(chall, i);
            hax_lib::assert!(matches!(pdecoms[i].0, sized_array_for_cop::sized_array_2(_)));
            hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1));
            let (com,sds) = vec_reconstruct_k1(&pdecoms[i], b.clone(), iv);
            let sds: &[[u8; 16]] = match &sds {
                sized_array_for_sds::sized_array_1(inner) => inner.as_slice(),
                sized_array_for_sds::sized_array_2(inner) => inner.as_slice(),
            };
            let N_b = sds.len();
            hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1));
            let delta = num_rec_k1(&b);

            let mut sd_updated_verifier: [[u8;16];k_1_pow] = [[0;16];k_1_pow];
            for j in 1..N_b {
                hax_lib::loop_invariant!(|j: usize| {
                    j <= N_b
                });
                sd_updated_verifier[j] = sds[xor_with_bound(j, delta as usize, Log2Number::wrap(2048))];
            }
            let sds_for_later_use :  sized_array_for_sds = sized_array_for_sds::sized_array_2(sd_updated_verifier);
            let (_u_mark, q) = convert_to_VOLE::<k_1>(&sds_for_later_use, iv);
            let (_u_mark, q) = (_u_mark, sized_array_for_q_v::sized_array_2(q));

            commitments[i] = com;
            big_q[i] = q;
            hax_lib::assert_prop!(matches!(big_q[i], sized_array_for_q_v::sized_array_2(_)));
            hax_lib::assert!(big_q[i].len() == k_1);
        };
        hax_lib::assert_prop!(hax_lib::forall(|j: usize|
            hax_lib::Prop::from(j > i)
            .or(hax_lib::Prop::from(j < tau_0).and(hax_lib::implies(
            matches!(big_q[j], sized_array_for_q_v::sized_array_1(_)), big_q[j].len() == k_0)))
            .or(hax_lib::Prop::from(j >= tau_0).and(hax_lib::implies(
            matches!(big_q[j], sized_array_for_q_v::sized_array_2(_)), big_q[j].len() == k_1)))));
        hax_lib::assert_prop!(hax_lib::forall(
            |j: usize| j > i
            || (j < tau_0 && big_q[j].len() == k_0)
            || (j >= tau_0 && big_q[j].len() == k_1)));

        // println!("end of loop_reconstruct took: {:?}", loop_start.elapsed());
    }
    hax_lib::assert_prop!(hax_lib::forall(|i: usize|
        hax_lib::Prop::from(i >= big_q.len())
        .or(hax_lib::Prop::from(i < tau_0).and(hax_lib::implies(
            matches!(big_q[i], sized_array_for_q_v::sized_array_1(_)), big_q[i].len() == k_0)))
        .or(hax_lib::Prop::from(i >= tau_0).and(hax_lib::implies(
            matches!(big_q[i], sized_array_for_q_v::sized_array_2(_)), big_q[i].len() == k_1)))));
    hax_lib::assert_prop!(hax_lib::forall(
        |i: usize| i >= big_q.len()
        || (i < tau_0 && big_q[i].len() == k_0)
        || (i >= tau_0 && big_q[i].len() == k_1)));
    let coms_flat: [u8; tau * 32] = flatten::<tau, 32, {tau * 32}>(commitments);
    let hash = h_1_for_352(&coms_flat);
    (hash, big_q)
}