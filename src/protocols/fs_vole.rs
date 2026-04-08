use crate::utils::math::xor_arrays;
use crate::utils::types::{ell};
use crate::utils::prg::prg_convert_to_vole;
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

