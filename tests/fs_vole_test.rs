#[cfg(test)]
mod tests {

    use bachelor_assurance::protocols::fs_vole::{chall_dec, convert_to_VOLE, FAEST_VOLE_commit, FAEST_VOLE_reconstruct};
    use bachelor_assurance::utils::math::xor_arrays;
    
    use bachelor_assurance::utils::constants::{k_0, k_1, tau, tau_0};
    use bachelor_assurance::utils::vector_commit::{vec_commit_k0, vec_open_k0, vec_reconstruct_k0};

    /*
    #[test]
    fn test_convert_to_vole_for_0(){
        let delta : Vec<u8> = vec![0,0,0,0,0,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit_k0(r, iv, d as i128);
        let pdecom = vec_open_k0(&decom, delta.clone(), d as i128);
        let (h_verifier, sds_verifier) = vec_reconstruct_k0(&pdecom, delta.clone(), iv, d as i128);
        let b = num_rec(delta, delta.len() as usize) as u8;


        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ b) as usize]
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (b >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }
        let mut q_from_prover = vec![[0;234];7];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }

     */
    /*
    #[test]
    fn test_convert_to_vole_for_1(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let delta : Vec<u8> = vec![1,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, delta.clone(), d as i128);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta.clone(), iv, d as i128);
        let b = num_rec(delta, d) as u8;


        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ b) as usize]
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (b >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }
        let mut q_from_prover = vec![[0;234];7];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }

    #[test]
    fn test_convert_to_vole_for_27(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let delta : Vec<u8> = vec![1,1,0,1,1,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, delta.clone(), d as i128);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta.clone(), iv, d as i128);
        let b = num_rec(delta, d) as u8;


        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ b) as usize]
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (b >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }
        let mut q_from_prover = vec![[0;234];7];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }

    #[test]
    fn test_convert_to_vole_for_127(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let delta : Vec<u8> = vec![1,1,1,1,1,1,1];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, delta.clone(), d as i128);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta.clone(), iv, d as i128);
        let b = num_rec(delta, d) as u8;


        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ b) as usize]
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (b >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }
        let mut q_from_prover = vec![[0;234];7];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }
    #[test]
    fn test_convert_to_vole_for_54(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let delta : Vec<u8> = vec![0,1,1,0,1,1,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, delta.clone(), d as i128);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta.clone(), iv, d as i128);
        let b = num_rec(delta, d) as u8;


        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ b) as usize]
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (b >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }
        let mut q_from_prover = vec![[0;234];7];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }

    #[test]
    fn test_convert_to_vole_for_54_larger_b(){
        let n_d : i128 = 256;
        let d = n_d.ilog(2) as u64;
        let delta : Vec<u8> = vec![1,0,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, delta.clone(), d as i128);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta.clone(), iv, d as i128);
        let b = num_rec(delta, d);


        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b = sds_verifier.len() as u64;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16]; 2_i32.pow(d as u32) as usize];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ b) as usize]
        }
        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];d as usize];
        for j in 0..d {
            if (b >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }
        let mut q_from_prover = vec![[0;234];d as usize];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }

    #[test]
    fn test_faest_commit_and_reconstruct(){
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        let chall : [u8;16] = [0xaf, 0x02, 0x04, 0x03, 0x04, 0x13, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0f, 0x0e, 0x00];

        let (h_com, decoms, cs, u0, big_v) = FAEST_VOLE_commit(r, iv);

        let mut pdecoms : Vec<(Vec<[u8; 16]>,[u8; 32])> = vec![];

        for i in 0..tau{
            let b = chall_dec(chall, i);
            let current_k;
            if i < tau_0 {
                current_k = k_0;
            } else {
                current_k = k_1;
            }
            let pdecom = vec_open(decoms[i].clone(), b, current_k as i128);
            pdecoms.push(pdecom)
        }

        let (h_rec, big_q) = FAEST_VOLE_reconstruct(chall, pdecoms, iv);

        let largest_k;
        if k_0 > k_1{
            largest_k = k_0;
        } else {
            largest_k = k_1;
        }

        let mut q_from_prover : Vec<Vec<[u8;234]>> = vec![];

        for i in 0..tau{
            let current_k = if i < tau_0 { k_0 } else { k_1 };
            q_from_prover.push(vec![[0;234];current_k])
        }

        for i in 0..tau{
            let u_i = if i == 0 { u0 } else { xor_arrays::<234>(&u0, &cs[i]) };
            let b = chall_dec(chall, i);
            let current_k;
            if i < tau_0 {
                current_k = k_0;
            } else {
                current_k = k_1;
            }
            let delta = num_rec(b, current_k as u64);
            let mut new_u : Vec<[u8;234]> = vec![[0;234];current_k];
            for j in 0..current_k {
                if (delta >> j) & 1 == 1{
                    new_u[j] = u_i
                }
            }

            for j in 0..current_k {
                let q_from_prover_instans = xor_arrays::<234>(&big_v[i][j], &new_u[j]);
                q_from_prover[i][j] = q_from_prover_instans;
            }
        }

        for i in 0..tau{
            assert_eq!(q_from_prover[i], big_q[i]);
        }

        assert_eq!(h_com, h_rec);
    }
    #[test]
    fn test_faest_commit_and_reconstruct_chall_0(){
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        let chall : [u8;16] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let (h_com, decoms, cs, u0, big_v) = FAEST_VOLE_commit(r, iv);

        let mut pdecoms : Vec<(Vec<[u8; 16]>,[u8; 32])> = vec![];

        for i in 0..tau{
            let b = chall_dec(chall, i);
            let current_k;
            if i < tau_0 {
                current_k = k_0;
            } else {
                current_k = k_1;
            }
            let pdecom = vec_open(decoms[i].clone(), b, current_k as i128);
            pdecoms.push(pdecom)
        }

        let (h_rec, big_q) = FAEST_VOLE_reconstruct(chall, pdecoms, iv);
        for i in 0..tau{
            assert_eq!(big_q[i], big_v[i]);
        }

        assert_eq!(h_com, h_rec);


    }
    
     */

}