#[cfg(test)]
mod tests {
    use Bachelor_Assurance::utils::vector_commit::{vec_commit, vec_open, vec_reconstruct};
    use Bachelor_Assurance::protocols::fs_vole::convert_to_VOLE;
    use Bachelor_Assurance::utils::math::xor_arrays;

    #[test]
    fn test_convert_to_vole_for_0(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let delta : u8 = 0;
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, n_d);
        let pdecom = vec_open(decom, delta, d);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta, iv);

        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];

        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ delta) as usize]
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (delta >> j) & 1 == 1{
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
    fn test_convert_to_vole_for_1(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let delta : u8 = 1;
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, n_d);
        let pdecom = vec_open(decom, delta, d);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta, iv);

        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];
        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ delta) as usize]
        }
        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (delta >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

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
        let delta : u8 = 27;
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, n_d);
        let pdecom = vec_open(decom, delta, d);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta, iv);

        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];
        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ delta) as usize]
        }
        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (delta >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

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
        let delta : u8 = 127;
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, n_d);
        let pdecom = vec_open(decom, delta, d);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta, iv);

        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];
        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ delta) as usize]
        }
        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (delta >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

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
        let delta : u8 = 54;
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h_prover, decom, sds_prover) = vec_commit(r, iv, n_d);
        let pdecom = vec_open(decom, delta, d);
        let (h_verifier, sds_verifier) = vec_reconstruct(pdecom, delta, iv);

        let (u, v) = convert_to_VOLE(sds_prover, iv);
        let N_b : u8 = sds_verifier.len() as u8;
        let mut sd_updated_verifier : Vec<[u8;16]>= vec![[0;16];128];
        for j in 1..N_b {
            sd_updated_verifier[j as usize] = sds_verifier[(j ^ delta) as usize]
        }
        let mut new_u : Vec<[u8;234]> = vec![[0;234];7];
        for j in 0..d {
            if (delta >> j) & 1 == 1{
                new_u[j as usize] = u
            }
        }

        let (u_mark, q) = convert_to_VOLE(sd_updated_verifier, iv);

        let mut q_from_prover = vec![[0;234];7];
        for j in 0..d {
            let q_from_prover_instans = xor_arrays::<234>(&v[j as usize], &new_u[j as usize]);
            q_from_prover[j as usize] = q_from_prover_instans;
        }

        assert_eq!(q, q_from_prover);
    }
}