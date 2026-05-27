#[cfg(test)]
mod tests{
    /*
    use Bachelor_Assurance::utils::preliminary_helper_methods::num_rec;
    use Bachelor_Assurance::utils::vector_commit::*;
    #[test]
    fn test_vector_commitment_b_is_0(){
        let d = 7;
        let b : Vec<u8> = vec![0,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    #[test]
    fn test_vector_commitment_b_is1(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    #[test]
    fn test_vector_commitment_b_is2(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![0,1,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    #[test]
    fn test_vector_commitment_b_is3(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,1,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }

    #[test]
    fn test_vector_commitment_b_is4(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![0,0,1,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }

    #[test]
    fn test_vector_commitment_b_is27(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,1,0,1,1,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    #[test]
    fn test_vector_commitment_b_is28(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![0,0,1,1,1,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }

    #[test]
    fn test_vector_commitment_b_is127(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,1,1,1,1,1,1];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        println!("bahh");
        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    // this is a very latge test that takes a long time to run
    // #[test]
    fn test_everything(){
        let n_d: i128 = 128;
        let d = n_d.ilog(2) as u64;
        let n = 7;

        let r: [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];

        let iv: [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        for mask in 0..(1 << n) {
            // build b from mask
            let b: Vec<u8> = (0..n)
                .map(|i| ((mask >> i) & 1) as u8)
                .collect();

            let (h, decom, sds) = vec_commit(r, iv, d as i128);
            let pdecom = vec_open(decom, b.clone(), d as i128);
            let good_or_bad = vec_verify(h, pdecom, b.clone(), iv, d as i128);
            assert!(good_or_bad, "failed for b = {:?}", num_rec(b, d));
        }
    }

    #[test]
    fn test_for_larger_than_128_for_0(){
        let n_d : i128 = 256;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![0,0,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        println!("bahh");
        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    #[test]
    fn test_for_larger_than_128_for_1(){
        let n_d : i128 = 256;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,0,0,0,0,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        println!("bahh");
        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }
    #[test]
    fn test_for_larger_than_128_for_255(){
        let n_d : i128 = 256;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,1,1,1,1,1,1,1];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        println!("bahh");
        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }

    #[test]
    fn test_for_larger_than_128_for_185(){
        let n_d : i128 = 256;
        let d = n_d.ilog(2) as u64;
        let b : Vec<u8> = vec![1,0,0,1,1,1,0,1];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        println!("bahh");
        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }

    #[test]
    fn test_for_d_is_11_for_185(){
        let d = 11;
        let b : Vec<u8> = vec![1,0,0,1,1,1,0,1,0,0,0];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];
        println!("bahh");
        let (h, decom, sds) = vec_commit(r, iv, d as i128);
        let pdecom = vec_open(decom, b.clone(), d as i128);
        let good_or_bad = vec_verify(h, pdecom, b, iv, d as i128);
        assert!(good_or_bad);
    }


     */

}