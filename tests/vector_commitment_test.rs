#[cfg(test)]
mod tests{
    use Bachelor_Assurance::utils::vector_commit::*;
    #[test]
    fn test_vector_commitment(){
        let n_d : i128 = 128;
        let d = n_d.ilog(2) as u64;
        let b : Vec<bool> = vec![false,true,false, false, false, false, false];
        let r : [u8; 16] = [0x03, 0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x2c, 0x0d, 0x0e, 0x0f];
        let iv : [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00];

        let (h, decom, sds) = vec_commit(r, iv, n_d);
        let pdecom = vec_open(decom, b.clone(), d);
        let good_or_bad = vec_verify(h, pdecom, b, iv);
        assert!(good_or_bad);
    }
}