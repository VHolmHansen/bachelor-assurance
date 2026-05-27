#[cfg(test)]
mod tests{
    use bachelor_assurance::protocols::fs_vole::{chall_dec_k0, FAEST_VOLE_commit};
    use bachelor_assurance::utils::constants::{k_0, k_1, tau, tau_0};
    use bachelor_assurance::utils::ggm_tree::get_leaves_node_from_root;
    use bachelor_assurance::utils::hash_functions::h_0;
    use bachelor_assurance::utils::preliminary_helper_methods::{num_rec_k0, num_rec_k1};
    use bachelor_assurance::utils::types::{sized_array_for_coms, sized_array_for_cop};
    use bachelor_assurance::utils::vector_commit::{vec_commit_k0, vec_commit_k1, vec_open_k0, vec_open_k1, vec_reconstruct_k0, vec_reconstruct_k1};

    // helper since we don't have a generic bit_dec, only num_rec_k0/k1
    fn bit_dec(index: u64, depth: usize) -> Vec<u8> {
        let mut out = vec![0u8; depth];
        let mut idx = index;
        for j in 0..depth {
            out[j] = (idx % 2) as u8;
            idx /= 2;
        }
        out
    }
    #[test]
    fn test_numrec_bitdec() {
        // test 1: BitDec(2, 2) -> {0x00, 0x01}, NumRec = 2
        let b_1 = bit_dec(2, 2);
        assert_eq!(b_1, vec![0x00, 0x01]);
        let idx_1: u64 = b_1.iter().enumerate().map(|(i, &b)| (b as u64) * (1u64 << i)).sum();
        assert_eq!(idx_1, 2);

        // test 2: BitDec(7, 4) -> {0x01, 0x01, 0x01, 0x00}, NumRec = 7
        let b_2 = bit_dec(7, 4);
        assert_eq!(b_2, vec![0x01, 0x01, 0x01, 0x00]);
        let idx_2: u64 = b_2.iter().enumerate().map(|(i, &b)| (b as u64) * (1u64 << i)).sum();
        assert_eq!(idx_2, 7);

        // test 3: BitDec(10, 4) -> {0x00, 0x01, 0x00, 0x01}, NumRec = 10
        let b_3 = bit_dec(10, 4);
        assert_eq!(b_3, vec![0x00, 0x01, 0x00, 0x01]);
        let idx_3: u64 = b_3.iter().enumerate().map(|(i, &b)| (b as u64) * (1u64 << i)).sum();
        assert_eq!(idx_3, 10);

        // test 4: BitDec(13, 4) -> {0x01, 0x00, 0x01, 0x01}, NumRec = 13
        let b_4 = bit_dec(13, 4);
        assert_eq!(b_4, vec![0x01, 0x00, 0x01, 0x01]);
        let idx_4: u64 = b_4.iter().enumerate().map(|(i, &b)| (b as u64) * (1u64 << i)).sum();
        assert_eq!(idx_4, 13);
    }
    #[test]
    fn test_num_rec_k0_specific_values() {
        // test num_rec_k0 directly with known values
        let b: [u8; k_0] = {
            let mut arr = [0u8; k_0];
            let bits = bit_dec(13, k_0);
            arr.copy_from_slice(&bits);
            arr
        };
        assert_eq!(num_rec_k0(&b), 13);
    }
    const IV: [u8; 16] = [0x00; 16];
    const ROOT_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];

    #[test]
    fn test_vector_open_k0() {
        // leafIndex = 7, padded to k_0=12 bits
        let b: [u8; k_0] = [0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let leaf_index = num_rec_k0(&b);
        assert_eq!(leaf_index, 7); // sanity check

        let (h, decom, _sds) = vec_commit_k0(ROOT_KEY, IV, k_0 as i128);

        let (cop, com_j) = vec_open_k0(&decom, &b);

        // check 1: com_j matches the commitment stored at leafIndex during commit
        let expected_com_j = match &decom.2 {
            sized_array_for_coms::sized_array_1(inner) => inner[leaf_index as usize],
            _ => panic!("wrong variant")
        };
        assert_eq!(com_j, expected_com_j, "com_j should match stored commitment at leaf_index");

        // check 2: round-trip - reconstruct should reproduce the same hash
        let (rec_h, _) = vec_reconstruct_k0(&(cop, com_j), b, IV);
        assert_eq!(h, rec_h, "reconstructed hash should match original");
    }
    // Også en mindre
    #[test]
    fn test_vector_open_k1() {
        // leafIndex = 7, padded to k_1=11 bits
        let b: [u8; k_1] = [0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let leaf_index = num_rec_k1(&b);
        assert_eq!(leaf_index, 7);

        let (h, decom, _sds) = vec_commit_k1(ROOT_KEY, IV, k_1 as i128);

        let (cop, com_j) = vec_open_k1(&decom, &b);

        let expected_com_j = match &decom.2 {
            sized_array_for_coms::sized_array_2(inner) => inner[leaf_index as usize],
            _ => panic!("wrong variant")
        };
        assert_eq!(com_j, expected_com_j, "com_j should match stored commitment at leaf_index");

        let (rec_h, _) = vec_reconstruct_k1(&(cop, com_j), b, IV);
        assert_eq!(h, rec_h, "reconstructed hash should match original");
    }
    const ROOT_KEY_128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    // en omskrivning af deres test, siden vi ikke har mulighed for at køre vec_commit med 4, i stedet bygger vi træet direkte og matcher implementeringen
    #[test]
    fn test_vector_commit_depth_4() {
        // replicate the C test exactly: depth=4, 16 leaves
        let leaves = get_leaves_node_from_root::<16>(&ROOT_KEY_128, IV, 4);

        // compute sds and coms just like vec_commit does
        let mut sds  = [[0u8; 16]; 16];
        let mut coms = [[0u8; 32]; 16];
        for i in 0..16 {
            let (sd, com) = h_0(leaves[i], IV);
            sds[i]  = sd;
            coms[i] = com;
        }

        // check com[0] matches the expected value from C test vectors
        let expected_com_0: [u8; 32] = [
            0x8c, 0xee, 0xbb, 0x29, 0xff, 0x00, 0x29, 0xd5, 0xc0, 0x47, 0xce, 0x99, 0x5d, 0xea,
            0x94, 0x79, 0x54, 0xee, 0xdf, 0xa7, 0x04, 0x3b, 0x92, 0x53, 0x00, 0x84, 0x60, 0xbf,
            0x3c, 0x1c, 0x0d, 0x15,
        ];
        assert_eq!(coms[0], expected_com_0, "com[0] does not match C reference");
    }

}