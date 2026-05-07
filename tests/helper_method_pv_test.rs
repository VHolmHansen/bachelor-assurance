mod tests{
    use bachelor_assurance::utils::constants::lambda;
    use bachelor_assurance::utils::galois_field::gf128_mul;
    use bachelor_assurance::utils::helper_methods_prove_verify::{to_bits, to_field, zk_hash};
    use bachelor_assurance::utils::math::xor_arrays;

    // tests that the helper methods work
    #[test]
    fn test_to_bits_to_field_inverse() {
        let bits: [u8; 16] = [1,0,1,1,0,0,0,0, 0,1,0,0,0,0,0,0];
        let field_elems: [[u8; 16]; 2] = to_field::<16, 8, 2>(&bits);
        let mut bits_back = [0u8; 16];
        to_bits::<2, 8, 16>(&field_elems, &mut bits_back);
        assert_eq!(bits, bits_back);
    }

    #[test]
    fn zk_hash_test(){
        let x: [u8;16] = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let y: [u8;16] = [2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let z: [u8;16] = [3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let chall_3: [u8; lambda] = [1,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,
            0,1,0,1,1,0,1,0,0,1,1,1,0,0,1,0,
            1,1,0,0,1,0,1,1,0,1,0,0,1,1,1,0,
            0,1,1,0,0,1,0,1,1,0,1,0,0,1,1,1,
            1,0,0,1,0,1,1,0,0,1,1,0,1,0,1,0,
            0,1,1,1,0,0,1,0,1,1,0,1,0,0,1,1,
            1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,
            1,1,0,1,0,0,1,1,1,0,0,1,0,1,1,0];
        let delta_field = to_field::<128,128,1>(&chall_3)[0];
        let zero = [0u8;16];

        let chall_2: [u8; 3 * lambda + 64] = {
            let mut arr = [0u8; 3 * lambda + 64];
            for i in 0..3 * lambda + 64 {
                arr[i] = (i % 2) as u8;
            }
            arr
        };

        // Test x1 linearity
        let h1 = zk_hash(&chall_2, &[x, y], &z);
        let h2 = xor_arrays(&zk_hash(&chall_2, &[x, y], &zero), &z);
        println!("x1 linearity: h1={:?}", h1);
        println!("x1 linearity: h2={:?}", h2);
        assert_eq!(h1, h2, "x1 not linear");

        // Test x0 linearity with length 2
        let hx = zk_hash(&chall_2, &[x, zero], &zero);
        let hy = zk_hash(&chall_2, &[zero, y], &zero);
        let hxy = zk_hash(&chall_2, &[x, y], &zero);
        let hx_plus_hy = xor_arrays(&hx, &hy);
        println!("x0 linearity len2: hx+hy={:?}", hx_plus_hy);
        println!("x0 linearity len2: hxy  ={:?}", hxy);
        assert_eq!(hx_plus_hy, hxy, "x0 not linear for length 2");


        let delta_val: [u8;16] = [77, 157, 90, 78, 211, 114, 166, 229, 105, 86, 78, 203, 229, 50, 203, 105];
        let x0_test: Vec<[u8;16]> = (0..320).map(|i| {
            let mut v = [0u8;16];
            v[0] = (i % 256) as u8;
            v
        }).collect();
        let x1_test: [u8;16] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];

        let delta_x0: Vec<[u8;16]> = x0_test.iter().map(|xi| gf128_mul(xi, &delta_val)).collect();
        let delta_x1 = gf128_mul(&x1_test, &delta_val);

        let hash_x = zk_hash(&chall_2, &x0_test, &x1_test);
        let hash_delta_x = zk_hash(&chall_2, &delta_x0, &delta_x1);
        let delta_hash_x = gf128_mul(&hash_x, &delta_val);
        
        assert_eq!(hash_delta_x, delta_hash_x, "zk_hash not homogeneous!");
    }
}