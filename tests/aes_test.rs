
#[cfg(test)]
mod tests {
    use Bachelor_Assurance::protocols::aes::{add_round_key, gf2_affine_transform, mix_columns, shift_rows, sub_bytes};
    use Bachelor_Assurance::protocols::aes;
    use Bachelor_Assurance::utils::types::*;
    use Bachelor_Assurance::utils::galois_field::*;
    use Bachelor_Assurance::utils::math::{transform_byte_array_to_state, transform_state_to_array};

    #[test]
    fn test_encrypt() {

        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let plaintext: [[u8; 4]; 4] = [
            [0x00, 0x11, 0x22, 0x33], [0x44, 0x55, 0x66, 0x77],
            [0x88, 0x99, 0xaa, 0xbb], [0xcc, 0xdd, 0xee, 0xff],
        ];

        let expected: [[u8; 4]; 4] = [
            [0x69, 0xc4, 0xe0, 0xd8], [0x6a, 0x7b, 0x04, 0x30],
            [0xd8, 0xcd, 0xb7, 0x80], [0x70, 0xb4, 0xc5, 0x5a],
        ];

        let key_mark = aes::key_expansion(key);

        assert_eq!(aes::encrypt(plaintext, &key_mark), expected);
    }

    #[test]
    fn test_encrypt2() {

        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        let plaintext: [[u8; 4]; 4] = [
            [0xf3, 0x44, 0x81, 0xec],
            [0x3c, 0xc6, 0x27, 0xba],
            [0xcd, 0x5d, 0xc3, 0xfb],
            [0x08, 0xf2, 0x73, 0xe6],
        ];

        let expected: [[u8; 4]; 4] = [
            [0x03, 0x36, 0x76, 0x3e],
            [0x96, 0x6d, 0x92, 0x59],
            [0x5a, 0x56, 0x7c, 0xc9],
            [0xce, 0x53, 0x7f, 0x5e],
        ];

        let key_mark = aes::key_expansion(key);

        assert_eq!(aes::encrypt(plaintext, &key_mark), expected);
    }

    #[test]
    fn test_encrypt3() {

        let key = [
            0x10, 0xa5, 0x88, 0x69,
            0xd7, 0x4b, 0xe5, 0xa3,
            0x74, 0xcf, 0x86, 0x7c,
            0xfb, 0x47, 0x38, 0x59
        ];

        let plaintext: [[u8; 4]; 4] = [
            [0x00, 0x00, 0x00, 0x00],  // col 0
            [0x00, 0x00, 0x00, 0x00],  // col 1
            [0x00, 0x00, 0x00, 0x00],  // col 2
            [0x00, 0x00, 0x00, 0x00],
        ];

        let expected: [[u8; 4]; 4] = [
            [0x6d, 0x25, 0x1e, 0x69],
            [0x44, 0xb0, 0x51, 0xe0],
            [0x4e, 0xaa, 0x6f, 0xb4],
            [0xdb, 0xf7, 0x84, 0x65],
        ];

        let key_mark = aes::key_expansion(key);

        assert_eq!(aes::encrypt(plaintext, &key_mark), expected);
    }

    #[test]
    fn test_encrypt4() {

        let key = [
            0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
            0xf0, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];

        let plaintext: [[u8; 4]; 4] = [
            [0x00, 0x00, 0x00, 0x00],  // col 0
            [0x00, 0x00, 0x00, 0x00],  // col 1
            [0x00, 0x00, 0x00, 0x00],  // col 2
            [0x00, 0x00, 0x00, 0x00],
        ];

        let expected: [[u8; 4]; 4] = [
            [0x35, 0x35, 0xd5, 0x65],
            [0xac, 0xe3, 0xf3, 0x1e],
            [0xb2, 0x49, 0xba, 0x2c],
            [0xc6, 0x76, 0x5d, 0x7a],
        ];

        let key_mark = aes::key_expansion(key);

        assert_eq!(aes::encrypt(plaintext, &key_mark), expected);
    }

    #[test]
    fn test_encrypt5() {
        let key = [
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];

        let plaintext: [[u8; 4]; 4] = [
            [0x58, 0xc8, 0xe0, 0x0b],
            [0x26, 0x31, 0x68, 0x6d],
            [0x54, 0xea, 0xb8, 0x4b],
            [0x91, 0xf0, 0xac, 0xa1],
        ];

        let expected: [[u8; 4]; 4] = [
            [0x08, 0xa4, 0xe2, 0xef],
            [0xec, 0x8a, 0x8e, 0x33],
            [0x12, 0xca, 0x74, 0x60],
            [0xb9, 0x04, 0x0b, 0xbf],
        ];

        let key_mark = aes::key_expansion(key);

        assert_eq!(aes::encrypt(plaintext, &key_mark), expected);
    }

    #[test]
    fn test_encrypt6_fips() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let plaintext = transform_byte_array_to_state(&[
                                                            0x32, 0x43, 0xf6, 0xa8,
                                                            0x88, 0x5a, 0x30, 0x8d,
                                                            0x31, 0x31, 0x98, 0xa2,
                                                            0xe0, 0x37, 0x07, 0x34,
                                                            ]);

        let expected = transform_byte_array_to_state(&[0x39, 0x25, 0x84, 0x1d,
                                                            0x02, 0xdc, 0x09, 0xfb,
                                                            0xdc, 0x11, 0x85, 0x97,
                                                            0x19, 0x6a, 0x0b, 0x32,
                                                            ]);

        let key_mark = aes::key_expansion(key);

        assert_eq!(aes::encrypt(plaintext, &key_mark), expected);
    }

    #[test]
    fn test_add_round_key_two_props() {
        let plaintext1: State = [[50, 67, 246, 168], [136, 90, 48, 141],
            [49, 49, 152, 162], [224, 55, 7, 52]];

        let mut plaintext2: State = [[50, 67, 246, 168], [136, 90, 48, 141],
            [49, 49, 152, 162], [224, 55, 7, 52]];

        let key: [Word; 4] = [[43, 126, 21, 22], [40, 174, 210, 166],
                                       [171, 247, 21, 136], [9, 207, 79, 60]];

        aes::add_round_key(&mut plaintext2, key.clone());
        aes::add_round_key(&mut plaintext2, key);
        assert_eq!(plaintext2, plaintext1);

        let zero_key: [[u8; 4]; 4] = [[0u8; 4]; 4];
        aes::add_round_key(&mut plaintext2, zero_key);
        assert_eq!(plaintext2, plaintext1);

    }

   #[test]
    fn test_key_expansion() {
        let key = [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60];

        let expected: Vec<Word> = vec![[43,  126, 21,  22], [40,  174, 210, 166], [171, 247, 21,  136], [9,   207, 79,  60],
            [160, 250, 254, 23], [136, 84,  44,  177], [35,  163, 57,  57], [42,  108, 118, 5], [242, 194, 149, 242],
            [122, 150, 185, 67], [89,  53,  128, 122], [115, 89,  246, 127], [61,  128, 71,  125],
            [71,  22,  254, 62], [30,  35,  126, 68], [109, 122, 136, 59], [239, 68,  165, 65], [168, 82,  91,  127],
            [182, 113, 37,  59], [219, 11,  173, 0], [212, 209, 198, 248]];

       let result = aes::key_expansion(key)[0..21].to_vec();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_gf2_affine_transformation() {

        let bytes: [u8; 6] = [0, 42, 69, 91, 128, 255];

        let expected: [u8; 6] = [99, 70, 199, 140, 236, 156];

        let mut result = vec![];
        for b in bytes.iter() {
            result.push(aes::gf2_affine_transform(*b))
        }

        let x = gf2_affine_transform(42 ^ 69);
        let y = gf2_affine_transform(42) ^ gf2_affine_transform(69) ^ 0x63;

        assert_eq!(x, y);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encrypt_debug() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let plaintext = transform_byte_array_to_state(&[
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ]);

        let key_mark = aes::key_expansion(key);
        let result = aes::encrypt(plaintext, &key_mark);

        // print as flat bytes using transform_state_to_array
        let result_bytes = transform_state_to_array(&result);
        println!("Result bytes: {:02x?}", result_bytes);
        println!("Result state: {:02x?}", result);
    }

    #[test]
    fn test_encrypt_round1_debug() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];

        let plaintext = transform_byte_array_to_state(&[
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ]);

        println!("Plaintext state: {:02x?}", plaintext);
        // FIPS-197 expected after loading:
        // col 0: [32, 88, 31, e0]
        // col 1: [43, 5a, 31, 37]
        // col 2: [f6, 30, 98, 07]
        // col 3: [a8, 8d, a2, 34]

        let key_mark = aes::key_expansion(key);

        let mut state = plaintext;

        // initial add round key
        add_round_key(&mut state, key_mark[0..4].try_into().unwrap());
        println!("After initial AddRoundKey: {:02x?}", state);
        // FIPS-197 expected:
        // col 0: [19, 3d, e3, be]
        // col 1: [eb, d4, fd, 91]
        // col 2: [5d, bf, 8d, a5]
        // col 3: [a6, 42, af, 68]

        sub_bytes(&mut state);
        println!("After SubBytes: {:02x?}", state);
        // FIPS-197 expected:
        // col 0: [d4, 27, 11, ae]
        // col 1: [e0, bf, b4, 41]  (wait, this doesn't look right either)

        shift_rows(&mut state);
        println!("After ShiftRows: {:02x?}", state);
        // FIPS-197 expected:
        // col 0: [d4, bf, 5d, 30]...
        // hmm let me reconsider

        mix_columns(&mut state);
        println!("After MixColumns: {:02x?}", state);

        add_round_key(&mut state, key_mark[4..8].try_into().unwrap());
        println!("After AddRoundKey: {:02x?}", state);
        // FIPS-197 expected end of round 1:
        // col 0: [54, 73, 31, 36]...
        println!("Key words 0..4: {:02x?}", key_mark[0..4].to_vec());

        let key_as_state = transform_byte_array_to_state(&key);
        println!("Key as state: {:02x?}", key_as_state);
    }
}