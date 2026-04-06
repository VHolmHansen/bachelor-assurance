
#[cfg(test)]
mod tests {
    use Bachelor_Assurance::protocols::aes::{gf2_affine_transform};
    use Bachelor_Assurance::protocols::aes;
    use Bachelor_Assurance::utils::types::*;
    use Bachelor_Assurance::utils::galois_field::*;

    #[test]
    fn test_encrypt() {

        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];

        let plaintext: [[u8; 4]; 4] = [
            [0x00, 0x44, 0x88, 0xcc],
            [0x11, 0x55, 0x99, 0xdd],
            [0x22, 0x66, 0xaa, 0xee],
            [0x33, 0x77, 0xbb, 0xff],
        ];

        let expected: [[u8; 4]; 4] = [
            [0x69, 0x6a, 0xd8, 0x70],
            [0xc4, 0x7b, 0xcd, 0xb4],
            [0xe0, 0x04, 0xb7, 0xc5],
            [0xd8, 0x30, 0x80, 0x5a],
        ];



        let key_mark = aes::key_expansion(key);

        println!("key = {:?}", key_mark);

        assert_eq!(aes::encrypt(plaintext, key_mark), expected);
    }

    #[test]
    fn test_add_round_key() {
        let mut plaintext: State = [[50, 67, 246, 168], [136, 90, 48, 141],
            [49, 49, 152, 162], [224, 55, 7, 52]];

        let key: Vec<Word> = vec![[43, 126, 21, 22], [40, 174, 210, 166],
                                       [171, 247, 21, 136], [9, 207, 79, 60]];

        let expected: State = [[25, 107, 93, 161], [246, 244, 199, 66], [36, 227, 141, 237], [246, 145, 143, 8]];

        aes::add_round_key(&mut plaintext, key);

        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_add_round_key_two_props() {
        let plaintext1: State = [[50, 67, 246, 168], [136, 90, 48, 141],
            [49, 49, 152, 162], [224, 55, 7, 52]];

        let mut plaintext2: State = [[50, 67, 246, 168], [136, 90, 48, 141],
            [49, 49, 152, 162], [224, 55, 7, 52]];

        let key: Vec<Word> = vec![[43, 126, 21, 22], [40, 174, 210, 166],
                                       [171, 247, 21, 136], [9, 207, 79, 60]];

        aes::add_round_key(&mut plaintext2, key.clone());
        aes::add_round_key(&mut plaintext2, key);
        assert_eq!(plaintext2, plaintext1);

        let zero_key: Vec<Word> = vec![[0u8; 4]; 4];
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

       println!("result: {:?}", result);

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

        println!("test_gf28_inverse result: {:?}", result);
        assert_eq!(x, y);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_shift_rows() {
        let mut state: State = [[19,  69,  0,   1  ],
            [1,   19,  69,  0  ],
            [0,   1,   19,  69 ],
            [69,  0,   1,   19 ]];

        let expected: State = [[19, 69, 0, 1],
            [19, 69, 0, 1],
            [19, 69, 0, 1],
            [19, 69, 0, 1]];
        aes::shift_rows(&mut state);

        assert_eq!(state, expected);
    }

    #[test]
    fn test_mix_columns() {
        let c = vec![vec![2, 3, 1, 1],
                                    vec![1, 2, 3, 1],
                                    vec![1, 1, 2, 3],
                                    vec![3, 1, 1, 2]];

        let mut state: State = [[19,  69,  0,   1  ],
                                [1,   19,  69,  0  ],
                                [0,   1,   19,  69 ],
                                [69,  0,   1,   19 ]];

        let expected: State = [[96, 190, 221, 84],
            [84, 96, 190, 221],
            [221, 84, 96, 190],
            [190, 221, 84, 96]];
        aes::mix_columns(&mut state);

        for c in 0..4 {
            println!(
                "col {} = {:?}",
                c,
                [state[0][c], state[1][c], state[2][c], state[3][c]]
            );
        }
        println!("{:?}", gf28_multiply(2, 200));
        println!("res00: {:?}", gf28_multiply(19, 2) ^
            gf28_multiply(3, 1) ^
            gf28_multiply(1, 0) ^
            gf28_multiply(1, 69));
        assert_eq!(state, expected);
    }
}