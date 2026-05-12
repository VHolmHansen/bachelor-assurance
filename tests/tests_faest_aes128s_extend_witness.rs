#[cfg(all(test, feature = "lambda_128s"))]
mod tests{
    use bachelor_assurance::protocols::aes::{add_round_key, encrypt, gf2_affine_transform, key_expansion, mix_columns, shift_rows, sub_bytes};
    use bachelor_assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use bachelor_assurance::protocols::faest_key_gen::faest_key_gen;
    use bachelor_assurance::utils::constants::{ell, lambda_bytes, nk, nst, S_ke, LAMBDA, R};
    use bachelor_assurance::utils::galois_field;
    use bachelor_assurance::utils::helper_methods_cstrnts::{bits_to_byte, byte_to_bits};
    use bachelor_assurance::utils::math::transform_byte_array_to_state;
    use bachelor_assurance::utils::preliminary_helper_methods::flatten;
    use bachelor_assurance::utils::types::{Pk, Word};

    #[test]
    fn test_extend_witness_impl(){
        let (sk, pk) = faest_key_gen();
        let witness = faest_aes_extend_witness(sk, pk);

        // first check is to check that the key is in the first lambda_bytes*8 bits of the witness
        let key_of_witness : [u8;lambda_bytes*8] = witness[0..lambda_bytes*8].try_into().unwrap();
        let sk_bits = bytes_to_bits(sk);

        assert_eq!(key_of_witness, sk_bits);

        // Key expansion, finding non-linear bits, every fourth word from key_expansion
        let key = key_expansion(sk);
        let key_flat: [u8; (R+1) << 4] = flatten::<{(R+1) << 2}, 4, {(R+1) << 4}>(key);
        let mut ik = nk;
        let mut nonlin_offset = lambda_bytes * 8;
        for _ in 0..(S_ke >> 2) {
            let mut expected_word: Vec<u8> = Vec::new();
            for byte_idx in (ik << 2)..((ik+1) << 2) {
                let bits = byte_to_bits(key_flat[byte_idx]);
                for bit in bits { expected_word.push(bit); }
            }
            assert_eq!(&witness[nonlin_offset..nonlin_offset+32], expected_word.as_slice(),
                       "Non-linear word bits mismatch at ik={ik}");
            nonlin_offset += 32;
            ik = if LAMBDA == 192 { ik+6 } else { ik+4 };
        }
        // key_expansion ends

        // get plaintext
        let pt = pk[0].0;
        // get plaintext as bytes
        let pt_bytes = bits_to_bytes(pt);
        let pt_state = transform_byte_array_to_state(&pt_bytes);

        // completely copied encryption routine, shift row bits
        let mut res_state = pt_state;
        add_round_key(&mut res_state, key[0..nst].try_into().unwrap());

        let mut shift_offset = lambda_bytes * 8 + S_ke * 8;
        for r in 1..R {
            sub_bytes(&mut res_state);
            shift_rows(&mut res_state);

            // check shift row bits for this round
            let expected_round: Vec<u8> = (0..4).flat_map(|col| (0..4)
                .flat_map(move |row| byte_to_bits(res_state[col][row])))
                .collect();
            assert_eq!(&witness[shift_offset..shift_offset+128], expected_round.as_slice(),
                       "ShiftRows bits mismatch at round {r}");
            shift_offset += 128;

            mix_columns(&mut res_state);
            add_round_key(&mut res_state, key[(r << 2)..((r+1) << 2)].try_into().unwrap());
        }

        sub_bytes(&mut res_state);
        shift_rows(&mut res_state);
        add_round_key(&mut res_state, key[(R << 2)..(R+1) << 2].try_into().unwrap());
        // encryption routine ends here

        // total length check
        assert_eq!(witness.len(), ell, "Witness length mismatch");
    }

    // a test for testing that we match the reference implementation
    #[test]
    fn test_extend_witness_test_vector_from_ref(){
        let key: [u8; lambda_bytes] = [
            0x42, 0x13, 0x4f, 0x71, 0x34, 0x89, 0x1b, 0x16,
            0x82, 0xa8, 0xab, 0x56, 0x76, 0x27, 0x30, 0x0c,
        ];
        let input: [u8; 16] = [
            0x7b, 0x60, 0x66, 0xd6, 0x5a, 0x73, 0xd6, 0x00,
            0xa0, 0xae, 0xf0, 0x1c, 0x8b, 0x19, 0x17, 0x40,
        ];

        let input_bits = bytes_to_bits(input);
        let output_bits = bytes_to_bits([
            0x89, 0x13, 0xaf, 0x07, 0x31, 0xb5, 0x81, 0xdf,
            0x8a, 0x0a, 0xb5, 0x6e, 0x08, 0x3c, 0x6b, 0x7c,
        ]);
        let pk: Pk = [(input_bits, output_bits)];

        let witness = faest_aes_extend_witness(key, pk);

        let mut expected_bits = [0u8; ell];
        for i in 0..200 {
            let bits = byte_to_bits(expected_witness_bytes[i]);
            for b in 0..8 {
                expected_bits[i * 8 + b] = bits[b];
            }
        }

        assert_eq!(witness, expected_bits, "Witness does not match reference test vector");

    }



    fn bytes_to_bits(sk : [u8;lambda_bytes]) -> [u8;lambda_bytes*8]{
        let mut bits = [0u8;128];
        for j in 0..lambda_bytes{
            let byte = sk[j];
            for i in 0..8 {
                bits[i+j*8] = (byte >> i) & 1;
            }
        }

        bits
    }
    fn bits_to_bytes(sk : [u8; lambda_bytes*8]) -> [u8;lambda_bytes]{
        let mut bytes = [0u8;lambda_bytes];
        for i in 0..lambda_bytes{
            let mut byte_val = 0;
            for j in 0..8 {
                byte_val += (sk[i*8+j] << j)
            }
            bytes[i] = byte_val;
        }
        bytes
    }
    fn sub_word(word: Word) -> Word {
        let mut result: Word = [0; 4];
        for i in 0..4 {
            result[i] = gf2_affine_transform(galois_field::gf28_inverse(word[i]));
        }
        result
    }
    fn rot_word(word: Word) -> Word {
        [word[1], word[2], word[3], word[0]]
    }
    const RCON_TABLE : [u8;11] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108];

    const expected_witness_bytes: [u8; 200] = [
    0x42, 0x13, 0x4f, 0x71, 0x34, 0x89, 0x1b, 0x16, 0x82, 0xa8, 0xab, 0x56, 0x76, 0x27, 0x30,
    0x0c, 0x8f, 0x17, 0xb1, 0x49, 0x0f, 0xd0, 0xda, 0xcd, 0xf2, 0xd9, 0xd1, 0xe8, 0xbe, 0xb9,
    0x03, 0xe9, 0x0e, 0x21, 0xd4, 0x69, 0x89, 0xaf, 0x43, 0x7f, 0x5d, 0xa1, 0x87, 0x11, 0x19,
    0x81, 0x05, 0xd0, 0x87, 0x51, 0x4e, 0x23, 0x7a, 0xc4, 0x76, 0xcc, 0x12, 0x2d, 0x39, 0x29,
    0x9f, 0x6f, 0xcc, 0x5c, 0x93, 0xb2, 0xa5, 0x47, 0x54, 0x8f, 0xbd, 0xd6, 0x4b, 0x4b, 0x6c,
    0x10, 0x08, 0xf9, 0x87, 0x12, 0xf1, 0xd6, 0x17, 0xbb, 0x6f, 0x27, 0x27, 0xb2, 0x07, 0x15,
    0xe4, 0x53, 0xfd, 0x65, 0x3d, 0xf0, 0x56, 0xdc, 0x23, 0x70, 0xe1, 0xd3, 0x3a, 0x75, 0x92,
    0xf0, 0x64, 0x1b, 0xa6, 0x76, 0x3b, 0x4e, 0xb3, 0xf8, 0xd9, 0xa6, 0xa1, 0x60, 0x52, 0xf2,
    0xe6, 0x85, 0xef, 0x07, 0x09, 0x84, 0x7e, 0x8e, 0x93, 0x93, 0x5f, 0x6d, 0xfb, 0x85, 0xf6,
    0x74, 0x06, 0xd4, 0xd7, 0x30, 0xec, 0xce, 0x0d, 0xeb, 0x43, 0x47, 0x21, 0x9c, 0xf2, 0x0f,
    0x19, 0x04, 0x6b, 0x9a, 0xe8, 0x14, 0x7d, 0x4a, 0xfa, 0x47, 0x52, 0x36, 0x92, 0x49, 0x4e,
    0x52, 0xf1, 0x5d, 0x25, 0xf4, 0x7b, 0x57, 0xea, 0xd5, 0xb1, 0x42, 0x7a, 0x9a, 0x0c, 0xd8,
    0xaf, 0xb5, 0x0a, 0xcb, 0xbc, 0xd1, 0x08, 0xfa, 0xfb, 0x38, 0x34, 0x0b, 0x05, 0x50, 0xb9,
    0x0c, 0xb2, 0x5d, 0x9a, 0x9f,
    ];

}