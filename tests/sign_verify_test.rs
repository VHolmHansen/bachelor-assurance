mod tests {
    use Bachelor_Assurance::protocols::faest_key_gen::faest_key_gen;
    use Bachelor_Assurance::protocols::faest_sign::faest_sign;
    use Bachelor_Assurance::protocols::faest_verify::faest_verify;
    use Bachelor_Assurance::protocols::fs_vole::{FAEST_VOLE_commit, chall_dec};
    use Bachelor_Assurance::utils::constants::tau;
    use Bachelor_Assurance::utils::hash_functions::{h_1_for_sign, h_2_3, h_3};
    use Bachelor_Assurance::utils::helper_methods_for_sign::chall3_to_bits;
    use Bachelor_Assurance::utils::types::Tree;

    #[test]
    fn sign_verify_test() {
        let key = [
            201, 162, 240, 157, 17, 221, 199, 249, 177, 157, 68, 52, 44, 101, 110, 159,
        ];
        let pk = (
            [
                1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
                0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1,
                1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
                0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0,
                1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0,
            ],
            [
                1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0,
                1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0,
                1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0,
                1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1,
            ],
        );

        let msg: &[u8] = b"hello world";
        let sig = faest_sign(msg, key, pk.clone());

        let test_work = faest_verify(msg, pk, sig);
        assert!(test_work);
    }
    #[test]
    fn sign_verify_test_random_key() {
        let (key, pk) = faest_key_gen();

        let msg: &[u8] = b"hello world";
        let sig = faest_sign(msg, key, pk.clone());

        let test_work = faest_verify(msg, pk, sig);
        assert!(test_work);
    }
    #[test]
    fn sign_verify_test_random_key_multiple() {
        let messages: Vec<&[u8]> = vec![
            b"hello world",
            b"the quick brown fox jumps over the lazy dog",
            b"FAEST signature scheme",
            b"post-quantum cryptography",
            b"",
            b"a",
            b"1234567890",
            b"!@#$%^&*()",
            b"the answer is 42",
            b"bachelor assurance project",
        ];
        for i in 0..10 {
            let (key, pk) = faest_key_gen();

            let msg: &[u8] = messages[i];
            let sig = faest_sign(msg, key, pk.clone());

            let test_work = faest_verify(msg, pk, sig);
            assert!(test_work);
        }
    }

    use super::*;
    use Bachelor_Assurance::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
    use Bachelor_Assurance::protocols::faest_key_enc_cstrnts::{
        faest_aes_enc_bkwd, faest_aes_enc_fwd,
    };
    use Bachelor_Assurance::protocols::faest_prove_and_verify::{
        faest_aes_prove, faest_aes_verify,
    };
    use Bachelor_Assurance::protocols::fs_vole::FAEST_VOLE_reconstruct;
    use Bachelor_Assurance::utils::constants::{ell_bit_size, k_0, k_1, lambda, tau_0};
    use Bachelor_Assurance::utils::galois_field::gf128_mul;
    use Bachelor_Assurance::utils::hash_functions::{h_1_for_non_specific_size, h_2_1, h_2_2};
    use Bachelor_Assurance::utils::helper_methods_for_sign::{
        bits_to_state, expand_bits_56, u_to_bits, vole_hash, vole_to_row_major,
    };
    use Bachelor_Assurance::utils::math::xor_arrays;

}
