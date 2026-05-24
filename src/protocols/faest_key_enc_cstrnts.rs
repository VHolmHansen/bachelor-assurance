#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::constants::{key_schedule_bits, lambda_bytes};
use crate::utils::galois_field::gf_lambda_mul;
use crate::utils::helper_methods_cstrnts::byte_combine;
use crate::utils::math::xor_arrays;
use crate::utils::types::{ret_value, XorHelper};
use crate::utils::constants::{l_enc, LAMBDA, s_enc, R};

// this function runs for w, v and q
// it computes the F_{2^8} inputs to the S-boxes for each round of the AES encryption routine
// it needs to do this for all those values since q = w * Delta + v
// the mtag and mkey values, are to specify which iteration is being run
pub fn faest_aes_enc_fwd<T : ret_value, TK : ret_value<Elem = T::Elem>>(
    _m : usize,
    x: &T,
    x_k : &TK,
    in_out : &[u8; 128],
    mtag : bool,
    mkey : bool,
    Delta : <T as ret_value>::Elem
) -> [[u8;lambda_bytes]; s_enc] where
    [T::Elem; 8]: ret_value<Elem = T::Elem>,
    T::Elem: XorHelper
{
    if mtag && mkey {
        panic!("called with wrong values")
    }
    // the y structure that will contain the inputs
    let mut y : [<[[u8;lambda_bytes];4] as ret_value>::Elem;s_enc] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;s_enc]; // 4 is dummy
    // The first 16 S-box inputs are obtained by XORing the plaintext with the first round key.
    // For each of the 16 bytes of the state, we combine 8 bits into a single F_{2^8} element
    for i in 0..16 { // first add round key storage
        let mut x_in : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
        for j in 0..8 {
            // lift each plaintext bit into the appropriate field element type:
            // for wire values: 1 -> field one, 0 -> field zero
            // for VOLE tags:   always field zero (tags of public constants are 0)
            // for VOLE keys:   1 -> Delta, 0 -> field zero (key of constant c is c*Delta)
            // this comes from the q = w * Delta + v
            if mtag {
            } else if mkey {
                x_in[j] = if in_out[(i << 3) + j] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
            } else {
                x_in[j] = if in_out[(i << 3) + j] == 1 {<T as ret_value>::value_of_one()} else {<T as ret_value>::dummy_value};
            }
        }
        let x_k_slice_as_T: [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(x_k.get_slice(i << 3, (i << 3)+8));
        // let x_in_as_T = <T as ret_value>::turn_array_to_T(&x_in);
        let x_in_as_T: [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(&x_in);

        // using bytecombine we combine 8 bits into a single element in F_{2^{lambda}}
        // we move the two values into the same field
        let parameter_1 : [u8;lambda_bytes] = byte_combine::<T::Elem>(x_in_as_T);
        let parameter_2 : [u8;lambda_bytes] = byte_combine::<T::Elem>(x_k_slice_as_T);

        // XOR the plaintext element with the round key element to get the S-box input
        y[i] = <[u8;lambda_bytes]>::xor_array(&parameter_1, &parameter_2);
    }
    // in the witness (x), we have stored the rounds shiftrows output
    // by applying mixcolumns, and adding the round key, we get the next input to subbytes
    for j in 1..R{ // rest of the subbytes storage
        for c in 0..4{
            // i_x: index into x (witness/tag/key) for the ShiftRows output of round j-1
            // i_k: index into x_k for the round key of round j
            // i_y: index into y for the S-box inputs of round j, column c
            let i_x = ((j-1) << 7) + (c << 5);
            let i_k = (j << 7) + (c << 5);
            let i_y = (j << 4) + (c << 2);
            // combine the 4 rows of this column into F_{2^8} elements for both
            // the witness/tag/key values (x_hat) and the round key values (x_hat_k)
            let mut x_hat : [<[[u8;lambda_bytes];4] as ret_value>::Elem;4] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;4];
            let mut x_hat_k : [<[[u8;lambda_bytes];4] as ret_value>::Elem;4] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;4];
            for r in 0..4 {
                let get_slice_of_x: [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(x.get_slice(i_x+(r << 3),i_x+(r << 3)+8));
                // combine 8 bits into one F_{2^lambda} element per row
                x_hat[r] = byte_combine::<T::Elem>(get_slice_of_x);
                let get_slice_of_x_k : [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(x_k.get_slice(i_k+(r << 3), i_k+(r << 3)+8));

                x_hat_k[r] = byte_combine::<T::Elem>(get_slice_of_x_k);
            }
            // mix columns constants
            let mut one = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;8];
            let mut two = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;8];
            let mut three = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;8];

            one[0] = <[[u8;lambda_bytes];4] as ret_value>::value_of_one();
            two[1] = <[[u8;lambda_bytes];4] as ret_value>::value_of_one();
            three[0] = <[[u8;lambda_bytes];4] as ret_value>::value_of_one();
            three[1] = <[[u8;lambda_bytes];4] as ret_value>::value_of_one();

            let value_of_one = byte_combine::<[u8;lambda_bytes]>(one);
            let value_of_two = byte_combine::<[u8;lambda_bytes]>(two);
            let value_of_three = byte_combine::<[u8;lambda_bytes]>(three);
            // mix columns application
            // we also xor with round key, i.e. add it
            // after each application ,the values are stored in y
            let x_hat_0_2 = gf_lambda_mul(&x_hat[0],&value_of_two);
            let x_hat_1_3 = gf_lambda_mul(&x_hat[1],&value_of_three);
            let x_hat_2_1 = gf_lambda_mul(&x_hat[2],&value_of_one);
            let x_hat_3_1 = gf_lambda_mul(&x_hat[3],&value_of_one);
            let x_hat_k_0 = x_hat_k[0];

            y[i_y+0] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_2, &x_hat_1_3), &x_hat_2_1), &x_hat_3_1),&x_hat_k_0);

            let x_hat_0_1 = gf_lambda_mul(&x_hat[0],&value_of_one);
            let x_hat_1_2 = gf_lambda_mul(&x_hat[1],&value_of_two);
            let x_hat_2_3 = gf_lambda_mul(&x_hat[2],&value_of_three);
            let x_hat_k_1 = x_hat_k[1];

            y[i_y+1] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_1, &x_hat_1_2), &x_hat_2_3), &x_hat_3_1),&x_hat_k_1);

            let x_hat_1_1 = gf_lambda_mul(&x_hat[1],&value_of_one);
            let x_hat_2_2 = gf_lambda_mul(&x_hat[2],&value_of_two);
            let x_hat_3_3 = gf_lambda_mul(&x_hat[3],&value_of_three);
            let x_hat_k_2 = x_hat_k[2];

            y[i_y+2] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_1, &x_hat_1_1), &x_hat_2_2), &x_hat_3_3),&x_hat_k_2);

            let x_hat_0_3 = gf_lambda_mul(&x_hat[0],&value_of_three);
            let x_hat_3_2 = gf_lambda_mul(&x_hat[3],&value_of_two);
            let x_hat_k_3 = x_hat_k[3];

            y[i_y+3] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_3, &x_hat_1_1), &x_hat_2_1), &x_hat_3_2),&x_hat_k_3);
        }
    }
    y
}

// Computes the F_{2^8} outputs of the S-box inversions for each round of AES,
// working backwards through the cipher from the ciphertext towards each SubBytes layer
// this function also is called to q, w and v, for the same reason as fwd
pub fn faest_aes_enc_bkwd<T : ret_value, TK : ret_value<Elem = T::Elem>>(
    _m : usize, x : &T,
    x_k : &TK,
    in_out : &[u8; 128],
    mtag : bool,
    mkey : bool,
    Delta : <T as ret_value>::Elem
) -> [[u8;lambda_bytes];s_enc] where
    [T::Elem; 8]: ret_value<Elem = T::Elem>,
    T::Elem: XorHelper
{
    // list to contain the outputs
    let mut y : [<[[u8;lambda_bytes];4] as ret_value>::Elem;s_enc] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;s_enc]; // 4 is a dummy value
    // for rounds up til R-2, shiftrows ouput are read from the extended witness,
    // while for the last round the sbox will be derived from the ciphertext, i.e. the in_out
    for j in 0..R{
        for c in 0..4{
            for r in 0..4{
                // ird computes the index into x that undoes ShiftRows.
                // ShiftRows shifts row r left by r positions, so to undo it we
                // shift right by r, which means reading from column (c - r) mod 4.
                let ird = (j << 7) + ((c as isize - (r as isize)).rem_euclid(4) << 5) as usize + (r << 3);
                let mut x_tilde : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value; 8];
                if j < R-1{
                    // for all but the last round, read the S-box output directly
                    // from x (the ShiftRows output stored in the witness/tag/key)
                    for idx in 0..8{
                        x_tilde[idx] = x.get_element(ird+idx);
                    }
                } else {
                    // for the last round, the ShiftRows output is not stored in the witness.
                    // instead, derive it from the ciphertext by inverting the final AddRoundKey:
                    // x_tilde = ciphertext_bits XOR last_round_key_bits
                    let mut x_out : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
                    for i in 0..8{
                        // lift each ciphertext bit into the appropriate field element type,
                        // same logic as EncFwd for handling wire values, tags and keys
                        if mtag { // do nothing
                        } else if mkey {
                            x_out[i] = if in_out[ird - (j << 7) + i] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
                        } else {
                            x_out[i] = if in_out[ird - (j << 7) + i] == 1 {<T as ret_value>::value_of_one()} else {<T as ret_value>::dummy_value};
                        }
                    }
                    // invert AddRoundKey: XOR each ciphertext bit with the last round key bit
                    for idx in 0..8{
                        x_tilde[idx] = <T::Elem>::xor_array(&x_out[idx], &x_k.get_element(128+ird+idx));
                    }
                }
                let mut y_tilde : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value; 8];
                // invert the F_2-affine layer of the AES S-box.
                // the affine layer computes y_tilde[i] = x[i-1] XOR x[i-3] XOR x[i-6] (mod 8),
                // which is its own inverse over F_2 (it is an involution).
                for i in 0..8{
                    let parameter_a = &x_tilde[((i+7) as i32).rem_euclid(8) as usize]; // should be same for usize as -1
                    let parameter_b = &x_tilde[((i+5) as i32).rem_euclid(8) as usize]; // should be same for usize as -3
                    let parameter_c = &x_tilde[((i+2) as i32).rem_euclid(8) as usize]; // should be same for usize as -6

                    let middle_result = <T::Elem>::xor_array(parameter_a, parameter_b);
                    let final_result = <T::Elem>::xor_array(&middle_result, parameter_c);

                    y_tilde[i] = final_result;
                }
                // add the affine constant of the S-box to bits 0 and 2.
                // the AES S-box affine layer adds the constant 0x63 = 0110 0011,
                let value_might_be_delta = if mtag {<T as ret_value>::dummy_value} else {
                    if mkey {Delta.clone()} else {<T as ret_value>::value_of_one()}
                };
                y_tilde[0] = <T::Elem>::xor_array(&y_tilde[0],&value_might_be_delta);
                y_tilde[2] = <T::Elem>::xor_array(&y_tilde[2],&value_might_be_delta);
                // combine the 8 bits of the inverted S-box output into a single F_{2^lambda} element
                y[(j << 4) + (c << 2) + r] = byte_combine::<T::Elem>(<[T::Elem; 8] as ret_value>::turn_array_to_T(&y_tilde));
            }
        }
    }
    y
}
// the prover side of the encryption constraints
// wants to compute A_1 and A_0, for the sbox constraints of the encryption routine
// it is based on the constraints that sboxinput * sboxoutput = 1
pub fn faest_aes_enc_cstrnts_prover(
    _m : usize,
    in_of_in_and_out : [u8; 128],
    out_of_in_and_out : [u8; 128],
    w : [u8; l_enc], // l_enc stor
    v : [[u8;lambda_bytes]; l_enc],
    k : [u8;key_schedule_bits], // 1408 stor
    v_k : [[u8;lambda_bytes];key_schedule_bits],
    mkey : bool,
) -> ([[u8;lambda_bytes];s_enc],[[u8;lambda_bytes];s_enc])
{
    if mkey {
        panic!("mkey should be false");
    }
    // compute sbox inputs for witness and vole value v
    let s : [[u8;lambda_bytes];s_enc] = faest_aes_enc_fwd::<[u8;l_enc],[u8;key_schedule_bits]>(1, &w, &k, &in_of_in_and_out, false, false, 0); // w is 1152, k is 1408
    let v_s : [[u8;lambda_bytes];s_enc] = faest_aes_enc_fwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, &v, &v_k, &in_of_in_and_out, true, false, [0;lambda_bytes]); // v is 1152, v_k is 1408
    // computes outputs for witness and vole value v
    let s_overline: [[u8;lambda_bytes];s_enc] = faest_aes_enc_bkwd::<[u8;l_enc],[u8;key_schedule_bits]>(1, &w, &k, &out_of_in_and_out, false, false, 0); // w is 1152, k is 1408
    let v_s_overline : [[u8;lambda_bytes];s_enc] = faest_aes_enc_bkwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, &v, &v_k, &out_of_in_and_out, true, false, [0;lambda_bytes]); // v is 1152, v_k is 1408
    // lists for the A values
    let mut A_0 : [[u8;lambda_bytes];s_enc] = [[0;lambda_bytes];s_enc];
    let mut A_1 : [[u8;lambda_bytes];s_enc] = [[0;lambda_bytes];s_enc];
    for j in 0..s_enc {
        // for each Sbox
        // first it finds A0, which is the product of the v_sboxinput and v_sboxoutput
        A_0[j] = gf_lambda_mul(&v_s[j], &v_s_overline[j]);
        // then it wants to compute A1, where this is (w_sboxinput + v_sboxinput) * (w_sboxoutput + v_sboxoutput) - 1
        // an important thing to mention is that w_sboxinput * w_sboxoutput - 1 = 0, for valid witness
        let s_v_s_add = xor_arrays(&s[j], &v_s[j]);
        let s_overline_v_s_overline_add = xor_arrays(&s_overline[j], &v_s_overline[j]);
        let prod = gf_lambda_mul(&s_v_s_add, &s_overline_v_s_overline_add);
        // subtract 1_{F_{2^8}} and A0,j — in GF(2^128), subtraction is XOR
        let one_f28: [u8; lambda_bytes] = {
            let mut arr = [0u8; lambda_bytes];
            arr[0] = 0x01;
            arr
        };
        A_1[j] = xor_arrays(&xor_arrays(&prod, &one_f28), &A_0[j]);
    }
    // lastly return these two values
    (A_0, A_1)
}
// finding the encryption constraints for the verifier, and specific to the value q
pub fn faest_aes_enc_cstrnts_verifier(
    _m : usize,
    in_of_in_and_out : &[u8; 128],
    out_of_in_and_out : &[u8; 128],
    q : &[[u8;lambda_bytes];l_enc],
    q_k : &[[u8;lambda_bytes];key_schedule_bits],     //(R+1)*128=(R+1) << 7
    delta : [u8;lambda_bytes],
    mkey : bool
) -> [[u8;lambda_bytes];s_enc]
{
    if !mkey {
        panic!("mkey should not be false");
    }
    // calculates sbox input and output for q
    let q_s : [[u8;lambda_bytes];s_enc] = faest_aes_enc_fwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, q, q_k, in_of_in_and_out, false, true, delta); // q is 1152, q_k is 1408
    let q_s_overline: [[u8;lambda_bytes];s_enc] = faest_aes_enc_bkwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, &q, &q_k, out_of_in_and_out, false, true, delta); // q is 1152, q_k is 1408
    let mut B : [[u8;lambda_bytes]; s_enc] = [[0;lambda_bytes];s_enc];
    for j in 0..s_enc {
        // the B here is (q_in * q_out) - Delta^2
        let q_product : [u8;lambda_bytes] = gf_lambda_mul(&q_s[j], &q_s_overline[j]);
        let delta_product : [u8;lambda_bytes] = gf_lambda_mul(&delta, &delta);
        B[j] = xor_arrays(&q_product, &delta_product);
    }
    B
}
