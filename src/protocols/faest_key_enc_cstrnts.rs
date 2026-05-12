#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::constants::{key_schedule_bits, lambda_bytes};
use crate::utils::galois_field::gf_lambda_mul;
use crate::utils::helper_methods_cstrnts::byte_combine;
use crate::utils::math::xor_arrays;
use crate::utils::types::{ret_value, XorHelper};
use crate::utils::constants::{l_enc, LAMBDA, s_enc, R};

// m is size of elements
// x is the extended witness, vole tags or vole keys
// x_k expanded key values, vle tags or vole keys
// in_out is in or out, depending on who calls, where it AES plaintext or ciphertext block
// mtag same as for key_exp
// mkey same as for key_exp
// Delta, global vole key if mkey = 1 else none
// in_out should be size 128, where each u8 in it corresponds to one bit
// should never be called with mtag=1 and mkey= 1
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
    let mut y : [<[[u8;lambda_bytes];4] as ret_value>::Elem;s_enc] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;s_enc]; // 4 is dummy
    for i in 0..16 {
        let mut x_in : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
        for j in 0..8 {
            if mtag { // do nothing
            } else if mkey {
                x_in[j] = if in_out[(i << 3) + j] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
            } else {
                x_in[j] = if in_out[(i << 3) + j] == 1 {<T as ret_value>::value_of_one()} else {<T as ret_value>::dummy_value};
            }
        }
        let x_k_slice_as_T: [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(x_k.get_slice(i << 3, (i << 3)+8));
        // let x_in_as_T = <T as ret_value>::turn_array_to_T(&x_in);
        let x_in_as_T: [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(&x_in);

        let parameter_1 : [u8;lambda_bytes] = byte_combine::<T::Elem>(x_in_as_T);
        let parameter_2 : [u8;lambda_bytes] = byte_combine::<T::Elem>(x_k_slice_as_T);

        y[i] = <[u8;lambda_bytes]>::xor_array(&parameter_1, &parameter_2);
    }
    for j in 1..R{
        for c in 0..4{
            let i_x = ((j-1) << 7) + (c << 5);
            let i_k = (j << 7) + (c << 5);
            let i_y = (j << 4) + (c << 2);
            let mut x_hat : [<[[u8;lambda_bytes];4] as ret_value>::Elem;4] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;4];
            let mut x_hat_k : [<[[u8;lambda_bytes];4] as ret_value>::Elem;4] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;4];
            for r in 0..4 {
                // let get_slice_of_x = <T as ret_value>::turn_array_to_T(x.get_slice(i_x+8*r, i_x+8*r+8));
                let get_slice_of_x: [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(x.get_slice(i_x+(r << 3),i_x+(r << 3)+8));
                x_hat[r] = byte_combine::<T::Elem>(get_slice_of_x);
                // let get_slice_of_x_k = <T as ret_value>::turn_array_to_T(x_k.get_slice(i_k+8*r, i_k+8*r+8));
                let get_slice_of_x_k : [T::Elem; 8] = <[T::Elem; 8] as ret_value>::turn_array_to_T(x_k.get_slice(i_k+(r << 3), i_k+(r << 3)+8));

                x_hat_k[r] = byte_combine::<T::Elem>(get_slice_of_x_k);
            }
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
// delta is here a T value, that is only for simplifiuying implementation, delta should always be a [u8;lambda_bytes], and when this function is called with T = u8
// then, it should also have mkey == 0, and therefore will never be set equal to delta
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
    let mut y : [<[[u8;lambda_bytes];4] as ret_value>::Elem;s_enc] = [<[[u8;lambda_bytes];4] as ret_value>::dummy_value;s_enc]; // 4 is a dummy value
    for j in 0..R{
        for c in 0..4{
            for r in 0..4{
                let ird = (j << 7) + ((c as isize - (r as isize)).rem_euclid(4) << 5) as usize + (r << 3);
                let mut x_tilde : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value; 8];
                if j < R-1{
                    for idx in 0..8{
                        x_tilde[idx] = x.get_element(ird+idx);
                    }
                } else {
                    let mut x_out : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
                    for i in 0..8{
                        if mtag { // do nothing
                        } else if mkey {
                            x_out[i] = if in_out[ird - (j << 7) + i] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
                        } else {
                            x_out[i] = if in_out[ird - (j << 7) + i] == 1 {<T as ret_value>::value_of_one()} else {<T as ret_value>::dummy_value};
                        }
                    }
                    for idx in 0..8{
                        x_tilde[idx] = <T::Elem>::xor_array(&x_out[idx], &x_k.get_element(128+ird+idx));
                    }
                }
                let mut y_tilde : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value; 8];
                for i in 0..8{
                    let parameter_a = &x_tilde[((i+7) as i32).rem_euclid(8) as usize]; // should be same for usize as -1
                    let parameter_b = &x_tilde[((i+5) as i32).rem_euclid(8) as usize]; // should be same for usize as -3
                    let parameter_c = &x_tilde[((i+2) as i32).rem_euclid(8) as usize]; // should be same for usize as -6

                    let middle_result = <T::Elem>::xor_array(parameter_a, parameter_b);
                    let final_result = <T::Elem>::xor_array(&middle_result, parameter_c);

                    y_tilde[i] = final_result;
                }
                let value_might_be_delta = if mtag {<T as ret_value>::dummy_value} else {
                    if mkey {Delta.clone()} else {<T as ret_value>::value_of_one()}
                };
                y_tilde[0] = <T::Elem>::xor_array(&y_tilde[0],&value_might_be_delta);
                y_tilde[2] = <T::Elem>::xor_array(&y_tilde[2],&value_might_be_delta);

                y[(j << 4) + (c << 2) + r] = byte_combine::<T::Elem>(<[T::Elem; 8] as ret_value>::turn_array_to_T(&y_tilde));
            }
        }
    }
    y
}

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
    let s : [[u8;lambda_bytes];s_enc] = faest_aes_enc_fwd::<[u8;l_enc],[u8;key_schedule_bits]>(1, &w, &k, &in_of_in_and_out, false, false, 0); // w is 1152, k is 1408
    let v_s : [[u8;lambda_bytes];s_enc] = faest_aes_enc_fwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, &v, &v_k, &in_of_in_and_out, true, false, [0;lambda_bytes]); // v is 1152, v_k is 1408
    let s_overline: [[u8;lambda_bytes];s_enc] = faest_aes_enc_bkwd::<[u8;l_enc],[u8;key_schedule_bits]>(1, &w, &k, &out_of_in_and_out, false, false, 0); // w is 1152, k is 1408
    let v_s_overline : [[u8;lambda_bytes];s_enc] = faest_aes_enc_bkwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, &v, &v_k, &out_of_in_and_out, true, false, [0;lambda_bytes]); // v is 1152, v_k is 1408
    let mut A_0 : [[u8;lambda_bytes];s_enc] = [[0;lambda_bytes];s_enc];
    let mut A_1 : [[u8;lambda_bytes];s_enc] = [[0;lambda_bytes];s_enc];
    for j in 0..s_enc {
        A_0[j] = gf_lambda_mul(&v_s[j], &v_s_overline[j]);
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
    (A_0, A_1)
}
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
    let q_s : [[u8;lambda_bytes];s_enc] = faest_aes_enc_fwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, q, q_k, in_of_in_and_out, false, true, delta); // q is 1152, q_k is 1408
    let q_s_overline: [[u8;lambda_bytes];s_enc] = faest_aes_enc_bkwd::<[[u8;lambda_bytes];l_enc],[[u8;lambda_bytes];key_schedule_bits]>(LAMBDA, &q, &q_k, out_of_in_and_out, false, true, delta); // q is 1152, q_k is 1408
    let mut B : [[u8;lambda_bytes]; s_enc] = [[0;lambda_bytes];s_enc];
    for j in 0..s_enc {
        let q_product : [u8;lambda_bytes] = gf_lambda_mul(&q_s[j], &q_s_overline[j]);
        let delta_product : [u8;lambda_bytes] = gf_lambda_mul(&delta, &delta);
        B[j] = xor_arrays(&q_product, &delta_product);
    }
    B
}
