use crate::protocols::aes::R;
use crate::utils::galois_field::gf128_mul;
use crate::utils::helper_methods_cstrnts::byte_combine;
use crate::utils::math::xor_arrays;
use crate::utils::types::{ret_value, s_enc};

// m is size of elements
// x is the extended witness, vole tags or vole keys
// x_k expanded key values, vle tags or vole keys
// in_out is in or out, depending on who calls, where it AES plaintext or ciphertext block
// mtag same as for key_exp
// mkey same as for key_exp
// Delta, global vole key if mkey = 1 else none
// in_out should be size 128, where each u8 in it corresponds to one bit
// should never be called with mtag=1 and mkey= 1
pub fn faest_aes_enc_fwd<T : ret_value>(m : usize, x: T, x_k : T, in_out : Vec<u8>, mtag : bool, mkey : bool, Delta : <T as ret_value>::Elem) -> [[u8;16]; s_enc]{
    if mtag && mkey {
        panic!("called with wrong values")
    }
    let mut y : [<Vec<[u8;16]> as ret_value>::Elem;s_enc] = [<Vec<[u8;16]> as ret_value>::dummy_value;s_enc];
    for i in 0..16 {
        let mut x_in : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
        for j in 0..8 {
            if mtag { // do nothing
            } else if mkey {
                x_in[j] = if in_out[8*i+j] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
            } else {
                x_in[j] = if in_out[8*i+j] == 1 {<T as ret_value>::value_of_one} else {<T as ret_value>::dummy_value};
            }
        }
        let x_k_slice_as_T = <T as ret_value>::turn_array_to_T(&x_k.get_slice(8*i,8*i+8));
        let x_in_as_T = <T as ret_value>::turn_array_to_T(&x_in);

        let parameter_1 : [u8;16] = byte_combine(x_in_as_T);
        let parameter_2 : [u8;16] = byte_combine(x_k_slice_as_T);

        y[i] = <Vec<[u8;16]> as ret_value>::xor_array(&parameter_1, &parameter_2);
    }
    for j in 1..R{
        for c in 0..4{
            let i_x = 128 * (j-1) + 32 * c;
            let i_k = 128*j+32*c;
            let i_y = 16*j+4*c;
            let mut x_hat : [<Vec<[u8;16]> as ret_value>::Elem;4] = [<Vec<[u8;16]> as ret_value>::dummy_value;4];
            let mut x_hat_k : [<Vec<[u8;16]> as ret_value>::Elem;4] = [<Vec<[u8;16]> as ret_value>::dummy_value;4];
            for r in 0..4 {
                let get_slice_of_x = <T as ret_value>::turn_array_to_T(x.get_slice(i_x+8*r, i_x+8*r+8));
                x_hat[r] = byte_combine(get_slice_of_x);
                let get_slice_of_x_k = <T as ret_value>::turn_array_to_T(x_k.get_slice(i_x+8*r, i_x+8*r+8));
                x_hat_k[r] = byte_combine(get_slice_of_x_k);
            }
            let mut one = vec![<Vec<[u8;16]> as ret_value>::dummy_value;8];
            let mut two = vec![<Vec<[u8;16]> as ret_value>::dummy_value;8];
            let mut three = vec![<Vec<[u8;16]> as ret_value>::dummy_value;8];

            one[0] = <Vec<[u8;16]> as ret_value>::value_of_one;
            two[1] = <Vec<[u8;16]> as ret_value>::value_of_one;
            three[0] = <Vec<[u8;16]> as ret_value>::value_of_one;
            three[1] = <Vec<[u8;16]> as ret_value>::value_of_one;

            let value_of_one = byte_combine(one);
            let value_of_two = byte_combine(two);
            let value_of_three = byte_combine(three);

            let x_hat_0_2 = gf128_mul(&x_hat[0],&value_of_two);
            let x_hat_1_3 = gf128_mul(&x_hat[1],&value_of_three);
            let x_hat_2_1 = gf128_mul(&x_hat[2],&value_of_one);
            let x_hat_3_1 = gf128_mul(&x_hat[3],&value_of_one);
            let x_hat_k_0 = x_hat_k[0];

            y[i_y+0] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_2, &x_hat_1_3), &x_hat_2_1), &x_hat_3_1),&x_hat_k_0);

            let x_hat_0_1 = gf128_mul(&x_hat[0],&value_of_one);
            let x_hat_1_2 = gf128_mul(&x_hat[1],&value_of_two);
            let x_hat_2_3 = gf128_mul(&x_hat[2],&value_of_three);
            let x_hat_k_1 = x_hat_k[1];

            y[i_y+1] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_1, &x_hat_1_2), &x_hat_2_3), &x_hat_3_1),&x_hat_k_1);

            let x_hat_1_1 = gf128_mul(&x_hat[1],&value_of_one);
            let x_hat_2_2 = gf128_mul(&x_hat[2],&value_of_two);
            let x_hat_3_3 = gf128_mul(&x_hat[3],&value_of_three);
            let x_hat_k_2 = x_hat_k[2];

            y[i_y+2] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_1, &x_hat_1_1), &x_hat_2_2), &x_hat_3_3),&x_hat_k_2);

            let x_hat_0_3 = gf128_mul(&x_hat[0],&value_of_three);
            let x_hat_3_2 = gf128_mul(&x_hat[3],&value_of_two);
            let x_hat_k_3 = x_hat_k[3];

            y[i_y+3] = xor_arrays(&xor_arrays(&xor_arrays(&xor_arrays(&x_hat_0_3, &x_hat_1_1), &x_hat_2_1), &x_hat_3_2),&x_hat_k_3);
        }
    }
    y
}
// delta is here a T value, that is only for simplifiuying implementation, delta should always be a [u8;16], and when this function is called with T = u8
// then, it should also have mkey == 0, and therefore will never be set equal to delta
pub fn faest_aes_enc_bkwd<T : ret_value>(m : usize, x : T, x_k : T, in_out : Vec<u8>, mtag : bool, mkey : bool, Delta : <T as ret_value>::Elem) -> [[u8;16];160]{
    let mut y : [<Vec<[u8;16]> as ret_value>::Elem;s_enc] = [<Vec<[u8;16]> as ret_value>::dummy_value;s_enc];
    for j in 0..R{
        for c in 0..4{
            for r in 0..4{
                let ird = 128*j+ 32 * (c-r % 4) + 8*r;
                let mut x_tilde : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value; 8];
                if j < R-1{
                    for idx in 0..8{
                        x_tilde[idx] = x.get_element(ird+idx);
                    }
                } else {
                    let mut x_out : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
                    for i in 1..8{
                        if mtag { // do nothing
                        } else if mkey {
                            x_out[j] = if in_out[8*i+j] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
                        } else {
                            x_out[j] = if in_out[8*i+j] == 1 {<T as ret_value>::value_of_one} else {<T as ret_value>::dummy_value};
                        }
                    }
                    for idx in 0..8{
                        x_tilde[idx] = <T as ret_value>::xor_array(&x_out[idx], &x_k.get_element(128+ird+idx));
                    }
                }
                let mut y_tilde : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value; 8];
                for i in 0..8{
                    let parameter_a = &x_tilde[((i+7) as i32).rem_euclid(8) as usize]; // should be same for usize as -1
                    let parameter_b = &x_tilde[((i+5) as i32).rem_euclid(8) as usize]; // should be same for usize as -3
                    let parameter_c = &x_tilde[((i+2) as i32).rem_euclid(8) as usize]; // should be same for usize as -6

                    let middle_result = <T as ret_value>::xor_array(parameter_a, parameter_b);
                    let final_result = <T as ret_value>::xor_array(&middle_result, parameter_c);

                    y_tilde[i] = final_result;
                }
                let value_might_be_delta = if mtag {<T as ret_value>::dummy_value} else {
                    if mkey {Delta.clone()} else {<T as ret_value>::value_of_one}
                };
                y_tilde[0] = <T as ret_value>::xor_array(&y_tilde[0],&value_might_be_delta);
                y_tilde[2] = <T as ret_value>::xor_array(&y_tilde[2],&value_might_be_delta);

                y[16*j+4*c+r] = byte_combine(<T as ret_value>::turn_array_to_T(&y_tilde));
            }
        }
    }
    y

}