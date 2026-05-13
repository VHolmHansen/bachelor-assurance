#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use std::array;
use crate::utils::galois_field::gf128_mul;
use crate::utils::helper_methods_cstrnts::byte_combine;
use crate::utils::math::xor_arrays;
use crate::utils::types::{ret_value, value_of_one_in_bytes, ByteElem, ByteOrBytesElem, BytesElem, XorHelper};
use crate::utils::constants::{l_enc, lambda, s_enc, R};

// m is size of elements
// x is the extended witness, vole tags or vole keys
// x_k expanded key values, vle tags or vole keys
// in_out is in or out, depending on who calls, where it AES plaintext or ciphertext block
// mtag same as for key_exp
// mkey same as for key_exp
// Delta, global vole key if mkey = 1 else none
// in_out should be size 128, where each u8 in it corresponds to one bit
// should never be called with mtag=1 and mkey= 1
#[hax_lib::requires(!(mtag && mkey) && x.len() > 0 && x_k.len() > 0)] // need req for all types in x and x_k and delta to be the same
pub fn faest_aes_enc_fwd(
    _m : usize,
    x: &[ByteOrBytesElem; 1152],
    x_k : &[ByteOrBytesElem; 1408], //TODO: verify length, this is minimum
    in_out : &[u8; 128],
    mtag : bool,
    mkey : bool,
    Delta : ByteOrBytesElem,
) -> [[u8;16]; s_enc]
{
    /*
    if mtag && mkey {
        panic!("called with wrong values")
    }
    */
    let mut y : [[u8; 16]; s_enc] = [[0u8; 16];s_enc]; // 4 is dummy
    for i in 0..16 {
        hax_lib::loop_invariant!(|i: usize| {
            i <= 16 &&
            i <= usize::MAX / 8
        });
        let zeroes = ByteOrBytesElem::dummy(&x[0]);
        let ones = ByteOrBytesElem::ones(&x[0]);
        let mut x_in : [ByteOrBytesElem;8] = [zeroes; 8];
        for j in 0..8 {
            hax_lib::loop_invariant!(|j: usize| {
                j <= 8 &&
                i <= usize::MAX - j &&
                (i << 3) + j <= 128
            });
            let elem = in_out[(i << 3) + j];
            if mtag { // do nothing
            } else if mkey {
                x_in[j] = if elem == 1 {Delta.clone()} else {zeroes};
            } else {
                x_in[j] = if elem == 1 {ones} else {zeroes};
            }
        }
        let x_k_slice_as_T: [ByteOrBytesElem; 8] = x_k[i << 3..(i << 3)+8].try_into().unwrap();
        // let x_in_as_T = <T as ret_value>::turn_array_to_T(&x_in);
        //let x_in_as_T: [ByteOrBytesElem; 8] = <[ByteOrBytesElem; 8] as ret_value>::turn_array_to_T(&x_in);

        let parameter_1 : [u8;16] = byte_combine(x_in);
            //byte_combine::<T::Elem>(x_in_as_T);
        let parameter_2 : [u8;16] = byte_combine(x_k_slice_as_T);
        hax_lib::assert!(i < y.len());
        y[i] = <[u8;16]>::xor_array(&parameter_1, &parameter_2);
    }
    for j in 1..R{
        hax_lib::loop_invariant!(|j: usize| {
            j <= R &&
            j >= 1
        });
        for c in 0..4{
            hax_lib::loop_invariant!(|c: usize| {
                c <= 4 &&
                ((j-1) << 7) + (c << 5) + 32 <= x.len() + (c << 5) &&
                (j << 7) + (c << 5) + 32 <= x_k.len() + (c << 5) &&
                (j << 4) + (c << 2) + 3 <= y.len() + (c << 2)
            });
            //TODO: use above invariant as general understanding of invariants according to some offset
            //hax_lib::assert!(j <= usize::MAX / 128);
            //hax_lib::assert!(c <= usize::MAX / 32);
            //hax_lib::assert!(j << 7 <= usize::MAX - (c << 5));
            let i_x = ((j-1) << 7) + (c << 5);
            let i_k = (j << 7) + (c << 5);
            let i_y = (j << 4) + (c << 2);
            hax_lib::assert!(i_y + 3 < y.len());
            let mut x_hat : [[u8; 16];4] = [[0u8; 16];4];
            let mut x_hat_k : [[u8; 16];4] = [[0u8; 16];4];
            for r in 0..4 {
                hax_lib::loop_invariant!(|r: usize| {
                    r <= 4
                });
                //hax_lib::assert!(r <= usize::MAX / 8);
                //hax_lib::assert!(i_x <= usize::MAX - ((r << 3) + 8));
                hax_lib::assert!(i_x + (r << 3) + 8 <= x.len());
                //hax_lib::assert!(i_k <= usize::MAX - ((r << 3) + 8));
                hax_lib::assert!(i_k + (r << 3) + 8 <= x_k.len());
                // let get_slice_of_x = <T as ret_value>::turn_array_to_T(x.get_slice(i_x+8*r, i_x+8*r+8));
                let get_slice_of_x: [ByteOrBytesElem; 8] = x[(i_x+(r << 3))..(i_x+(r << 3)+8)].try_into().unwrap();
                x_hat[r] = byte_combine(get_slice_of_x);
                // let get_slice_of_x_k = <T as ret_value>::turn_array_to_T(x_k.get_slice(i_k+8*r, i_k+8*r+8));
                let get_slice_of_x_k : [ByteOrBytesElem; 8] = x_k[i_k+(r << 3)..i_k+(r << 3)+8].try_into().unwrap();

                x_hat_k[r] = byte_combine(get_slice_of_x_k);
            }
            //hax_lib::assert!(i_y + 3 <= y.len());
            let mut one: [ByteOrBytesElem; 8] = [ByteOrBytesElem::zero_bytes();8];
            let mut two: [ByteOrBytesElem; 8] = [ByteOrBytesElem::zero_bytes();8];
            let mut three: [ByteOrBytesElem; 8] = [ByteOrBytesElem::zero_bytes();8];

            one[0] = ByteOrBytesElem::Bytes(BytesElem(value_of_one_in_bytes));
            two[1] = ByteOrBytesElem::Bytes(BytesElem(value_of_one_in_bytes));
            three[0] = ByteOrBytesElem::Bytes(BytesElem(value_of_one_in_bytes));
            three[1] = ByteOrBytesElem::Bytes(BytesElem(value_of_one_in_bytes));

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
pub fn faest_aes_enc_bkwd(
    _m : usize, x : &[ByteOrBytesElem; 1152],
    x_k : &[ByteOrBytesElem; 1408],
    in_out : &[u8; 128],
    mtag : bool,
    mkey : bool,
    Delta : &ByteOrBytesElem,
) -> [[u8;16];160]
{
    let mut y : [[u8;16];s_enc] = [[0u8; 16];s_enc]; // 4 is a dummy value
    for j in 0..R{
        for c in 0..4{
            for r in 0..4{
                let ird = (j << 7) + ((c as isize - (r as isize)).rem_euclid(4) << 5) as usize + (r << 3);
                let mut x_tilde : [ByteOrBytesElem;8] = [ByteOrBytesElem::dummy(&x[0]); 8];
                if j < R-1{
                    for idx in 0..8{
                        x_tilde[idx] = x[ird+idx];
                    }
                } else {
                    let mut x_out : [ByteOrBytesElem;8] = [ByteOrBytesElem::dummy(&x[0]);8];
                    for i in 0..8{
                        if mtag { // do nothing
                        } else if mkey {
                            x_out[i] = if in_out[ird - (j << 7) + i] == 1 {Delta.clone()} else {ByteOrBytesElem::dummy(&x[0])};
                        } else {
                            x_out[i] = if in_out[ird - (j << 7) + i] == 1 {ByteOrBytesElem::ones(&x[0])} else {ByteOrBytesElem::dummy(&x[0])};
                        }
                    }
                    for idx in 0..8{
                        hax_lib::assume!(ByteOrBytesElem::same_variant(&x_out[idx], &x_k[128+ird+idx]));       //TODO: replace with assertion if possible
                        x_tilde[idx] = ByteOrBytesElem::xor_array(&x_out[idx], &x_k[(128+ird+idx)]);
                    }
                }
                let mut y_tilde : [ByteOrBytesElem;8] = [ByteOrBytesElem::dummy(&x[0]); 8];
                for i in 0..8{
                    let parameter_a = &x_tilde[((i+7) as i32).rem_euclid(8) as usize]; // should be same for usize as -1
                    let parameter_b = &x_tilde[((i+5) as i32).rem_euclid(8) as usize]; // should be same for usize as -3
                    let parameter_c = &x_tilde[((i+2) as i32).rem_euclid(8) as usize]; // should be same for usize as -6

                    hax_lib::assume!(ByteOrBytesElem::same_variant(parameter_a,parameter_b));       //TODO: replace with assertion if possible
                    let middle_result = ByteOrBytesElem::xor_array(parameter_a, parameter_b);
                    hax_lib::assume!(ByteOrBytesElem::same_variant(&middle_result, parameter_c));       //TODO: replace with assertion if possible
                    let final_result = ByteOrBytesElem::xor_array(&middle_result, parameter_c);

                    y_tilde[i] = final_result;
                }
                let value_might_be_delta = if mtag {ByteOrBytesElem::dummy(&x[0])} else {
                    if mkey {Delta.clone()} else {ByteOrBytesElem::ones(&x[0])}
                };
                hax_lib::assume!(ByteOrBytesElem::same_variant(&y_tilde[0], &value_might_be_delta));    //TODO: replace with assert if possible
                y_tilde[0] = ByteOrBytesElem::xor_array(&y_tilde[0],&value_might_be_delta);
                hax_lib::assume!(ByteOrBytesElem::same_variant(&y_tilde[2], &value_might_be_delta));    //TODO: replace with assert if possible
                y_tilde[2] = ByteOrBytesElem::xor_array(&y_tilde[2],&value_might_be_delta);

                y[(j << 4) + (c << 2) + r] = byte_combine(y_tilde);
            }
        }
    }
    y
}

#[hax_lib::requires(mkey == false)]
pub fn faest_aes_enc_cstrnts_prover(
    _m : usize,
    in_of_in_and_out : [u8; 128],
    out_of_in_and_out : [u8; 128],
    w : [u8; l_enc], // l_enc stor
    v : [[u8;16]; l_enc],
    k : [u8;(R+1) << 7], // 1408 stor
    v_k : [[u8;16];(R+1) << 7],
    mkey : bool,
) -> ([[u8;16];s_enc],[[u8;16];s_enc])
{
    /*
    if mkey {
        panic!("mkey should be false");
    }
     */
    let bobe_w: [ByteOrBytesElem; l_enc] = ByteOrBytesElem::from_byte_array(&w);
    let bobe_k: [ByteOrBytesElem; (R+1) << 7] = ByteOrBytesElem::from_byte_array(&k);
    let bobe_v: [ByteOrBytesElem; l_enc] = ByteOrBytesElem::from_bytes_array(&v);
    let bobe_v_k: [ByteOrBytesElem; (R+1) << 7] = ByteOrBytesElem::from_bytes_array(&v_k);

    let s : [[u8;16];s_enc] = faest_aes_enc_fwd(1, &bobe_w, &bobe_k, &in_of_in_and_out, false, false, ByteOrBytesElem::Byte(ByteElem(0))); // w is 1152, k is 1408
    let v_s : [[u8;16];160] = faest_aes_enc_fwd(lambda, &bobe_v, &bobe_v_k, &in_of_in_and_out, true, false, ByteOrBytesElem::Bytes(BytesElem([0;16]))); // v is 1152, v_k is 1408
    let s_overline: [[u8;16];160] = faest_aes_enc_bkwd(1, &bobe_w, &bobe_k, &out_of_in_and_out, false, false, &ByteOrBytesElem::Byte(ByteElem(0))); // w is 1152, k is 1408
    let v_s_overline : [[u8;16];160] = faest_aes_enc_bkwd(lambda, &bobe_v, &bobe_v_k, &out_of_in_and_out, true, false, &ByteOrBytesElem::Bytes(BytesElem([0;16]))); // v is 1152, v_k is 1408
    let mut A_0 : [[u8;16];160] = [[0;16];160];
    let mut A_1 : [[u8;16];160] = [[0;16];160];

    let value_of_s_enc = s_enc; //TODO: somehow use consts in a hax-compatible way here, ideally

    for j in 0..160 {
        hax_lib::loop_invariant!(|j: usize| {
            j <= 160
        });
        if j < 160 {

            A_0[j] = gf128_mul(&v_s[j], &v_s_overline[j]);

            let s_v_s_add: [u8; 16] = xor_arrays(&s[j], &v_s[j]);

            let s_overline_v_s_overline_add: [u8; 16] = xor_arrays(&s_overline[j], &v_s_overline[j]);
            let prod: [u8; 16] = gf128_mul(&s_v_s_add, &s_overline_v_s_overline_add);
            // subtract 1_{F_{2^8}} and A0,j — in GF(2^128), subtraction is XOR
            let one_f28: [u8; 16] = {
                let mut arr: [u8; 16] = [0u8; 16];
                arr[0] = 0x01;
                arr
            };

            A_1[j] = xor_arrays(&xor_arrays(&prod, &one_f28), &A_0[j]);
            continue
        }

    }
    (A_0, A_1)
}

#[hax_lib::requires(mkey == true)]
pub fn faest_aes_enc_cstrnts_verifier(
    _m : usize,
    in_of_in_and_out : &[u8; 128],
    out_of_in_and_out : &[u8; 128],
    q : &[[u8;16];l_enc],
    q_k : &[[u8;16];(R+1) << 7],     //(R+1)*128=(R+1) << 7
    delta : [u8;16],
    mkey : bool
) -> [[u8;16];s_enc]
{
    if !mkey {
        panic!("mkey should not be false");
    }
    let bobe_q: [ByteOrBytesElem; l_enc] = ByteOrBytesElem::from_bytes_array(&q);
    let bobe_q_k: [ByteOrBytesElem; (R+1) << 7] = ByteOrBytesElem::from_bytes_array(&q_k);

    let q_s : [[u8;16];160] = faest_aes_enc_fwd(lambda, &bobe_q, &bobe_q_k, in_of_in_and_out, false, true, ByteOrBytesElem::Bytes(BytesElem(delta))); // q is 1152, q_k is 1408
    let q_s_overline: [[u8;16];160] = faest_aes_enc_bkwd(lambda, &bobe_q, &bobe_q_k, out_of_in_and_out, false, true, &ByteOrBytesElem::Bytes(BytesElem(delta))); // q is 1152, q_k is 1408
    let mut B : [[u8;16]; s_enc] = [[0;16];s_enc];
    for j in 0..s_enc {
        let q_product : [u8;16] = gf128_mul(&q_s[j], &q_s_overline[j]);
        let delta_product : [u8;16] = gf128_mul(&delta, &delta);
        B[j] = xor_arrays(&q_product, &delta_product);
    }
    B
}
