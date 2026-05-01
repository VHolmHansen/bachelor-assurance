#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::utils::galois_field::gf128_mul;
use crate::protocols::aes::{setup_rcon_table};
use crate::utils::types::{ret_value};
use crate::utils::helper_methods_cstrnts::{byte_combine};
use crate::utils::constants::{ret_size_exp_bwd, ret_size_exp_fwd, s_enc, S_ke, nk, lambda, R, l_ke};


// pk, is a tuple with a in message and out that is 128 * (\lambda / 128)

// m = 1 for mtag=0 and mkey=0
// m = lambda for mtag=1 and mkey=0
// m = lambda for mtag=0 and mkey=lambda
pub fn faest_aes_key_exp_fwd<T : ret_value>(_m : usize, x: T, mtag : bool, mkey : bool, _Delta : [u8;16]) -> [<T as ret_value>::Elem;ret_size_exp_fwd] {
    if mtag && mkey{
        panic!("invalid tags")
    }
    let mut y : [<T as ret_value>::Elem;ret_size_exp_fwd] = [<T as ret_value>::dummy_value;ret_size_exp_fwd];
    // while it states lambda, we iterate over words and a word is 8*4 = 32, so we don't need lambda words we need 4 words
    for i in 0..lambda{
        y[i] = x.get_element(i);
    }
    let mut iwd = lambda;
    for j in nk..4*(R+1){
        let cond = (j % nk) == 0 || (nk > 6 && j % nk == 4);
        if cond {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32 {
                y[32*j+i] = x.get_element(iwd+i);
            }
            iwd += 32;
        }  else {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32{
                let value_to_pushed :<T as ret_value>::Elem = <T as ret_value>::xor_array(&y[32*(j-nk)+i], &y[32*(j-1)+i]);
                y[32*j+i] = value_to_pushed;
            }
        }
    }
    y
}


// x_k is the size of
pub fn faest_aes_key_exp_bkwd<T : ret_value>(_m : usize, x: T, x_k : T, mtag: bool, mkey : bool, Delta : <T as ret_value>::Elem) -> [<T as ret_value>::Elem;ret_size_exp_bwd] {
    if mtag && mkey{
        panic!("invalid tags")
    }
    // index to read words from x_k
    let mut i_wd = 0;
    // counting of s-boxes
    let mut c = 0;
    // handling of round constant removal
    let mut rmvRcon = true;
    let mut i_rcon = 0;

    // helper value
    let _one_f2m : &[u8;16] = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // return value
    let mut y : [<T as ret_value>::Elem;ret_size_exp_bwd] = [<T as ret_value>::dummy_value;ret_size_exp_bwd];

    for j in 0..S_ke{
        // first value in minues operation
        let parameter_a  = x.get_slice(8*j,8*j+8);
        let parameter_b = x_k.get_slice(i_wd+8*c,i_wd+8*c+8);

        let mut x_tilde : T = <T as ret_value>::xor_two_array(parameter_a, parameter_b);

        // The if statement
        if !mtag && rmvRcon && (c == 0) {
            let rcon_table = setup_rcon_table(10);
            let mut rcon_value = rcon_table[i_rcon];
            i_rcon += 1;
            for i in 0..8{
                let r =
                    if (rcon_value & 1) == 0 {&<T as ret_value>::dummy_value}
                    else {if mkey
                        {&Delta}
                        else {&<T as ret_value>::value_of_one}};
                let existing = x_tilde.get_element(i);
                x_tilde.set_element(i, &<T as ret_value>::xor_array(&existing, &r));
                rcon_value = rcon_value >> 1;
            }
        }

        let mut y_tilde : T = <T as ret_value>::new_with_size(8, T::dummy_value);
        for i in 0..8{
            // all three parameters
            let parameter_a = x_tilde.get_element(((i+7) as i32).rem_euclid(8) as usize); // should be same for usize as -1
            let parameter_b = x_tilde.get_element(((i+5) as i32).rem_euclid(8) as usize); // should be same for usize as -3
            let parameter_c = x_tilde.get_element(((i+2) as i32).rem_euclid(8) as usize); // should be same for usize as -6

            let middle_result = <T as ret_value>::xor_array(&parameter_a, &parameter_b);
            let final_result = <T as ret_value>::xor_array(&middle_result, &parameter_c);

            y_tilde.set_element(i, &final_result);
        }
        if !mtag {
            let delta_or_1 = if mkey {&Delta} else {&<T as ret_value>::value_of_one};
            y_tilde.set_element(0, &<T as ret_value>::xor_array(&y_tilde.get_element(0), delta_or_1));
            y_tilde.set_element(2, &<T as ret_value>::xor_array(&y_tilde.get_element(2), delta_or_1));
        }

        for i in 0..8{
            y[8 * j + i] = y_tilde.get_element(i);
        }


        c = c + 1;
        if c == 4 {
            c = 0;
            if lambda == 192 {
                // unsure what the value should be here
                i_wd = i_wd + 192
            } else {
                // changed the value to plus 1, since we don't index over 0..128, the equivalent for us is 0..1
                i_wd = i_wd + 128;
                if lambda == 256 {rmvRcon = !rmvRcon; }
            }
        }

    }
    y

}

pub fn faest_aes_exp_cstrnts_wv(w : &[u8], v : &[[u8; 16]], mkey : bool) -> ([[u8;16]; S_ke], [[u8;16]; S_ke], [u8; 1408], [[u8;16]; 1408] ) {
    if mkey {
        panic!("invalid tags")
    }
    let k = faest_aes_key_exp_fwd::<Vec<u8>>(1, w.to_vec(), false, false, [0;16]);
    let v_k = faest_aes_key_exp_fwd::<Vec<[u8;16]>>(128, v.to_vec(), true, false, [0;16]);
    let w_tilde: [u8;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<Vec<u8>>(1, w[lambda..].to_vec(), k.to_vec(), false, false, 0);
    let v_w: [[u8;16];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<Vec<[u8;16]>>(128, v[lambda..].to_vec(), v_k.to_vec(), true, false, [0;16]);

    let mut i_wd = 32 * (nk-1);

    let mut do_rot_word = true;

    let mut A_0 : [[u8;16]; S_ke] = [[0;16];S_ke];
    let mut A_1 : [[u8;16]; S_ke] = [[0;16];S_ke];

    for j in 0..(S_ke/4){
        let mut k_hat : [[u8;16];4] = [[0;16];4];
        let mut v_k_hat : [[u8;16];4] = [[0;16];4];
        let mut w_hat: [[u8;16];4] = [[0;16];4];
        let mut v_w_hat : [[u8;16];4] = [[0;16];4];

        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };

            k_hat[r]   = byte_combine(k  [(i_wd + 8*rotated)..(i_wd + 8*rotated + 8)].to_vec());
            v_k_hat[r] = byte_combine(v_k[(i_wd + 8*rotated)..(i_wd + 8*rotated + 8)].to_vec());
            w_hat[r]   = byte_combine(w_tilde[(32*j + 8*r)..(32*j + 8*r + 8)].to_vec());
            v_w_hat[r] = byte_combine(v_w   [(32*j + 8*r)..(32*j + 8*r + 8)].to_vec());
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            A_0[4*j+r] = gf128_mul(&v_k_hat[r], &v_w_hat[r]);
            let product = gf128_mul(&<Vec<[u8;16]> as ret_value>::xor_array(&k_hat[r],&v_k_hat[r]),&<Vec<[u8;16]> as ret_value>::xor_array(&w_hat[r],&v_w_hat[r]));
            let xor = <Vec<[u8;16]> as ret_value>::xor_array(&<Vec<[u8;16]> as ret_value>::value_of_one,&A_0[4*j+r]);
            A_1[4*j+r] = <Vec<[u8;16]> as ret_value>::xor_array(&product,&xor);
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }
    (A_0, A_1, k, v_k)
}

pub fn faest_aes_exp_cstrnts_qDelta(Delta : [u8;16], q : [[u8;16]; l_ke], mkey : bool) -> ([[u8;16];S_ke], [[u8;16];1408]){
    if !mkey {
        panic!("invalid tags")
    }
    let q_k = faest_aes_key_exp_fwd::<Vec<[u8;16]>>(128, q.to_vec(), false, true, Delta);
    let q_w_flat: [[u8;16];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<Vec<[u8;16]>>(128, q[lambda..].to_vec(), q_k.to_vec(), false, true, Delta);

    let mut B : [[u8;16];S_ke] = [[0;16];S_ke];

    let mut i_wd = 32 * (nk-1);
    let mut do_rot_word = true;
    for j in 0..(S_ke/4) {
        let mut q_hat_k : [[u8;16];4] = [[0;16];4];
        let mut q_hat_w : [[u8;16];4] = [[0;16];4];
        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };

            q_hat_k[r] = byte_combine(q_k    [(i_wd + 8*rotated)..(i_wd + 8*rotated + 8)].to_vec());
            q_hat_w[r] = byte_combine(q_w_flat[(32*j + 8*r)..(32*j + 8*r + 8)].to_vec());
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            B[4*j+r] = <Vec<[u8;16]> as ret_value>::xor_array(&gf128_mul(&q_hat_k[r], &q_hat_w[r]), &gf128_mul(&Delta, &Delta));
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }
    (B, q_k)
}


