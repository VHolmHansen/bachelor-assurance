#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::utils::galois_field::gf128_mul;
use crate::protocols::aes::{setup_rcon_table};
use crate::utils::types::{ret_value};
use crate::utils::helper_methods_cstrnts::{byte_combine};
use crate::utils::constants::{ret_size_exp_bwd, ret_size_exp_fwd, S_ke, nk, lambda, R, l_ke};


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
    for j in nk..((R+1) << 2){
        let cond = (j % nk) == 0 || (nk > 6 && j % nk == 4);
        if cond {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32 {
                y[(j << 5) + i] = x.get_element(iwd+i);
            }
            iwd += 32;
        }  else {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32{
                let value_to_pushed :<T as ret_value>::Elem = <T as ret_value>::xor_array(&y[((j-nk) << 5) + i], &y[((j-1) << 5) + i]);
                y[(j << 5) + i] = value_to_pushed;
            }
        }
    }
    y
}


// x is 320
// x_k is 1408
pub fn faest_aes_key_exp_bkwd<T : ret_value, TK : ret_value<Elem = T::Elem>>(_m : usize, x: T, x_k : TK, mtag: bool, mkey : bool, Delta : <T as ret_value>::Elem) -> [<T as ret_value>::Elem;ret_size_exp_bwd] {
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
        let parameter_a  = x.get_slice(j << 3,(j << 3) + 8);
        let parameter_b = x_k.get_slice(i_wd + (c << 3),i_wd + (c << 3) + 8);

        let mut x_tilde : [T::Elem; 8] = <T as ret_value>::xor_two_array(parameter_a, parameter_b);

        // The if statement
        if !mtag && rmvRcon && (c == 0) {
            let rcon_table = setup_rcon_table();
            let mut rcon_value = rcon_table[i_rcon];
            i_rcon += 1;
            for i in 0..8{
                let r =
                    if (rcon_value & 1) == 0 {&<T as ret_value>::dummy_value}
                    else {if mkey
                        {&Delta}
                        else {&<T as ret_value>::value_of_one}};
                let existing = &x_tilde[i];
                x_tilde[i] = <T as ret_value>::xor_array(&existing, &r);
                rcon_value = rcon_value >> 1;
            }
        }

        let mut y_tilde : T = <T as ret_value>::new_with_size(T::dummy_value); 
        for i in 0..8{
            // all three parameters
            let parameter_a = &x_tilde[((i+7) as i32).rem_euclid(8) as usize]; // should be same for usize as -1
            let parameter_b = &x_tilde[((i+5) as i32).rem_euclid(8) as usize]; // should be same for usize as -3
            let parameter_c = &x_tilde[((i+2) as i32).rem_euclid(8) as usize]; // should be same for usize as -6

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
            y[(j << 3) + i] = y_tilde.get_element(i);
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

pub fn faest_aes_exp_cstrnts_wv(w : [u8; l_ke], v : [[u8; 16]; l_ke], mkey : bool) -> ([[u8;16]; S_ke], [[u8;16]; S_ke], [u8; 1408], [[u8;16]; 1408] ) {
    if mkey {
        panic!("invalid tags")
    }
    let k : [u8;1408] = faest_aes_key_exp_fwd::<[u8;l_ke]>(1, w, false, false, [0;16]);
    let v_k : [[u8;16];1408] = faest_aes_key_exp_fwd::<[[u8;16];l_ke]>(128, v, true, false, [0;16]);

    let w_slice : &[u8;320] = (&w[lambda..]).try_into().unwrap(); // make w a known size, 320 is l_ke-lambda
    let w_tilde: [u8;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<[u8;320],[u8;1408]>(1, *w_slice, k, false, false, 0); // w : l_ke-lambda = 448-128 = 320, k : 1408
    let v_slice : &[[u8;16];320] = (&v[lambda..]).try_into().unwrap(); // make v a known size, 320 is l_ke-lambda
    let v_w: [[u8;16];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<[[u8;16];320],[[u8;16];1408]>(128, *v_slice, v_k, true, false, [0;16]); // v : l_ke-lambda = 448-128 = 320, v_k : 1408

    let mut i_wd = (nk-1) << 5;

    let mut do_rot_word = true;

    let mut A_0 : [[u8;16]; S_ke] = [[0;16];S_ke];
    let mut A_1 : [[u8;16]; S_ke] = [[0;16];S_ke];

    for j in 0..(S_ke >> 2){
        let mut k_hat : [[u8;16];4] = [[0;16];4];
        let mut v_k_hat : [[u8;16];4] = [[0;16];4];
        let mut w_hat: [[u8;16];4] = [[0;16];4];
        let mut v_w_hat : [[u8;16];4] = [[0;16];4];

        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };

            let k_hat_slice: &[u8;8] = (&k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)]).try_into().unwrap();
            let v_k_hat_slice: &[[u8;16];8] = (&v_k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)]).try_into().unwrap();
            let w_hat_slice : &[u8;8] = (&w_tilde[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)]).try_into().unwrap();
            let v_w_hat_slice : &[[u8;16];8] = (&v_w   [((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)]).try_into().unwrap();

            k_hat[r]   = byte_combine(*k_hat_slice);
            v_k_hat[r] = byte_combine(*v_k_hat_slice);
            w_hat[r]   = byte_combine(*w_hat_slice);
            v_w_hat[r] = byte_combine(*v_w_hat_slice);
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            A_0[4*j+r] = gf128_mul(&v_k_hat[r], &v_w_hat[r]);
            let product = gf128_mul(&<[[u8;16];4] as ret_value>::xor_array(&k_hat[r],&v_k_hat[r]),&<[[u8;16];4] as ret_value>::xor_array(&w_hat[r],&v_w_hat[r]));
            let xor = <[[u8;16];4] as ret_value>::xor_array(&<[[u8;16];4] as ret_value>::value_of_one,&A_0[(j << 2) + r]);
            A_1[4*j+r] = <[[u8;16];4] as ret_value>::xor_array(&product,&xor);
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }
    (A_0, A_1, k, v_k)
}

pub fn faest_aes_exp_cstrnts_qDelta(Delta : [u8;16], q : [[u8;16]; l_ke], mkey : bool) -> ([[u8;16];S_ke], [[u8;16];1408]){
    if !mkey {
        panic!("invalid tags")
    }
    let q_k = faest_aes_key_exp_fwd::<[[u8;16];l_ke]>(128, q, false, true, Delta);
    let q_slice : &[[u8;16];320] = (&q[lambda..]).try_into().unwrap();
    let q_w_flat: [[u8;16];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<[[u8;16];320],[[u8;16];1408]>(128, *q_slice, q_k, false, true, Delta); // q : l_ke-lambda = 320, q_k : 1408

    let mut B : [[u8;16];S_ke] = [[0;16];S_ke];

    let mut i_wd = (nk-1) << 5;
    let mut do_rot_word = true;
    for j in 0..(S_ke >> 2) {
        let mut q_hat_k : [[u8;16];4] = [[0;16];4];
        let mut q_hat_w : [[u8;16];4] = [[0;16];4];
        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };

            let q_hat_k_slice : &[[u8;16];8] = (&q_k    [(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)]).try_into().unwrap();
            let q_hat_w_slice : &[[u8;16];8] = (&q_w_flat[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)]).try_into().unwrap();

            q_hat_k[r] = byte_combine(*q_hat_k_slice);
            q_hat_w[r] = byte_combine(*q_hat_w_slice);
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            B[(j << 2) + r] = <[[u8;16];4] as ret_value>::xor_array(&gf128_mul(&q_hat_k[r], &q_hat_w[r]), &gf128_mul(&Delta, &Delta));
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }
    (B, q_k)
}


