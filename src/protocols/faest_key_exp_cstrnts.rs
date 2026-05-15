#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use std::array;
use crate::protocols::aes;
use crate::utils::galois_field::gf128_mul;
use crate::protocols::aes::{setup_rcon_table};
use crate::utils::types::{ret_value, ByteElem, ByteOrBytesElem, BytesElem, XorHelper};
use crate::utils::helper_methods_cstrnts::{byte_combine};
use crate::utils::constants::{ret_size_exp_bwd, ret_size_exp_fwd, S_ke, nk, lambda, R, l_ke};


// pk, is a tuple with a in message and out that is 128 * (\lambda / 128)

// m = 1 for mtag=0 and mkey=0
// m = lambda for mtag=1 and mkey=0
// m = lambda for mtag=0 and mkey=lambda
#[hax_lib::fstar::options("--z3rlimit 50")]
#[hax_lib::opaque]
#[hax_lib::requires(hax_lib::Prop::from(SIZE >= lambda + (((((R + 1) << 2) - 1) / nk) * 32))
.and(hax_lib::Prop::from(!(mtag && mkey)))
.and(hax_lib::forall(|i: usize| i >= SIZE || ByteOrBytesElem::same_variant(&x[i], &x[0]))))]
pub fn faest_aes_key_exp_fwd<const SIZE: usize>(_m : usize, x: [ByteOrBytesElem; SIZE], mtag : bool, mkey : bool, _Delta : [u8;16]) -> [ByteOrBytesElem;ret_size_exp_fwd] {
    /*
    if mtag && mkey{
        panic!("invalid tags")
    }

     */
    let mut y : [ByteOrBytesElem;ret_size_exp_fwd] = [ByteOrBytesElem::dummy(&x[0]); ret_size_exp_fwd];
    hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
    // while it states lambda, we iterate over words and a word is 8*4 = 32, so we don't need lambda words we need 4 words
    for i in 0..lambda{
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::Prop::from(i <= lambda)
            .and(hax_lib::Prop::from(i <= x.len()))
            .and(hax_lib::Prop::from(i <= y.len()))
            .and(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])))
        });
        hax_lib::assert!(i < y.len());
        hax_lib::assert!(i < x.len());
        hax_lib::assert!(ByteOrBytesElem::same_variant(&y[i], &x[0]));
        y[i] = x[i];
    }
    hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
    let mut iwd = lambda;
    let mut ncond: usize = 0;
    for j in nk..((R+1) << 2){
        hax_lib::loop_invariant!(|j: usize| {
            hax_lib::Prop::from(j <= ((R + 1) << 2))
            .and(hax_lib::Prop::from(j >= nk))
            .and(hax_lib::Prop::from(ncond == (j-1) / nk))
            .and(hax_lib::Prop::from(iwd == lambda + ncond * 32))
            .and(hax_lib::Prop::from(j << 5 <= ret_size_exp_fwd))
            .and(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])))
        });
        hax_lib::assert!(j < ((R + 1) << 2));
        hax_lib::assert!(j >= nk);
        hax_lib::assert!(iwd == lambda + ncond * 32);
        hax_lib::assume!((j << 5) < ret_size_exp_fwd);
        let cond = (j % nk) == 0 || (nk > 6 && j % nk == 4);
        if cond {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32 {
                hax_lib::loop_invariant!(|i: usize| {
                    hax_lib::Prop::from(i <= 32)
                    .and(hax_lib::Prop::from(ncond == (j-1) / nk))
                    .and(hax_lib::Prop::from(iwd == lambda + ncond * 32))
                    .and(hax_lib::Prop::from(iwd + i <= x.len()))
                    .and(hax_lib::Prop::from((j << 5) + i <= ret_size_exp_fwd))
                });
                hax_lib::assert!(i < 32);
                hax_lib::assert!(j << 5 < ret_size_exp_fwd);
                hax_lib::assert!(iwd == lambda + ncond * 32);
                hax_lib::assert!((j << 5) + i < y.len());
                hax_lib::assert!(iwd + i < x.len());
                hax_lib::assert!((j << 5) + i < ret_size_exp_fwd);
                hax_lib::assert!(ByteOrBytesElem::same_variant(&y[(j << 5) + i], &x[0]));
                y[(j << 5) + i] = x[iwd + i];
                hax_lib::assert!(ByteOrBytesElem::same_variant(&y[(j << 5) + i], &x[0]));
                //y[(j << 5) + i] = x[iwd+i];
                hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
            }
            ncond += 1;
            iwd += 32;
            hax_lib::assert!(ncond == j / nk);
            hax_lib::assert!(iwd == lambda + ncond * 32);
            hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
        }  else {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32{
                hax_lib::loop_invariant!(|i: usize| {
                    hax_lib::Prop::from(i <= 32)
                    .and(hax_lib::Prop::from(iwd == lambda + ncond * 32))
                    .and(hax_lib::Prop::from((j << 5) + i <= ret_size_exp_fwd))
                });
                hax_lib::assert!(i < 32);
                hax_lib::assert!(iwd == lambda + ncond * 32);
                hax_lib::assert!((j << 5) + i < ret_size_exp_fwd);
                hax_lib::assert!(ByteOrBytesElem::same_variant(&y[((j-nk) << 5) + i], &x[0]));
                let value_to_pushed : ByteOrBytesElem = ByteOrBytesElem::xor_array(&y[((j-nk) << 5) + i], &y[((j-1) << 5) + i]);
                hax_lib::assert!(ByteOrBytesElem::same_variant(&value_to_pushed, &x[0]));
                y[(j << 5) + i] = value_to_pushed;
                hax_lib::assert!(ByteOrBytesElem::same_variant(&y[(j << 5) + i], &x[0]));
                //y[(j << 5) + i] = value_to_pushed;
                hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
            }
        }
    }
    y
}


// x is 320
// x_k is 1408
#[hax_lib::requires(matches!(x, x_k) && !(mtag && mkey) && N >= 320 && M >= 1312)]
pub fn faest_aes_key_exp_bkwd<const N: usize, const M: usize>(
    _m : usize,
    x: [ByteOrBytesElem; N],
    x_k : [ByteOrBytesElem; M],
    mtag: bool,
    mkey : bool,
    Delta : ByteOrBytesElem)
    -> [ByteOrBytesElem;ret_size_exp_bwd]
{
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
    let mut y : [ByteOrBytesElem;ret_size_exp_bwd] = [ByteOrBytesElem::dummy(&x[0]);ret_size_exp_bwd];

    for j in 0..S_ke{
        hax_lib::loop_invariant!(|j: usize| {
            j <= S_ke &&
            i_wd + (c << 3) + 8 <= M
        });
        // first value in minues operation
        let parameter_a: [ByteOrBytesElem; 8] = x[j << 3..(j << 3) + 8].try_into().unwrap();
        let parameter_b: [ByteOrBytesElem; 8] = x_k[i_wd + (c << 3)..i_wd + (c << 3) + 8].try_into().unwrap();

        let mut x_tilde : [ByteOrBytesElem; 8] = array::from_fn(|i: usize| ByteOrBytesElem::xor_array(&parameter_a[i], &parameter_b[i]));

        // The if statement
        if !mtag && rmvRcon && (c == 0) {
            let rcon_table = setup_rcon_table();
            let mut rcon_value = rcon_table[i_rcon];
            i_rcon += 1;
            for i in 0..8{
                let r =
                    if (rcon_value & 1) == 0 {&ByteOrBytesElem::dummy(&x[0])}
                    else {if mkey
                        {&Delta}
                        else {&ByteOrBytesElem::ones(&x[0])}};
                let existing = &x_tilde[i];
                x_tilde[i] = ByteOrBytesElem::xor_array(&existing, &r);
                rcon_value = rcon_value >> 1;
            }
        }

        let mut y_tilde : [ByteOrBytesElem; N] = [ByteOrBytesElem::dummy(&x[0]); N];
        for i in 0..8usize{
            hax_lib::loop_invariant!(|i: usize| {
               i <= 8
            });
            // all three parameters
            let parameter_a = &x_tilde[aes::bitand_mod((i+7) as u8, 8-1) as usize]; // should be same for usize as -1
            let parameter_b = &x_tilde[aes::bitand_mod((i+5) as u8, 8-1) as usize]; // should be same for usize as -3
            let parameter_c = &x_tilde[aes::bitand_mod((i+2) as u8, 8-1) as usize]; // should be same for usize as -6

            let middle_result = ByteOrBytesElem::xor_array(&parameter_a, &parameter_b);
            let final_result = ByteOrBytesElem::xor_array(&middle_result, &parameter_c);

            y_tilde[i] = final_result;
        }
        if !mtag {
            let delta_or_1 = if mkey {&Delta} else {&ByteOrBytesElem::ones(&x[0])};
            y_tilde[0] = ByteOrBytesElem::xor_array(&y_tilde[0], delta_or_1);
            y_tilde[2] = ByteOrBytesElem::xor_array(&y_tilde[2], delta_or_1);
        }

        for i in 0..8{
            y[(j << 3) + i] = y_tilde[i];
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
    let bobe_w: [ByteOrBytesElem; l_ke] = ByteOrBytesElem::from_byte_array(&w);
    let bobe_v: [ByteOrBytesElem; l_ke] = ByteOrBytesElem::from_bytes_array(&v);

    let k : [ByteOrBytesElem;1408] = faest_aes_key_exp_fwd::<l_ke>(1, bobe_w, false, false, [0;16]);
    let v_k : [ByteOrBytesElem;1408] = faest_aes_key_exp_fwd::<l_ke>(128, bobe_v, true, false, [0;16]);

    let w_slice : [ByteOrBytesElem;320] = bobe_w[lambda..].try_into().unwrap(); // make w a known size, 320 is l_ke-lambda
    let w_tilde: [ByteOrBytesElem;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<320, 1408>(1, w_slice, k, false, false, ByteOrBytesElem::Byte(ByteElem(0))); // w : l_ke-lambda = 448-128 = 320, k : 1408
    let v_slice : [ByteOrBytesElem;320] = bobe_v[lambda..].try_into().unwrap(); // make v a known size, 320 is l_ke-lambda
    let v_w: [ByteOrBytesElem;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<320,1408>(128, v_slice, v_k, true, false, ByteOrBytesElem::Bytes(BytesElem([0;16]))); // v : l_ke-lambda = 448-128 = 320, v_k : 1408

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

            let k_hat_slice: [ByteOrBytesElem;8] =
                array::from_fn(|i| {
                    ByteOrBytesElem::Byte(ByteElem(
                        ByteOrBytesElem::get_byte(&k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)][i]))
                    )
                });
            let v_k_hat_slice: [ByteOrBytesElem;8] =
                array::from_fn(|i| {
                    ByteOrBytesElem::Bytes(BytesElem(
                        ByteOrBytesElem::get_bytes(&v_k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)][i]))
                    )
                });
            let w_hat_slice : [ByteOrBytesElem;8] =
                array::from_fn(|i| {
                    ByteOrBytesElem::Byte(ByteElem(
                        ByteOrBytesElem::get_byte(&w_tilde[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)][i]))
                    )
                });
            let v_w_hat_slice : [ByteOrBytesElem;8] =
                array::from_fn(|i| {
                    ByteOrBytesElem::Bytes(BytesElem(
                        ByteOrBytesElem::get_bytes(&v_w[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)][i]))
                    )
                });

            k_hat[r]   = byte_combine(k_hat_slice);
            v_k_hat[r] = byte_combine(v_k_hat_slice);
            w_hat[r]   = byte_combine(w_hat_slice);
            v_w_hat[r] = byte_combine(v_w_hat_slice);
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            A_0[4*j+r] = gf128_mul(&v_k_hat[r], &v_w_hat[r]);
            let product = gf128_mul(&<[u8;16]>::xor_array(&k_hat[r],&v_k_hat[r]),&<[u8;16]>::xor_array(&w_hat[r],&v_w_hat[r]));
            let xor = <[u8;16]>::xor_array(&<[[u8;16];4] as ret_value>::value_of_one,&A_0[(j << 2) + r]);
            A_1[4*j+r] = <[u8;16]>::xor_array(&product,&xor);
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }
    let k_res : [u8; 1408] = array::from_fn(|i: usize| {
        ByteOrBytesElem::get_byte(&k[i])
    });

    let v_k_res : [[u8; 16]; 1408] = array::from_fn(|i: usize| {
        ByteOrBytesElem::get_bytes(&v_k[i])
    });

    (A_0, A_1, k_res, v_k_res)
}

pub fn faest_aes_exp_cstrnts_qDelta(Delta : [u8;16], q : [[u8;16]; l_ke], mkey : bool) -> ([[u8;16];S_ke], [[u8;16];1408]){
    if !mkey {
        panic!("invalid tags")
    }

    let bobe_q = ByteOrBytesElem::from_bytes_array(&q);

    let q_k = faest_aes_key_exp_fwd::<l_ke>(128, bobe_q, false, true, Delta);
    let q_slice : &[ByteOrBytesElem;320] = (&bobe_q[lambda..]).try_into().unwrap();


    let q_w_flat: [ByteOrBytesElem;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<320, 1408>(128, *q_slice, q_k, false, true, ByteOrBytesElem::Bytes(BytesElem(Delta))); // q : l_ke-lambda = 320, q_k : 1408

    let mut B : [[u8;16];S_ke] = [[0;16];S_ke];

    let mut i_wd = (nk-1) << 5;
    let mut do_rot_word = true;
    for j in 0..(S_ke >> 2) {
        let mut q_hat_k : [[u8;16];4] = [[0;16];4];
        let mut q_hat_w : [[u8;16];4] = [[0;16];4];
        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };

            let q_hat_k_slice : [ByteOrBytesElem;8] = q_k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)].try_into().unwrap();

            let q_hat_w_slice : [ByteOrBytesElem;8] =q_w_flat[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)].try_into().unwrap();

            q_hat_k[r] = byte_combine(q_hat_k_slice);
            q_hat_w[r] = byte_combine(q_hat_w_slice);
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            B[(j << 2) + r] = <[u8;16]>::xor_array(&gf128_mul(&q_hat_k[r], &q_hat_w[r]), &gf128_mul(&Delta, &Delta));
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }

    let q_k_res : [[u8; 16]; 1408] = array::from_fn(|i: usize| {
        ByteOrBytesElem::get_bytes(&q_k[i])
    });

    (B, q_k_res)
}


