#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::utils::galois_field::gf128_mul;
use crate::protocols::aes::{setup_rcon_table};
use crate::utils::types::{ByteArray, ByteElem, ByteOrBytesArray, ByteOrBytesElem, BytesArray, BytesElem, XorHelper};
use crate::utils::{helper_methods_cstrnts::byte_combine, math};
use crate::utils::constants::{ret_size_exp_bwd, ret_size_exp_fwd, S_ke, nk, lambda, R, l_ke};


// pk, is a tuple with a in message and out that is 128 * (\lambda / 128)

// m = 1 for mtag=0 and mkey=0
// m = lambda for mtag=1 and mkey=0
// m = lambda for mtag=0 and mkey=lambda
#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::requires(hax_lib::Prop::from(SIZE >= lambda + (((((R + 1) << 2) - 1) / nk) * 32))
.and(hax_lib::Prop::from(!(mtag && mkey))))]
#[hax_lib::ensures(|result| result.is_byte() == x.is_byte())]
pub fn faest_aes_key_exp_fwd<const SIZE: usize>(_m : usize, x: ByteOrBytesArray<SIZE>, mtag : bool, mkey : bool, _Delta : [u8;16]) -> ByteOrBytesArray<ret_size_exp_fwd> {
    /*
    if mtag && mkey{
        panic!("invalid tags")
    }

     */

    let mut y: ByteOrBytesArray<ret_size_exp_fwd> = ByteOrBytesArray::dummy(&ByteOrBytesArray::get_at_index(&x, 0));
    //let mut y : [ByteOrBytesElem;ret_size_exp_fwd] = [ByteOrBytesElem::dummy(&x[0]); ret_size_exp_fwd];
    //hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
    // while it states lambda, we iterate over words and a word is 8*4 = 32, so we don't need lambda words we need 4 words
    for i in 0..lambda{
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::Prop::from(i <= lambda)
            .and(hax_lib::Prop::from(i <= x.len()))
            .and(hax_lib::Prop::from(i <= y.len()))
            .and(ByteOrBytesArray::same_variant(&y, &x))
            //.and(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])))
        });
        hax_lib::assert!(i < y.len());
        hax_lib::assert!(i < x.len());
        hax_lib::assert!(ByteOrBytesArray::same_variant(&y, &x));
        let elem = ByteOrBytesArray::get_at_index(&x, i);
        hax_lib::assert_prop!(hax_lib::implies(ByteOrBytesArray::same_variant(&y, &x),
            elem.is_byte() == y.is_byte()));

        y = ByteOrBytesArray::set_at_index(y, i, ByteOrBytesArray::get_at_index(&x, i));
    }
    //hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
    let mut iwd = lambda;
    let mut ncond: usize = 0;
    for j in nk..((R+1) << 2){
        hax_lib::loop_invariant!(|j: usize| {
            hax_lib::Prop::from(j <= ((R + 1) << 2))
            .and(hax_lib::Prop::from(j >= nk))
            .and(hax_lib::Prop::from(ncond == (j-1) / nk))
            .and(hax_lib::Prop::from(iwd == lambda + ncond * 32))
            .and(hax_lib::Prop::from(j << 5 <= ret_size_exp_fwd))
            .and(ByteOrBytesArray::same_variant(&y, &x))
            //.and(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])))
        });
        hax_lib::assert!(j < ((R + 1) << 2));
        hax_lib::assert!(j >= nk);
        hax_lib::assert!(iwd == lambda + ncond * 32);
        hax_lib::assert!((j << 5) < ret_size_exp_fwd);

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
                    .and(ByteOrBytesArray::same_variant(&y, &x))
                });
                hax_lib::assert!(i < 32);
                hax_lib::assert!(j << 5 < ret_size_exp_fwd);
                hax_lib::assert!(iwd == lambda + ncond * 32);
                hax_lib::assert!((j << 5) + i < y.len());
                hax_lib::assert!(iwd + i < x.len());
                hax_lib::assert!((j << 5) + i < ret_size_exp_fwd);
                hax_lib::assert!(ByteOrBytesArray::same_variant(&y, &x));
                let elem = ByteOrBytesArray::get_at_index(&x, iwd + i);
                hax_lib::assert_prop!(hax_lib::implies(ByteOrBytesArray::same_variant(&y, &x),
                    elem.is_byte() == y.is_byte()));
                y = ByteOrBytesArray::set_at_index(y, (j << 5) + i, ByteOrBytesArray::get_at_index(&x, iwd + i));
                //hax_lib::assert!(ByteOrBytesElem::same_variant(&y[(j << 5) + i], &x[0]));
                //y[(j << 5) + i] = x[iwd+i];
                //hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
            }
            ncond += 1;
            iwd += 32;
            hax_lib::assert!(ncond == j / nk);
            hax_lib::assert!(iwd == lambda + ncond * 32);
            //hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
        }  else {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            for i in 0..32{
                hax_lib::loop_invariant!(|i: usize| {
                    hax_lib::Prop::from(i <= 32)
                    .and(hax_lib::Prop::from(iwd == lambda + ncond * 32))
                    .and(hax_lib::Prop::from((j << 5) + i <= ret_size_exp_fwd))
                    .and(ByteOrBytesArray::same_variant(&y, &x))
                });
                hax_lib::assert!(i < 32);
                hax_lib::assert!(iwd == lambda + ncond * 32);
                hax_lib::assert!((j << 5) + i < ret_size_exp_fwd);
                hax_lib::assert!(ByteOrBytesElem::same_variant(&ByteOrBytesArray::get_at_index(&y, ((j-nk) << 5) + i), &ByteOrBytesArray::get_at_index(&y, ((j-1) << 5) + i)));
                let value_to_pushed : ByteOrBytesElem = ByteOrBytesElem::xor_array(
                    &ByteOrBytesArray::get_at_index(&y, ((j-nk) << 5) + i),
                    &ByteOrBytesArray::get_at_index(&y, ((j-1) << 5) + i));
                //hax_lib::assert!(ByteOrBytesElem::same_variant(&value_to_pushed, &x[0]));
                //hax_lib::assert!(ByteOrBytesArray::same_variant(&y, &x));
                //let elem = ByteOrBytesArray::get_at_index(&x, iwd + i);
                /*hax_lib::assert_prop!(hax_lib::implies(ByteOrBytesArray::same_variant(, &x),
                    value_to_be_pushed.is_byte() == y.is_byte()));

                 */
                hax_lib::assert!(ByteOrBytesElem::same_variant(&ByteOrBytesArray::get_at_index(&y, (j<<5) + i), &value_to_pushed));
                hax_lib::assert!(y.is_byte() == value_to_pushed.is_byte());
                y = ByteOrBytesArray::set_at_index(y, (j << 5) + i, value_to_pushed);
                //hax_lib::assert!(ByteOrBytesElem::same_variant(&y[(j << 5) + i], &x[0]));
                //y[(j << 5) + i] = value_to_pushed;
                //hax_lib::assert_prop!(hax_lib::forall(|i: usize| i >= y.len() || ByteOrBytesElem::same_variant(&y[i], &x[0])));
            }
        }
        hax_lib::assert!(j < ((R + 1) << 2));
        hax_lib::assert!(j >= nk);
        hax_lib::assert!(ncond == j / nk);
        hax_lib::assert!(iwd == lambda + ncond * 32);
        hax_lib::assert!((j << 5) < ret_size_exp_fwd);
        hax_lib::assert!(ByteOrBytesArray::same_variant(&y, &x));
    }
    y
}


// x is 320
// x_k is 1408
#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::requires(matches!(x, x_k) && !(mtag && mkey) && N >= S_ke << 3 && M >= 1312
//&& ByteOrBytesElem::same_variant(Delta, &x[0])
)]
#[hax_lib::ensures(|result| result.is_byte() == x.is_byte())]
pub fn faest_aes_key_exp_bkwd<const N: usize, const M: usize>(
    _m : usize,
    x: ByteOrBytesArray<N>,
    x_k : ByteOrBytesArray<M>,
    mtag: bool,
    mkey : bool,
    Delta : ByteOrBytesElem)
    -> ByteOrBytesArray<ret_size_exp_bwd>
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
    let mut ncond = 0;

    // helper value
    let _one_f2m : &[u8;16] = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // return value
    let mut y : ByteOrBytesArray<ret_size_exp_bwd> = ByteOrBytesArray::dummy(&ByteOrBytesArray::get_at_index(&x, 0));

    for j in 0..S_ke{
        hax_lib::loop_invariant!(|j: usize| {
            j <= S_ke &&
            ncond == (j) / 4 &&
            i_wd == ncond * lambda &&
            c == j % 4 &&
            (j << 3) <= N &&
            ((!mtag && i_rcon == (j + 3) / 4) || (mtag && i_rcon == 0)) &&
            ByteOrBytesArray::same_variant(&y, &x)
        });

        hax_lib::assert!((j << 3) + 8 <= N);
        hax_lib::assert!(c << 3 <= usize::MAX - 8);
        hax_lib::assert!(i_wd <= usize::MAX - ((c << 3) + 8));
        hax_lib::assert!(i_wd + (c << 3) + 8 <= M);
        // first value in minues operation
        let parameter_a: ByteOrBytesArray<8> = ByteOrBytesArray::get_slice(&x, j << 3, (j << 3) + 8);
        let parameter_b: ByteOrBytesArray<8> = ByteOrBytesArray::get_slice(&x_k, i_wd + (c << 3), i_wd + (c << 3) + 8);

        //let mut x_tilde : [ByteOrBytesElem; 8] = array::from_fn(|i: usize| {assert!(i < 8); ByteOrBytesElem::xor_array(&parameter_a[i], &parameter_b[i])});
        let mut x_tilde : ByteOrBytesArray<8> = ByteOrBytesArray::dummy(&ByteOrBytesArray::get_at_index(&x, 0));
        hax_lib::assert!(ByteOrBytesArray::same_variant(&x_tilde, &x));

        for i in 0..8 {
            hax_lib::loop_invariant!(|i: usize| {
                i <= 8 &&
                ByteOrBytesArray::same_variant(&x_tilde, &x)
            });
            //hax_lib::assume!(ByteOrBytesElem::same_variant(&parameter_a[i], &parameter_b[i]));
            x_tilde = ByteOrBytesArray::set_at_index(
                x_tilde, i, ByteOrBytesElem::xor_array(
                    &ByteOrBytesArray::get_at_index(
                        &parameter_a, i),
                    &ByteOrBytesArray::get_at_index(
                        &parameter_b, i)));
        }


        // The if statement
        if !mtag && rmvRcon && (c == 0) {
            let rcon_table = setup_rcon_table();
            hax_lib::assert!(i_rcon < rcon_table.len());
            let mut rcon_value = rcon_table[i_rcon];
            hax_lib::assert!((!mtag && i_rcon == (j + 3) / 4) || (mtag && i_rcon == 0));
            i_rcon += 1;
            hax_lib::assert!((!mtag && i_rcon == (j + 4) / 4) || (mtag && i_rcon == 0));
            for i in 0..8{
                hax_lib::loop_invariant!(|i: usize| {
                    i <= 8 &&
                    ByteOrBytesArray::same_variant(&x_tilde, &x)
                });
                let r =
                    if (rcon_value & 1) == 0 {&ByteOrBytesElem::dummy(&ByteOrBytesArray::get_at_index(&x, 0))}
                    else {if mkey
                        {&Delta}
                        else {&ByteOrBytesElem::ones(&ByteOrBytesArray::get_at_index(&x, 0))}};
                let existing = ByteOrBytesArray::get_at_index(&x_tilde, i);
                //hax_lib::assume!(ByteOrBytesElem::same_variant(&existing, &r));
                x_tilde = ByteOrBytesArray::set_at_index(x_tilde, i, ByteOrBytesElem::xor_array(&existing, &r));
                rcon_value = rcon_value >> 1;
            }
        }

        let mut y_tilde : ByteOrBytesArray<N> = ByteOrBytesArray::dummy(&ByteOrBytesArray::get_at_index(&x, 0));
        hax_lib::assert!(ByteOrBytesArray::same_variant(&y_tilde, &x));
        hax_lib::assert!(ByteOrBytesArray::same_variant(&x_tilde, &x));
        hax_lib::assert_prop!(hax_lib::implies(
            ByteOrBytesArray::same_variant(&y_tilde, &x) && ByteOrBytesArray::same_variant(&x_tilde, &x),
            ByteOrBytesArray::same_variant(&y_tilde, &x_tilde) && ByteOrBytesArray::same_variant(&x_tilde, &y_tilde)));
        //hax_lib::assert!(ByteOrBytesArray::same_variant(&x_tilde, &y_tilde));
        for i in 0..8usize{
            hax_lib::loop_invariant!(|i: usize| {
                i <= 8 &&
                ByteOrBytesArray::same_variant(&x_tilde, &y_tilde)
            });
            // all three parameters
            let parameter_a = ByteOrBytesArray::get_at_index(&x_tilde, math::bitand_mod((i+7) as u8, 8-1) as usize); // should be same for usize as -1
            let parameter_b = ByteOrBytesArray::get_at_index(&x_tilde, math::bitand_mod((i+5) as u8, 8-1) as usize); // should be same for usize as -3
            let parameter_c = ByteOrBytesArray::get_at_index(&x_tilde, math::bitand_mod((i+2) as u8, 8-1) as usize); // should be same for usize as -6


            hax_lib::assert!(ByteOrBytesElem::same_variant(&parameter_a, &parameter_b));
            let middle_result: ByteOrBytesElem = ByteOrBytesElem::xor_array(&parameter_a, &parameter_b);
            hax_lib::assert!(ByteOrBytesElem::same_variant(&middle_result, &parameter_c));
            let final_result: ByteOrBytesElem = ByteOrBytesElem::xor_array(&middle_result, &parameter_c);

            y_tilde = ByteOrBytesArray::set_at_index(y_tilde, i, final_result);
            hax_lib::assert!(ByteOrBytesArray::same_variant(&x_tilde, &y_tilde))
        }
        if !mtag {
            let delta_or_1 = if mkey {&Delta} else {&ByteOrBytesElem::ones(&ByteOrBytesArray::get_at_index(&x, 0))};
            hax_lib::assert_prop!(hax_lib::implies(delta_or_1.is_byte() == x.is_byte() && x.is_byte() == y_tilde.is_byte(), delta_or_1.is_byte() == y_tilde.is_byte()));
            hax_lib::assert_prop!(hax_lib::implies(delta_or_1.is_byte() == y_tilde.is_byte(), ByteOrBytesElem::same_variant(&delta_or_1, &ByteOrBytesArray::get_at_index(&y_tilde, 0))));
            //hax_lib::assert!(ByteOrBytesElem::same_variant(&ByteOrBytesArray::get_at_index(&y_tilde, 0), delta_or_1));
            let val0 = ByteOrBytesElem::xor_array(&ByteOrBytesArray::get_at_index(&y_tilde, 0), delta_or_1);
            y_tilde = ByteOrBytesArray::set_at_index(y_tilde, 0, val0);
            //hax_lib::assume!(ByteOrBytesElem::same_variant(&y_tilde[2], delta_or_1));
            let val2 = ByteOrBytesElem::xor_array(&ByteOrBytesArray::get_at_index(&y_tilde, 2), delta_or_1);
            y_tilde = ByteOrBytesArray::set_at_index(y_tilde, 2, val2);
        }

        hax_lib::assert!(ByteOrBytesArray::same_variant(&y, &y_tilde));
        for i in 0..8{
            hax_lib::loop_invariant!(|i: usize| {
                i <= y_tilde.len() &&
                (j << 3) + i <= y.len() &&
                ByteOrBytesArray::same_variant(&y, &y_tilde)

            });
            hax_lib::assert!((j<<3) + i < y.len());
            hax_lib::assert!(ByteOrBytesArray::get_at_index(&y, (j << 3) + i).is_byte() == ByteOrBytesArray::get_at_index(&y_tilde, i).is_byte());
            y = ByteOrBytesArray::set_at_index(y, (j << 3) + i, ByteOrBytesArray::get_at_index(&y_tilde, i));
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
            }
            ncond += 1
        }
        hax_lib::assert!(ncond == (j + 1) / 4);
        hax_lib::assert!(i_wd == ((j + 1) / 4) * lambda);
        hax_lib::assert!(c == (j + 1) % 4);

        hax_lib::assert!((!mtag && i_rcon == (j + 4) / 4) || (mtag && i_rcon == 0));
    }
    y

}

#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::requires(mkey == false)]
pub fn faest_aes_exp_cstrnts_wv(w : [u8; l_ke], v : [[u8; 16]; l_ke], mkey : bool) -> ([[u8;16]; S_ke], [[u8;16]; S_ke], [u8; 1408], [[u8;16]; 1408] ) {
    /*
    if mkey {
        panic!("invalid tags")
    }
     */
    //let bobe_w: [ByteOrBytesElem; l_ke] = ByteOrBytesElem::from_byte_array(&w);
    //let bobe_v: [ByteOrBytesElem; l_ke] = ByteOrBytesElem::from_bytes_array(&v);
    let boba_w: ByteArray<l_ke> = ByteArray(w);
    let boba_v: BytesArray<l_ke> = BytesArray(v);

    let k : [u8; 1408] = faest_aes_key_exp_fwd::<l_ke>(1, ByteOrBytesArray::Byte(boba_w), false, false, [0;16]).get_byte();
    let v_k : [[u8; 16]; 1408] = faest_aes_key_exp_fwd::<l_ke>(128, ByteOrBytesArray::Bytes(boba_v), true, false, [0;16]).get_bytes();

    let w_slice : [u8; 320] = w[lambda..].try_into().unwrap(); // make w a known size, 320 is l_ke-lambda
    let w_tilde: [u8; ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<320, 1408>(1, ByteOrBytesArray::from_byte_array(w_slice), ByteOrBytesArray::from_byte_array(k), false, false, ByteOrBytesElem::Byte(ByteElem(0))).get_byte(); // w : l_ke-lambda = 448-128 = 320, k : 1408
    let v_slice : [[u8; 16]; 320] = v[lambda..].try_into().unwrap(); // make v a known size, 320 is l_ke-lambda
    let v_w: [[u8; 16]; ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<320,1408>(128,  ByteOrBytesArray::from_bytes_array(v_slice), ByteOrBytesArray::from_bytes_array(v_k), true, false, ByteOrBytesElem::Bytes(BytesElem([0;16]))).get_bytes(); // v : l_ke-lambda = 448-128 = 320, v_k : 1408

    let mut i_wd = (nk-1) << 5; // for lambda = 128 => 3 * 32 = 96
    let mut do_rot_word = true;

    let mut A_0 : [[u8;16]; S_ke] = [[0;16];S_ke];
    let mut A_1 : [[u8;16]; S_ke] = [[0;16];S_ke];

    for j in 0..(S_ke >> 2){
        hax_lib::loop_invariant!(|j: usize| {
            j <= S_ke >> 2 &&
            i_wd == ((nk - 1) << 5) + j * lambda &&
            i_wd <= 1408 &&
            (j << 5) <= ret_size_exp_bwd
        });
        let mut k_hat : [[u8;16];4] = [[0;16];4];
        let mut v_k_hat : [[u8;16];4] = [[0;16];4];
        let mut w_hat: [[u8;16];4] = [[0;16];4];
        let mut v_w_hat : [[u8;16];4] = [[0;16];4];
        hax_lib::assert!(i_wd == ((nk - 1) << 5) + j * lambda);
        hax_lib::assert!((j << 5) + (3 << 3) + 8 <= ret_size_exp_bwd);

        //TODO this loop fails, probably the i_wd calc that's wrong
        for r in 0..4 {
            hax_lib::loop_invariant!(|r: usize| {
                r <= 4 &&
                //(lambda == 256 && j > 0 && i_wd + (r << 3) + 8 <= 1408) || (i_wd + (((r+1) % 4) << 3) + 8 <= 1408) &&
                (r << 3) <= ret_size_exp_bwd - (j << 5)
            });
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };
            //hax_lib::assume!((lambda == 256 && j > 0 && i_wd + (r << 3) + 8 <= 1408) || (i_wd + (((r+1) % 4) << 3) + 8 <= 1408));
            hax_lib::assert!(((j << 5) + (r << 3) + 8) <= ret_size_exp_bwd);
            hax_lib::assert!((i_wd + (rotated << 3) + 8) <= k.len());
            hax_lib::assert!((i_wd + (rotated << 3) + 8) <= v_k.len());
            hax_lib::assert!(((j << 5) + (r << 3) + 8) <= w_tilde.len());
            hax_lib::assert!(((j << 5) + (r << 3) + 8) <= v_w.len());

            let k_hat_slice: ByteOrBytesArray<8> = ByteOrBytesArray::Byte(ByteArray(
                k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)].try_into().unwrap()));
            let v_k_hat_slice: ByteOrBytesArray<8> = ByteOrBytesArray::Bytes(BytesArray(
                v_k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)].try_into().unwrap()));
            let w_hat_slice : ByteOrBytesArray<8> = ByteOrBytesArray::Byte(ByteArray(
                w_tilde[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)].try_into().unwrap()));
            let v_w_hat_slice : ByteOrBytesArray<8> = ByteOrBytesArray::Bytes(BytesArray(
                v_w[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)].try_into().unwrap()));

            k_hat[r]   = byte_combine(k_hat_slice);
            v_k_hat[r] = byte_combine(v_k_hat_slice);
            w_hat[r]   = byte_combine(w_hat_slice);
            v_w_hat[r] = byte_combine(v_w_hat_slice);
            hax_lib::assert!((lambda == 256 && j > 0 && i_wd + (r << 3) + 8 < 1408) || (i_wd + (((r+1) % 4) << 3) + 8 < 1408));
            hax_lib::assert!(((j << 5) + (r << 3) + 8) <= ret_size_exp_bwd);
            hax_lib::assert!(r << 3 < ret_size_exp_bwd - (j << 5));
            hax_lib::assert!(r < 4);
        }
        hax_lib::assert!((lambda == 256 && j > 0 && i_wd < 1408 - 32) || (i_wd < 1408 - 32));
        hax_lib::assert!((j << 5) <= ret_size_exp_bwd - 32);
        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            hax_lib::loop_invariant!(|r: usize| {
                r <= 4 &&
                4 * j + r <= S_ke
            });
            hax_lib::assert!(4 * j + r < S_ke);
            hax_lib::assert!(4 * j + r < A_0.len());
            A_0[4*j+r] = gf128_mul(&v_k_hat[r], &v_w_hat[r]);
            let product = gf128_mul(&<[u8;16]>::xor_array(&k_hat[r],&v_k_hat[r]),&<[u8;16]>::xor_array(&w_hat[r],&v_w_hat[r]));
            let ones = ByteOrBytesElem::one_bytes();
            let xor = <[u8;16]>::xor_array(&ByteOrBytesElem::get_bytes(&ones),&A_0[(j << 2) + r]);
            hax_lib::assert!(4 * j + r < A_1.len());
            A_1[4*j+r] = <[u8;16]>::xor_array(&product,&xor);
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
        hax_lib::assert!(i_wd == ((nk - 1) << 5) + (j+1) * lambda);
        hax_lib::assert!((j << 5) + (3 << 3) + 8 <= ret_size_exp_bwd);
        hax_lib::assert!(j < S_ke >> 2);
        hax_lib::assert!(i_wd <= 1408);
        hax_lib::assert!(j << 5 < ret_size_exp_bwd);


    }
    (A_0, A_1, k, v_k)
}

#[hax_lib::fstar::options("--z3rlimit 500")]
#[hax_lib::requires(mkey == true)]
pub fn faest_aes_exp_cstrnts_qDelta(Delta : [u8;16], q : [[u8;16]; l_ke], mkey : bool) -> ([[u8;16];S_ke], [[u8;16];1408]){
    /*
    if !mkey {
        panic!("invalid tags")
    }
     */

    let q_k = faest_aes_key_exp_fwd::<l_ke>(128, ByteOrBytesArray::Bytes(BytesArray(q)), false, true, Delta);
    let q_slice : &ByteOrBytesArray<320> = &ByteOrBytesArray::Bytes(BytesArray(q[lambda..].try_into().unwrap()));

    let q_w_flat: ByteOrBytesArray<ret_size_exp_bwd> = faest_aes_key_exp_bkwd::<320, 1408>(128, *q_slice, q_k, false, true, ByteOrBytesElem::Bytes(BytesElem(Delta))); // q : l_ke-lambda = 320, q_k : 1408

    let mut B : [[u8;16];S_ke] = [[0;16];S_ke];

    let mut i_wd = (nk-1) << 5;
    let mut do_rot_word = true;
    for j in 0..(S_ke >> 2) {
        hax_lib::loop_invariant!(|j: usize| {
            j <= S_ke >> 2 &&
            i_wd == ((nk - 1) << 5) + j * lambda
        });
        let mut q_hat_k : [[u8;16];4] = [[0;16];4];
        let mut q_hat_w : [[u8;16];4] = [[0;16];4];
        for r in 0..4 {
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };
            hax_lib::assert!(i_wd + (rotated << 3) + 8 <= 1408);
            let q_hat_k_slice : ByteOrBytesArray<8> = ByteOrBytesArray::get_slice::<8>(&q_k,i_wd + (rotated << 3), i_wd + (rotated << 3) + 8);
            hax_lib::assert!((j << 5) + (r << 3) + 8 <= ret_size_exp_bwd);
            let q_hat_w_slice : ByteOrBytesArray<8> = ByteOrBytesArray::get_slice::<8>(&q_w_flat, (j << 5) + (r << 3), (j << 5) + (r << 3) + 8);

            q_hat_k[r] = byte_combine(q_hat_k_slice);
            q_hat_w[r] = byte_combine(q_hat_w_slice);
        }

        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            hax_lib::loop_invariant!(|r: usize| {
                r <= 4 &&
                (j << 2) + 4 <= S_ke
            });
            B[(j << 2) + r] = <[u8;16]>::xor_array(&gf128_mul(&q_hat_k[r], &q_hat_w[r]), &gf128_mul(&Delta, &Delta));
        }
        hax_lib::assert!(i_wd == ((nk - 1) << 5) + j * lambda);
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
        hax_lib::assert!(j < S_ke >> 2);
        hax_lib::assert!(i_wd == ((nk - 1) << 5) + (j + 1) * lambda);
    }

    let q_k_res : [[u8; 16]; 1408] = ByteOrBytesArray::get_bytes(&q_k);

    (B, q_k_res)
}


