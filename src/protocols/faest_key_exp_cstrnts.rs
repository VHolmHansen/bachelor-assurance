#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::utils::galois_field::gf_lambda_mul;
use crate::protocols::aes::{setup_rcon_table};
use crate::utils::types::{ret_value, XorHelper};
use crate::utils::helper_methods_cstrnts::{byte_combine};
use crate::utils::constants::{ret_size_exp_bwd, ret_size_exp_fwd, S_ke, nk, LAMBDA, R, l_ke, key_schedule_bits, lambda_bytes, l_ke_minus_lambda};


// calculating sbox inputs for the key expansion routine
// The key schedule works word by word (32 bits each). For words that depend on SubWord
// (every Nk words, and additionally every 4 words when Nk=8), the word is read directly
// from x (these are the non-linear witness bits recorded in ExtendWitness).
// For all other words, the word is computed as the XOR of two previous words,
// which is a linear operation and requires no witness bits.
// it is for the same reason as with encrypt, where it is called to w, v and q
pub fn faest_aes_key_exp_fwd<T : ret_value>(_m : usize, x: T, mtag : bool, mkey : bool, _Delta : [u8;lambda_bytes]) -> [<T as ret_value>::Elem;ret_size_exp_fwd] {
    if mtag && mkey{
        panic!("invalid tags")
    }
    let mut y : [<T as ret_value>::Elem;ret_size_exp_fwd] = [<T as ret_value>::dummy_value;ret_size_exp_fwd];
    // while it states lambda, we iterate over words and a word is 8*4 = 32, so we don't need lambda words we need 4 words
    // copy the first Nk words (lambda bits) directly from x into the expanded key.
    // these are the bits of the secret key k itself
    for i in 0..LAMBDA {
        y[i] = x.get_element(i);
    }
    // iwd tracks the current read position in x for non-linear (SubWord) words
    let mut iwd = LAMBDA;
    for j in nk..((R+1) << 2){
        // this word depends on SubWord if it is at a multiple of Nk,
        // or additionally at offset 4 within a block when Nk=8 (AES256)
        let cond = (j % nk) == 0 || (nk > 6 && j % nk == 4);
        if cond {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            // non-linear word: read directly from x (these are the non-lin word bits
            // recorded in ExtendWitness, i.e. the output of SubWord)
            for i in 0..32 {
                y[(j << 5) + i] = x.get_element(iwd+i);
            }
            iwd += 32;
        }  else {
            // same change made here, we are not pushing bits, we are pushing words, so for every 32 bits to be pushed, push one word
            // linear word: compute as XOR of the word Nk positions back and the previous word.
            // this is a purely linear operation so no witness bits are needed.
            for i in 0..32{
                let value_to_pushed :<T as ret_value>::Elem = <T::Elem>::xor_array(&y[((j-nk) << 5) + i], &y[((j-1) << 5) + i]);
                y[(j << 5) + i] = value_to_pushed;
            }
        }
    }
    y
}


// calculating sbox output for the key expansion routine
// For each of the S_ke S-boxes in the key schedule, the algorithm:
//   1. Removes the XOR-ed byte from the expanded key (undoing the key schedule addition)
//   2. Removes the round constant (Rcon) if applicable (only for the first byte of each
//      SubWord block, and not when computing VOLE tags since Rcon is a public constant)
//   3. Inverts the F_2-affine layer of the AES S-box bitwise
//   4. Adds the affine constant (bits 0 and 2 of 0x63) to complete the inverse
// this is for the same reasons called to w, v and q
pub fn faest_aes_key_exp_bkwd<T : ret_value, TK : ret_value<Elem = T::Elem>>(
    _m : usize,
    x: T,
    x_k : TK,
    mtag: bool,
    mkey : bool,
    Delta : <T as ret_value>::Elem)
    -> [<T as ret_value>::Elem;ret_size_exp_bwd] where
    T::Elem: XorHelper
{
    if mtag && mkey{
        panic!("invalid tags")
    }
    // index to read words from x_k
    let mut i_wd = 0;
    // counting of s-boxes
    let mut c = 0;
    // handling of round constant removal
    // rmvRcon tracks whether the round constant should be removed for the current S-box.
    let mut rmvRcon = true;
    let mut i_rcon = 0;

    // helper value
    let mut one_f2m = [0u8; lambda_bytes];
    one_f2m[0] = 0x01;
    let _one_f2m = &one_f2m;

    // return value
    let mut y : [<T as ret_value>::Elem;ret_size_exp_bwd] = [<T as ret_value>::dummy_value;ret_size_exp_bwd];

    for j in 0..S_ke{
        // first value in minus operation
        // step 1: remove the XOR-ed byte from the expanded key to recover the S-box input.
        // x contains the output of SubWord, and x_k contains the expanded key word that
        // was XOR-ed into it during the key schedule, so we XOR them to undo that addition.
        let parameter_a  = x.get_slice(j << 3,(j << 3) + 8);
        let parameter_b = x_k.get_slice(i_wd + (c << 3),i_wd + (c << 3) + 8);

        let mut x_tilde : [T::Elem; 8] = <T::Elem>::xor_two_array(parameter_a, parameter_b);

        // The if statement
        // step 2: remove the round constant (Rcon) if this is the first byte of a SubWord
        // block (c=0) and we are not computing VOLE tags (since Rcon is a public constant,
        // its tag is 0 and nothing needs to be subtracted).
        // for VOLE keys, Rcon bit 1 maps to Delta and bit 0 maps to 0, same logic as EncFwd.
        if !mtag && rmvRcon && (c == 0) {
            let rcon_table = setup_rcon_table();
            let mut rcon_value = rcon_table[i_rcon];
            i_rcon += 1;
            for i in 0..8{
                // for each bit of Rcon: if the bit is 1, XOR in Delta (for VOLE keys)
                // or field element 1 (for wire values); if the bit is 0, XOR in nothing
                let r =
                    if (rcon_value & 1) == 0 {&<T as ret_value>::dummy_value}
                    else {if mkey
                        {&Delta}
                        else {&<T as ret_value>::value_of_one()}};
                let existing = &x_tilde[i];
                x_tilde[i] = <T::Elem>::xor_array(&existing, &r);
                rcon_value = rcon_value >> 1;
            }
        }
        // step 3: invert the F_2-affine layer of the AES S-box.
        // the affine layer computes y_tilde[i] = x[i-1] XOR x[i-3] XOR x[i-6] (mod 8),
        // which is its own inverse (it is an involution over F_2).
        let mut y_tilde : T = <T as ret_value>::new_with_size(T::dummy_value);
        for i in 0..8{
            // all three parameters
            let parameter_a = &x_tilde[((i+7) as i32).rem_euclid(8) as usize]; // should be same for usize as -1
            let parameter_b = &x_tilde[((i+5) as i32).rem_euclid(8) as usize]; // should be same for usize as -3
            let parameter_c = &x_tilde[((i+2) as i32).rem_euclid(8) as usize]; // should be same for usize as -6

            let middle_result = <T::Elem>::xor_array(&parameter_a, &parameter_b);
            let final_result = <T::Elem>::xor_array(&middle_result, &parameter_c);

            y_tilde.set_element(i, &final_result);
        }
        // step 4: add the affine constant of the S-box to bits 0 and 2.
        // the AES S-box affine layer adds the constant 0x63 = 0110 0011, which has bits 0 and 2 set.
        // for wire values this adds 1, for VOLE keys this adds Delta,
        // and for VOLE tags this adds nothing (tags of public constants are 0).
        if !mtag {
            let delta_or_1 = if mkey {&Delta} else {&<T as ret_value>::value_of_one()};
            y_tilde.set_element(0, &<T::Elem>::xor_array(&y_tilde.get_element(0), delta_or_1));
            y_tilde.set_element(2, &<T::Elem>::xor_array(&y_tilde.get_element(2), delta_or_1));
        }
        // store the 8 bits of the inverted S-box output into y
        for i in 0..8{
            y[(j << 3) + i] = y_tilde.get_element(i);
        }

        // advance the S-box counter; every 4 S-boxes we move to the next word in x_k
        c = c + 1;
        if c == 4 {
            c = 0;
            if LAMBDA == 192 {
                // AES192: words are 192 bits apart in the expanded key
                i_wd = i_wd + 192
            } else {
                // changed the value to plus 1, since we don't index over 0..128, the equivalent for us is 0..1
                i_wd = i_wd + 128;
                // for AES256, rmvRcon alternates every 4 S-boxes because only every
                // other SubWord block has the round constant added
                if LAMBDA == 256 {rmvRcon = !rmvRcon; }
            }
        }
    }
    y

}

pub fn faest_aes_exp_cstrnts_wv(w : [u8; l_ke], v : [[u8; lambda_bytes]; l_ke], mkey : bool) -> ([[u8;lambda_bytes]; S_ke], [[u8;lambda_bytes]; S_ke], [u8;key_schedule_bits], [[u8;lambda_bytes];key_schedule_bits] ) {
    if mkey {
        panic!("invalid tags")
    }
    // firstly compute the sbox input for the witness and v
    let k : [u8;key_schedule_bits] = faest_aes_key_exp_fwd::<[u8;l_ke]>(1, w, false, false, [0;lambda_bytes]);
    let v_k : [[u8;lambda_bytes];key_schedule_bits] = faest_aes_key_exp_fwd::<[[u8;lambda_bytes];l_ke]>(128, v, true, false, [0;lambda_bytes]);

    // the non-linear witness bits start after the first lambda bits (which are the key itself).
    // compute the output sbox
    let w_slice : &[u8;l_ke_minus_lambda] = (&w[LAMBDA..]).try_into().unwrap(); // make w a known size, 320 is l_ke-lambda
    let w_tilde: [u8;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<[u8;l_ke_minus_lambda],[u8;key_schedule_bits]>(1, *w_slice, k, false, false, 0); // w : l_ke-lambda = 448-128 = 320, k : 1408
    // compute the output sbox
    let v_slice : &[[u8;lambda_bytes];l_ke_minus_lambda] = (&v[LAMBDA..]).try_into().unwrap(); // make v a known size, 320 is l_ke-lambda
    let v_w: [[u8;lambda_bytes];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<[[u8;lambda_bytes];l_ke_minus_lambda],[[u8;lambda_bytes];key_schedule_bits]>(128, *v_slice, v_k, true, false, [0;lambda_bytes]); // v : l_ke-lambda = 448-128 = 320, v_k : 1408
    // i_wd tracks the read position in k and v_k for the current word.
    // we start at word Nk-1 because the first S-box input is the last word of the
    // initial key (before the first SubWord operation in the key schedule)
    let mut i_wd = (nk-1) << 5;
    // do_rot_word tracks whether RotWord applies to the current SubWord block.
    // for AES128/192 it is always true; for AES256 it alternates every 4 S-boxes
    let mut do_rot_word = true;
    // list storage for a0 and a1
    let mut A_0 : [[u8;lambda_bytes]; S_ke] = [[0;lambda_bytes];S_ke];
    let mut A_1 : [[u8;lambda_bytes]; S_ke] = [[0;lambda_bytes];S_ke];
    // process S_ke/4 words, each containing 4 S-boxes
    for j in 0..(S_ke >> 2){
        // storage for thw rods
        let mut k_hat : [[u8;lambda_bytes];4] = [[0;lambda_bytes];4];
        let mut v_k_hat : [[u8;lambda_bytes];4] = [[0;lambda_bytes];4];
        let mut w_hat: [[u8;lambda_bytes];4] = [[0;lambda_bytes];4];
        let mut v_w_hat : [[u8;lambda_bytes];4] = [[0;lambda_bytes];4];

        for r in 0..4 {
            // RotWord is implemented by rotating the read index: instead of reading
            // bytes 0,1,2,3 we read bytes 1,2,3,0 (i.e. (r+1) mod 4).
            // this avoids actually rotating the data and matches the spec's RotWord operation.
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };
            // read 8 bits from k and v_k for the S-box input (the expanded key byte before SubWord),
            // applying the RotWord rotation via the rotated index
            let k_hat_slice: &[u8;8] = (&k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)]).try_into().unwrap();
            let v_k_hat_slice: &[[u8;lambda_bytes];8] = (&v_k[(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)]).try_into().unwrap();
            // read 8 bits from w_tilde and v_w for the S-box output (the inversion output)
            let w_hat_slice : &[u8;8] = (&w_tilde[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)]).try_into().unwrap();
            let v_w_hat_slice : &[[u8;lambda_bytes];8] = (&v_w   [((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)]).try_into().unwrap();
            // combine 8 bits into a single F_{2^lambda} element via ByteCombine
            k_hat[r]   = byte_combine::<u8>(*k_hat_slice);
            v_k_hat[r] = byte_combine::<[u8;lambda_bytes]>(*v_k_hat_slice);
            w_hat[r]   = byte_combine::<u8>(*w_hat_slice);
            v_w_hat[r] = byte_combine::<[u8;lambda_bytes]>(*v_w_hat_slice);
        }

        if LAMBDA == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            // the same here holds for the A value, as it did in enc cstrnts for the prover, so it is the same A values
            A_0[4*j+r] = gf_lambda_mul(&v_k_hat[r], &v_w_hat[r]);
            let product = gf_lambda_mul(&<[u8;lambda_bytes]>::xor_array(&k_hat[r],&v_k_hat[r]),&<[u8;lambda_bytes]>::xor_array(&w_hat[r],&v_w_hat[r]));
            let xor = <[u8;lambda_bytes]>::xor_array(&<[[u8;lambda_bytes];4] as ret_value>::value_of_one(),&A_0[(j << 2) + r]);
            A_1[4*j+r] = <[u8;lambda_bytes]>::xor_array(&product,&xor);
        }
        if LAMBDA == 192 {i_wd += 192} else {i_wd += 128}
    }
    (A_0, A_1, k, v_k)
}

pub fn faest_aes_exp_cstrnts_qDelta(Delta : [u8;lambda_bytes], q : [[u8;lambda_bytes]; l_ke], mkey : bool) -> ([[u8;lambda_bytes];S_ke], [[u8;lambda_bytes];key_schedule_bits]){
    if !mkey {
        panic!("invalid tags")
    }
    // input for q
    let q_k = faest_aes_key_exp_fwd::<[[u8;lambda_bytes];l_ke]>(128, q, false, true, Delta);
    // output for q, and also first start after the first lambda bits
    let q_slice : &[[u8;lambda_bytes];l_ke_minus_lambda] = (&q[LAMBDA..]).try_into().unwrap();
    let q_w_flat: [[u8;lambda_bytes];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<[[u8;lambda_bytes];l_ke_minus_lambda],[[u8;lambda_bytes];key_schedule_bits]>(128, *q_slice, q_k, false, true, Delta); // q : l_ke-lambda = 320, q_k : 1408
    // storage for B
    let mut B : [[u8;lambda_bytes];S_ke] = [[0;lambda_bytes];S_ke];
    // same word-by-word iteration as in the prover side, with the same RotWord and
    // i_wd logic, but operating on VOLE keys instead of wire values and tags
    let mut i_wd = (nk-1) << 5;
    let mut do_rot_word = true;

    for j in 0..(S_ke >> 2) {
        let mut q_hat_k : [[u8;lambda_bytes];4] = [[0;lambda_bytes];4];
        let mut q_hat_w : [[u8;lambda_bytes];4] = [[0;lambda_bytes];4];
        for r in 0..4 {
            // same RotWord rotation as in the prover side
            let rotated = if do_rot_word { (r + 1) % 4 } else { r };
            // read and ByteCombine the VOLE keys for the S-box input and output
            let q_hat_k_slice : &[[u8;lambda_bytes];8] = (&q_k    [(i_wd + (rotated << 3))..(i_wd + (rotated << 3) + 8)]).try_into().unwrap();
            let q_hat_w_slice : &[[u8;lambda_bytes];8] = (&q_w_flat[((j << 5) + (r << 3))..((j << 5) + (r << 3) + 8)]).try_into().unwrap();
            q_hat_k[r] = byte_combine::<[u8;lambda_bytes]>(*q_hat_k_slice);
            q_hat_w[r] = byte_combine::<[u8;lambda_bytes]>(*q_hat_w_slice);
        }

        if LAMBDA == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            // the same calculation here for B
            B[(j << 2) + r] = <[u8;lambda_bytes]>::xor_array(&gf_lambda_mul(&q_hat_k[r], &q_hat_w[r]), &gf_lambda_mul(&Delta, &Delta));
        }
        if LAMBDA == 192 {i_wd += 192} else {i_wd += 128}
    }
    (B, q_k)
}


