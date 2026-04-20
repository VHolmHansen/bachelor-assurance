use crate::utils::galois_field::gf128_mul;
use crate::protocols::aes::{add_round_key, setup_rcon_table, R};
use crate::utils::types::{S_ke, State};
use crate::protocols::aes::{key_expansion, mix_columns, nk, shift_rows, sub_bytes};
use crate::utils::galois_field::gf128_pow;
use crate::utils::math::{xor_arrays};
use crate::utils::types::{lambda, Word};

trait ret_value {
    type Elem: Clone;
    const dummy_value : Self::Elem;
    const value_of_one : Self::Elem;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem];
    fn get_element(&self, x : usize) -> Self::Elem;
    fn push_value(self, x : Self::Elem) -> Self;
    fn xor_array(x : &Self::Elem, y : &Self::Elem) -> Self::Elem;
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self;
    fn set_element(&mut self, index : usize, value : &Self::Elem);
    fn new_with_size(size: usize, value: Self::Elem) -> Self;
    fn len(&self) -> usize;
    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16];
}
impl ret_value for Vec<[u8;16]> {
    type Elem = [u8;16];
    const dummy_value : Self::Elem = [0;16];
    const value_of_one : Self::Elem = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem] {
        &self[x..y]
    }
    fn get_element(&self, x : usize) -> [u8;16] {
        self[x]
    }
    fn push_value(mut self, x: [u8;16]) -> Self {
        self.push(x);
        self
    }
    fn xor_array(x : &[u8;16], y : &[u8;16]) -> [u8;16]{
        xor_arrays(x, y)
    }

    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self {
        let mut res: Vec<[u8;16]> = vec![];
        for i in 0..8 {
            let value_to_push = Self::xor_array(&x[i], &y[i]);
            res.push(value_to_push);
        }
        res
    }

    fn set_element(&mut self, index : usize, value : &Self::Elem) {
        self[index] = *value;
    }
    fn new_with_size(size: usize, value: Self::Elem) -> Self {
        vec![value; size]
    }
    fn len(&self) -> usize{
        self.len()
    }

    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16]{
        gf128_mul(&x, &alpha_val)
    }
}

impl ret_value for Vec<u8> {
    type Elem = u8;
    const dummy_value : Self::Elem = 0;
    const value_of_one : Self::Elem = 1;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem] {
        &self[x..y]
    }
    fn get_element(&self, x : usize) -> u8 {
        self[x]
    }
    fn push_value(mut self, x: u8) -> Self {
        self.push(x);
        self
    }
    fn xor_array(x : &u8, y : &u8) -> u8{
        x ^ y
    }
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self {
        let mut res: Vec<u8> = vec![];
        for i in 0..8 {
            let value_to_push = Self::xor_array(&x[i], &y[i]);
            res.push(value_to_push);
        }
        res
    }

    fn set_element(&mut self, index : usize, value : &Self::Elem) {
        self[index] = *value;
    }
    fn new_with_size(size: usize, value: Self::Elem) -> Self {
        vec![value; size]
    }
    fn len(&self) -> usize{
        self.len()
    }

    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16]{
        if x == 1 {
            alpha_val
        } else {
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }
    }
}

const ret_size_exp_fwd : usize = lambda*(R+1);
const ret_size_exp_bwd : usize = 8 * S_ke;

const s_enc : usize = 16 * R;


// pk, is a tuple with a in message and out that is 128 * (\lambda / 128)
pub fn faest_aes_extend_witness(k :[u8;16], pk : (State,State)) -> Vec<u8>{
    let (in_aes, out_aes) = pk;
    let k_overline = key_expansion(k);
    let mut witness : Vec<Word> = k_overline[0..nk].to_vec();

    let mut ik = nk;

    let ske = ((-(lambda as i128)/8) + 56 + 28*((lambda as i128) / 256))/4;

    for j in 0..ske{

        witness.push(k_overline[ik]);

        ik = if lambda == 192 { ik+6 } else { ik+4 };
    }
    let Beta = lambda / 128;
    for b in 0..Beta{
        let mut state_new = in_aes;
        add_round_key(&mut state_new, k_overline[0..4].try_into().unwrap());
        for j in 1..R{
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            for i in 0..nk{
                witness.push(state_new[i]);
            }
            mix_columns(&mut state_new);
            add_round_key(&mut state_new, k_overline[4*j..4*j+4].try_into().unwrap());
        }
    }
    words_to_blocks(witness).into_iter().flat_map(|arr| arr).collect()
}
// m = 1 for mtag=0 and mkey=0
// m = lambda for mtag=1 and mkey=0
// m = lambda for mtag=0 and mkey=lambda
pub fn faest_aes_key_exp_fwd<T : ret_value>(m : usize, x: T, mtag : bool, mkey : bool, Delta : [u8;16]) -> [<T as ret_value>::Elem;ret_size_exp_fwd] {
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
pub fn faest_aes_key_exp_bkwd<T : ret_value>(m : usize, x: T, x_k : T, mtag: bool, mkey : bool, Delta : <T as ret_value>::Elem) -> [<T as ret_value>::Elem;ret_size_exp_bwd] {
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
    let one_f2m : &[u8;16] = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // return value
    let mut y : [<T as ret_value>::Elem;ret_size_exp_bwd] = [<T as ret_value>::dummy_value;ret_size_exp_bwd];

    for j in 0..S_ke{
        // first value in minues operation
        let parameter_a  = x.get_slice(8*j,8*j+8);
        let parameter_b = x_k.get_slice(i_wd+8*c,i_wd+8*c+8);

        let mut x_tilde : T = <T as ret_value>::xor_two_array(parameter_a, parameter_b);

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
                x_tilde.set_element(i, r);
                rcon_value = rcon_value >> 1;
            }
        }

        let mut y_tilde : T = <T as ret_value>::new_with_size(8, T::dummy_value);
        for i in 0..8{
            // all three parameters
            let parameter_a = x_tilde.get_element(((i-1) as i32).rem_euclid(8) as usize);
            let parameter_b = x_tilde.get_element(((i-3) as i32).rem_euclid(8) as usize);
            let parameter_c = x_tilde.get_element(((i-6) as i32).rem_euclid(8) as usize);

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

pub fn faest_aes_exp_cstrnts_wv(w : Vec<u8>, v : Vec<[u8;16]>, mkey : bool) -> ([[u8;16]; s_enc], [[u8;16]; s_enc], [u8; 1408],[[u8;16]; 1408] ) {
    if !mkey {
        panic!("invalid tags")
    }
    let k = faest_aes_key_exp_fwd::<Vec<u8>>(1, w.clone(), false, false, [0;16]);
    let v_k = faest_aes_key_exp_fwd::<Vec<[u8;16]>>(128, v.clone(), true, false, [0;16]);
    let w_tilde: [u8;ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<Vec<u8>>(1, w[lambda..].to_vec(), k.to_vec(), false, false, 0);
    let v_w: [[u8;16];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<Vec<[u8;16]>>(128, v[lambda..].to_vec(), v_k.to_vec(), true, false, [0;16]);

    let mut i_wd = 32 * (nk-1);

    let mut do_rot_word = true;

    let mut A_0 : [[u8;16]; s_enc] = [[0;16];s_enc];
    let mut A_1 : [[u8;16]; s_enc] = [[0;16];s_enc];

    for j in 0..(S_ke/4){
        let mut k_hat : [[u8;16];4] = [[0;16];4];
        let mut v_k_hat : [[u8;16];4] = [[0;16];4];
        let mut w_hat: [[u8;16];4] = [[0;16];4];
        let mut v_w_hat : [[u8;16];4] = [[0;16];4];

        for r in 0..4 {
            let mut r_mark = r;
            if do_rot_word {r_mark = ((r+3) as i64).rem_euclid(4) as usize}
            k_hat[r_mark] = byte_combine(k[(i_wd+8*r)..(i_wd+8*r+8)].to_vec());
            v_k_hat[r_mark] = byte_combine(v_k[(i_wd+8*r)..(i_wd+8*r+8)].to_vec());
            w_hat[r] = byte_combine(w_tilde[(32*j+8*r)..(32*j+8*r+8)].to_vec());
            v_w_hat[r] = byte_combine(v_w[(32*j+8*r)..(32*j+8*4+8)].to_vec())
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

pub fn faest_aes_exp_cstrnts_qDelta(Delta : [u8;16], q : Vec<[u8;16]>, mkey : bool) -> ([[u8;16];s_enc], [[u8;16];1408]){
    if mkey {
        panic!("invalid tags")
    }
    let q_k = faest_aes_key_exp_fwd::<Vec<[u8;16]>>(128, q.clone(), false, true, Delta);
    let q_w_hat: [[u8;16];ret_size_exp_bwd] = faest_aes_key_exp_bkwd::<Vec<[u8;16]>>(128, q[lambda..].to_vec(), q_k.to_vec(), false, true, Delta);

    let mut B : [[u8;16];s_enc] = [[0;16];s_enc];

    let mut i_wd = 32 * (nk-1);
    let mut do_rot_word = true;
    for j in 0..(S_ke/4) {
        let mut q_hat_k : [[u8;16];4] = [[0;16];4];
        let mut q_w_hat : [[u8;16];4] = [[0;16];4];
        for r in 0..4 {
            let mut r_mark = r;
            if do_rot_word {r_mark = ((r+3) as i64).rem_euclid(4) as usize}
            q_hat_k[r_mark] = byte_combine(q_k[(i_wd+8*r)..(i_wd+8*r+8)].to_vec());
            q_w_hat[r_mark] = byte_combine(q_w_hat[(32*j+8*r)..(32*j+8*r+8)].to_vec());
        }
        if lambda == 256 {do_rot_word = ! do_rot_word}
        for r in 0..4{
            B[4*j+r] = <Vec<[u8;16]> as ret_value>::xor_array(&gf128_mul(&q_hat_k[r], &q_w_hat[r]), &gf128_mul(&Delta, &Delta));
        }
        if lambda == 192 {i_wd += 192} else {i_wd += 128}
    }
    (B, q_k)
}


fn words_to_blocks(x: Vec<Word>) -> Vec<[u8; 16]> {
    x.chunks(4)
        .map(|chunk| {
            let mut block = [0u8; 16];
            for (i, word) in chunk.iter().enumerate() {
                block[i * 4..(i + 1) * 4].copy_from_slice(word);
            }
            block
        })
        .collect()
}

fn byte_combine<T : ret_value>(x : T) -> [u8;16] {
    if x.len() % 8 != 0 {
        panic!("invalid byte length")
    }
    let mut res : [u8;16] = [0;16];
    for i in 0..8 {
        let alpha_pow_val = alpha_pow(i);
        res = <Vec<[u8;16]> as ret_value>::xor_array(&res, &<T as ret_value>::multiply_with_alpha(x.get_element(i as usize), alpha_pow_val));
    }
    res
}

fn alpha_pow(i : i32) -> [u8;16] {
    if i == 0 {
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    } else if i == 1 {
        alpha
    } else {
        gf128_pow(&alpha, i)
    }
}

const alpha : [u8;16] = [0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1, 0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05];

