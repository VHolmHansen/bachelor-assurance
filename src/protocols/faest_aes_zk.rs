use crate::protocols::aes::{add_round_key, setup_rcon_table, R};
use crate::utils::types::{k_0, k_1, tau_0, S_ke, State};
use crate::protocols::aes::{key_expansion, mix_columns, nk, shift_rows, sub_bytes};
use crate::utils::math::{transform_byte_array_to_state, xor_arrays};
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
}

const ret_size_exp_fwd : usize = lambda*(R+1);
const ret_size_exp_bwd : usize = 8 * S_ke;


// pk, is a tuple with a in message and out that is 128 * (\lambda / 128)
pub fn faest_aes_extend_witness(k :[u8;16], pk : (State,State)) -> Vec<[u8;16]>{
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
        add_round_key(&mut state_new, k_overline[0..4].to_vec());
        for j in 1..R{
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            for i in 0..nk{
                witness.push(state_new[i]);
            }
            mix_columns(&mut state_new);
            add_round_key(&mut state_new, k_overline[4*j..4*j+4].to_vec());
        }
    }
    words_to_blocks(witness)
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
            let rcon_table = setup_rcon_table(10);
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

fn blocks_to_words(x: Vec<[u8; 16]>) -> Vec<Word> {
    x.into_iter()
        .flat_map(|block| {
            // Split the 16-byte block into four 4-byte chunks
            block.chunks_exact(4)
                .map(|chunk| {
                    let mut word = [0u8; 4];
                    word.copy_from_slice(chunk);
                    word
                })
                .collect::<Vec<Word>>()
        })
        .collect()
}