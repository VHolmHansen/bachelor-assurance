
use std::ops::Rem;
use hax_lib::{loop_invariant, Int, ToInt};
use libcrux::drbg::{Drbg, RngCore};
use crate::utils::{math, finite_field, galois_field};
use crate::utils::finite_field::{Field};
use crate::utils::types::{Matrix, State, Word};


pub const nk: usize = 4;            // code dup
pub const nst: usize = 4;           // code dup
const R: usize = nk + 6; // max(nk, nst) + 6


#[hax_lib::exclude]
pub fn main(field: Field) {
    let mut rand_gen = match Drbg::new(libcrux::digest::Algorithm::Sha256) {
        Ok(drbg) => drbg,
        Err(e) => panic!("{}", e)
    };

    let mut key = [0; 16];
    rand_gen.fill_bytes(&mut key);
    let expanded_key = key_expansion(key);

    // dummy state
    let mut state: State = [[0; nst]; nk];
    for i in 0..nk {
        for j in 0..nst {
            state[i][j] = (i + j * i) as u8;
        }
    }

}

#[hax_lib::exclude]
pub fn encrypt(state: State, key: Vec<Word>) -> State {
    let mut res_state = state;
    add_round_key(&mut res_state, key[0..nst].to_vec());
    println!("state_matrix: {:?}", res_state);

    //4-8
    for r in 1..R {
        sub_bytes(&mut res_state);
        shift_rows(&mut res_state);
        mix_columns(&mut res_state);
        add_round_key(&mut res_state, key[(nst * r)..(nst*(r+1))].to_vec());
    }

    sub_bytes(&mut res_state);
    shift_rows(&mut res_state);
    add_round_key(&mut res_state, key[nst*(R)..nst*(R+1)].to_vec()); //replace R where R = nk*11 as temp

    res_state
}

#[hax_lib::exclude]
pub fn key_expansion(key: [u8; 16]) -> Vec<Word> {
    let w= key.chunks(4).collect::<Vec<_>>();
    let new_w: Vec<Word> = w.into_iter().map(|e| {e.try_into().unwrap()}).collect();
    let rcon = setup_rcon_table(nk + 6);

    let mut result_key = Vec::with_capacity(44);
    result_key = math::push_on_vec(result_key, new_w);

    for i in nk..44 {
        let mut temp = result_key[i-1];
        if i.rem_euclid(nk) == 0 {
            let mut rotated = sub_word(rot_word(temp));
            rotated[0] ^= rcon[i/nk-1];
            temp = rotated;
        };
        if nk > 6 && i.rem_euclid(nk) == 4 {
            temp = sub_word(temp);
        };
        let mut temp_word: Word = [0; 4];
        for j in 0..4 {
            temp_word[j] = result_key[i-nk][j] ^ temp[j]
        }
        result_key.push(temp_word);
    }

    println!("resultkey {:?}", result_key);
    result_key
}

#[hax_lib::exclude]
fn setup_rcon_table(n: usize) -> Vec<u8> {
    let mut rcon: Vec<u8> = Vec::with_capacity(n);

    let mut value = 0x01;

    for i in 0..10 {
        rcon.push(value);
        value = galois_field::gf28_multiply(value, 0x02)
    }
    rcon
}

#[hax_lib::exclude]
fn sub_bytes(state: &mut State) {
    for i in 0..nk {
        for j in 0..nst {
            state[i][j] = s_box(state[i][j]);
        }
    }
}

#[hax_lib::exclude]
#[hax_lib::ensures(|result| result <= u8::MAX)]
fn s_box(b: u8) -> u8{
    gf2_affine_transform(galois_field::gf28_inverse(b))
}

#[hax_lib::exclude]
pub fn add_round_key(state: &mut State, keys: Vec<Word>) {
    for row in 0..4 {
        for c in 0..4 {
            state[row][c] = state[row][c] ^ keys[c][row];
        }
    }
}

// doesn't work for nst = 8
#[hax_lib::requires(state.len() == nk
                    && state[0].len() == nst)]
#[hax_lib::ensures(|state| state.len() == nk
                    && state[0].len() == nst)]
pub fn shift_rows(state: &mut State){
    let temp_state = state.clone();
    for i in 1..nk {
        for j in 0..nst {
            state[i][j] = temp_state[i][(j + i).rem_euclid(nst)] ;
        }
    }
}

#[hax_lib::requires(state.len() == nk
                    && state[0].len() == nst)]
#[hax_lib::ensures(|state| state.len() == nk
                    && state[0].len() == nst)]
pub fn mix_columns(state: &mut State) {
    let a: Matrix<u8> = vec![vec![2, 3, 1, 1],
                             vec![1, 2, 3, 1],
                             vec![1, 1, 2, 3],
                             vec![3, 1, 1, 2]];

    let temp_state = galois_field::gf28_matrix_multiplication(a, *state);
    for row in 0..4 {
        for c in 0..4 {
            state[row][c] = temp_state[row][c];
        }
    }
}

#[hax_lib::requires(word.len() == 4)]
#[hax_lib::ensures(|result| result.len() == 4)]
fn rot_word(word: Word) -> Word {
    [word[1], word[2], word[3], word[0]]
}

#[hax_lib::requires(word.len() == 4)]
#[hax_lib::ensures(|result| result.len() == 4)]
fn sub_word(word: Word) -> Word {
    let mut result: Word = [0; 4];
    for i in 0..4 {
        result[i] = gf2_affine_transform(galois_field::gf28_inverse(word[i]));
    }

    result
}

#[hax_lib::requires(w <= u8::MAX)]
#[hax_lib::ensures(|result| result <= u8::MAX)]
pub fn gf2_affine_transform(w: u8) -> u8 {
    let mut result = 0u8;
    let c = 0x63;

    for i in 0u8..8u8 {
        hax_lib::loop_invariant!(|i: u8| {
            i <= u8::BITS as u8
        });

        let bit =
            ((w >> i) & 1) ^
                ((w >> bitand_mod(i + 4, 7)) & 1) ^
                ((w >> bitand_mod(i + 5, 7)) & 1) ^
                ((w >> bitand_mod(i + 6, 7)) & 1) ^
                ((w >> bitand_mod(i + 7, 7)) & 1) ^
                ((c >> i) & 1);

        result |= bit << i;
    };

    result
}

#[hax_lib::requires(n <= u8::MAX && modu <= u8::BITS as u8)]
#[hax_lib::ensures(|result| result < u8::BITS as u8)]
fn bitand_mod(n: u8, modu: u8) -> u8 {
    hax_lib::assume!(n & modu < u8::BITS as u8);
    n & modu
}