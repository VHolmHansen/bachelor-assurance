use std::iter::Map;
use std::ops::Rem;
use hax_lib::{Int, ToInt};
use libcrux::drbg::{Drbg, RngCore};
use crate::utils::{math, finite_field};
use crate::utils::finite_field::{Field, Matrix};

type Word = [u8; 4];
type State = [[u8; nst]; nk];

const nk: usize = 4;
const nst: usize = 4;


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


fn key_expansion(key: [u8; 16]) -> Vec<Word> {
    let w= key.chunks(4).collect::<Vec<_>>();
    let new_w: Vec<Word> = w.into_iter().map(|e| {e.try_into().unwrap()}).collect();
    let rcon = setup_rcon_table(nk + 6);

    let mut result_key = Vec::with_capacity(44);
    result_key = math::push_on_vec(result_key, new_w);

    for i in nk..44 {
        let mut temp = result_key[i-1];
        if i.rem_euclid(nk) == 0 {
            let xor_temp = sub_word(rot_word(temp))[0] ^ rcon[i/nk - 1] ;
            temp = [xor_temp, 0x00, 0x00, 0x00]
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

fn setup_rcon_table(n: usize) -> Vec<u8> {
    let mut rcon: Vec<u8> = Vec::with_capacity(n);

    let mut value = 0x01;

    for i in 0..10 {
        rcon.push(value);
        value = gf28_multiply(value, 0x02)
    }
    rcon
}

fn sub_bytes() {

}

fn add_round_key(state: &mut State, keys: Vec<Word>, round: usize) {
    for row in 0..4 {
        for c in 0..4 {
            state[row][c] = state[row][c] ^ keys[round * 4 + c][row];
        }
    }
}

// doesn't work for nst = 8
fn shift_rows(state: &mut State){
    let temp_state = state.clone();
    for i in 0..nk {
        for j in 0..nst {
            state[i][j] = temp_state[i][(j + i + nst).rem_euclid(nst)] ;
        }
    }
}

fn mix_columns(state: &mut State) {
    // dummy ?
    let a: Matrix<u8> = vec![vec![0x02, 0x03, 0x01, 0x01],
                             vec![0x01, 0x02, 0x03, 0x01],
                             vec![0x01, 0x01, 0x02, 0x03],
                             vec![0x03, 0x01, 0x01, 0x02]];

    let temp_state = gf28_matrix_multiplication(a, *state);
    for row in 0..4 {
        for c in 0..4 {
            state[row][c] = temp_state[row][c];
        }
    }
}

fn rot_word(word: Word) -> Word {
    [word[1], word[2], word[3], word[0]]
}

fn sub_word(word: Word) -> Word {
    let mut result: Word = [0; 4];
    for i in 0..4 {
        result[i] = gf2_affine_transform(gf28_inverse(word[i]));
    }

    result
}

fn gf28_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0{
            result ^= a;
        }
        let hi_bit_set = a & 0x80;
        a <<= 1;
        a &= 0xFF;
        if hi_bit_set != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

fn gf28_inverse(a: u8) -> u8 {
    if a == 0 {
        return 0;
    };

    fn gf28_pow(mut base: u8, mut exp: u8) -> u8 {
        let mut result = 1;
        while exp > 0 {
            if exp & 1 != 0 {
                result = gf28_multiply(base, result);
            }
            base = gf28_multiply(base, base);
            exp >>= 1;
        }
        result
    }

    gf28_pow(a, 254)
}

fn gf2_affine_transform(w: u8) -> u8 {
    let mut result = 0u8;
    let c = 0x63;

    for i in 0..8 {
        let bit =
            ((w >> i) & 1) ^
            ((w >> ((i + 4) & 7)) & 1) ^
            ((w >> ((i + 5) & 7)) & 1) ^
            ((w >> ((i + 6) & 7)) & 1) ^
            ((w >> ((i + 7) & 7)) & 1) ^
            (c >> i);

        result |= bit << i;
    };
    result
}

fn gf28_matrix_multiplication(a: Matrix<u8>, b: State) -> Matrix<u8> {
    let rows = a.len();
    let columns = b[0].len();
    let n = b.len();

    let mut res: Matrix<u8> = vec![vec![0; columns]; rows];

    for i in 0..rows {
        for j in 0..columns {
            for k in 0..n {

                res[i][j] ^= gf28_multiply(a[i][k], b[k][j]); // can be optimized with bit trickery
            }
        }
    }

    res
}