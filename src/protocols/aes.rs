
use crate::utils::{galois_field};
use crate::utils::types::{Matrix, State, Word};
use crate::utils::constants::{nk, nst, R};

#[hax_lib::requires(key.len() == (R + 1) << 2)]    //<< 2 = * nst where nst = 4
pub fn encrypt(state: State, key: &[Word]) -> State {
    let mut res_state = state;
    add_round_key(&mut res_state, key[0..nst].try_into().unwrap());

    //4-8
    for r in 1..R {
        sub_bytes(&mut res_state);
        shift_rows(&mut res_state);
        mix_columns(&mut res_state);
        add_round_key(&mut res_state, key[(r << 2)..((r+1) << 2)].try_into().unwrap());     //nst * r = r << 2 & nst*(r+1) = (r+1) << 2
    }

    sub_bytes(&mut res_state);
    shift_rows(&mut res_state);
    add_round_key(&mut res_state, key[(R << 2)..(R+1) << 2].try_into().unwrap());     //nst * R = R << 2 & nst * (R+1) = (R+1) << 2

    res_state
}

pub fn key_expansion(key: [u8; 16]) -> [Word; (R + 1) << 2] {      // nst * (R+1) = (R+1) << 2
    let rcon = setup_rcon_table();
    let mut result_key: [Word; 44] = [[0u8, 0u8, 0u8, 0u8]; 44];

    for i in 0..4 {
        for j in 0..4 {
            result_key[i][j] = key[(i << 2)+j];        // i * 4 = i << 2
        }
    }

    for i in nk..((R + 1) << 2) {      // nst * (R+1) = (R+1) << 2
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
        result_key[i] = temp_word;
    }

    result_key
}

#[hax_lib::ensures(|result| result.len() == R)]
pub fn setup_rcon_table() -> [u8; R] {
    let mut rcon: [u8; R] = [0u8; R];
    let mut value: u8 = 0x01;
    for i in 0..R {
        rcon[i] = value;
        value = galois_field::gf28_multiply(value, 0x02)
    }
    rcon

}

#[hax_lib::requires(prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len()
                        || state[i].len() == nst)))]
#[hax_lib::ensures(|state| prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len()
                        || state[i].len() == nst)))]
pub fn sub_bytes(state: &mut State) {
    for i in 0..nk {
        for j in 0..nst {
            state[i][j] = s_box(state[i][j]);
        }
    }
}

#[hax_lib::ensures(|result| result <= u8::MAX)]
fn s_box(b: u8) -> u8{
    gf2_affine_transform(galois_field::gf28_inverse(b))
}


#[hax_lib::requires(prop::from(keys.len() >= nk)
                    .and(hax_lib::forall(|i: usize| i >= keys.len() || keys[i].len() >= nst)))]
#[hax_lib::ensures(|state| prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len() || state[i].len() == nst)))]
pub fn add_round_key(state: &mut State, keys: [Word; nst]) {
    for row in 0..4 {
        for c in 0..4 {
            state[c][row] = state[c][row] ^ keys[c][row];
        }
    }
}

// doesn't work for nst = 8
#[hax_lib::requires(state.len() == nk
                    && state[0].len() == nst)]
#[hax_lib::ensures(|state| prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len() || state[i].len() == nst)))]
pub fn shift_rows(state: &mut State) {
    let temp_state = state.clone();
    for row in 1..4 {
        for col in 0..4 {
            state[col][row] = temp_state[(col + row).rem_euclid(4)][row];
        }
    }
}

#[hax_lib::requires(state.len() == nk
                    && state[0].len() == nst)]
#[hax_lib::ensures(|state| state.len() == nk
                    && state[0].len() == nst)]
pub fn mix_columns(state: &mut State) {
    let a: Matrix<u8, nst, nk> =
        [[2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]];

    for col in 0..4 {
        let column = [state[col][0], state[col][1], state[col][2], state[col][3]];
        for row in 0..4 {
            state[col][row] =
                galois_field::gf28_multiply(a[row][0], column[0]) ^
                    galois_field::gf28_multiply(a[row][1], column[1]) ^
                    galois_field::gf28_multiply(a[row][2], column[2]) ^
                    galois_field::gf28_multiply(a[row][3], column[3]);
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
    hax_lib::assume!(n & modu < u8::BITS as u8);    //TODO: make lemma?
    n & modu
}