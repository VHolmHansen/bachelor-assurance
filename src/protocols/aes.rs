use hax_lib::*;
use crate::utils::constants::lambda_bytes;
use crate::utils::{galois_field};
use crate::utils::types::{Matrix, State, Word};
use crate::utils::constants::{nk, nst, R};

#[requires(key.len() == (R + 1) << 2)]    //<< 2 = * nst where nst = 4
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

pub fn key_expansion(key: [u8; lambda_bytes]) -> [Word; (R + 1) * 4] {      // nst * (R+1) = (R+1) << 2
    // let rcon = setup_rcon_table();
    let mut result_key: [Word; (R + 1) * 4] = [[0u8, 0u8, 0u8, 0u8]; (R + 1) * 4];

    for i in 0..nk {
        for j in 0..4 {
            result_key[i][j] = key[(i * 4)+j];        // i * 4 = i << 2
        }
    }

    for i in nk..((R + 1) * 4) {      // nst * (R+1) = (R+1) << 2
        let mut temp = result_key[i-1];
        if i.rem_euclid(nk) == 0 {
            let mut rotated = sub_word(rot_word(temp));
            rotated[0] ^= RCON_TABLE[i/nk-1];
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

#[ensures(|result| result.len() == R)]
pub fn setup_rcon_table() -> [u8; R] {
    let mut rcon: [u8; R] = [0u8; R];
    let mut value: u8 = 0x01;
    for i in 0..R {
        rcon[i] = value;
        value = galois_field::gf28_multiply(value, 0x02)
    }
    rcon

}

#[cfg(not(feature = "hax"))]
pub fn sub_bytes(state: &mut State) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = S_BOX_ARRAY[state[i][j] as usize]; // switched to using an array with precomputed values
        }
    }
}

#[cfg(feature = "hax")]
#[hax_lib::requires(Prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len()
                        || state[i].len() == nst)))]
#[hax_lib::ensures(|state| Prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len()
                        || state[i].len() == nst)))]
pub fn sub_bytes(state: &mut State) {
    for i in 0..nk {
        for j in 0..nst {
            state[i][j] = s_box(state[i][j]);
        }
    }
}

#[ensures(|result| result <= u8::MAX)]
fn s_box(b: u8) -> u8{
    gf2_affine_transform(galois_field::gf28_inverse(b))
}


#[requires(Prop::from(keys.len() >= nk)
                    .and(hax_lib::forall(|i: usize| i >= keys.len() || keys[i].len() >= nst)))]
#[ensures(|state| Prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len() || state[i].len() == nst)))]
pub fn add_round_key(state: &mut State, keys: [Word; nst]) {
    for row in 0..4 {
        for c in 0..4 {
            state[c][row] = state[c][row] ^ keys[c][row];
        }
    }
}

// doesn't work for nst = 8
#[requires(state.len() == nk
                    && state[0].len() == nst)]
#[ensures(|state| Prop::from(state.len() == nk)
                    .and(hax_lib::forall(|i: usize| i >= state.len() || state[i].len() == nst)))]
pub fn shift_rows(state: &mut State) {
    let temp_state = state.clone();
    for row in 1..4 {
        for col in 0..4 {
            state[col][row] = temp_state[(col + row).rem_euclid(4)][row];
        }
    }
}

#[requires(state.len() == nk
                    && state[0].len() == nst)]
#[ensures(|state| state.len() == nk
                    && state[0].len() == nst)]
pub fn mix_columns(state: &mut State) {
    let a: Matrix<u8, 4, 4> =
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

#[requires(word.len() == 4)]
#[ensures(|result| result.len() == 4)]
fn rot_word(word: Word) -> Word {
    [word[1], word[2], word[3], word[0]]
}

#[cfg(not(feature = "hax"))]
fn sub_word(word: Word) -> Word {
    [S_BOX_ARRAY[word[0] as usize],S_BOX_ARRAY[word[1] as usize],S_BOX_ARRAY[word[2] as usize],S_BOX_ARRAY[word[3] as usize]]
}

#[cfg(feature = "hax")]
#[requires(word.len() == 4)]
#[ensures(|result| result.len() == 4)]
fn sub_word(word: Word) -> Word {
    let mut result: Word = [0; 4];
    for i in 0..4 {
        result[i] = gf2_affine_transform(galois_field::gf28_inverse(word[i]));
    }
    result
}

#[requires(w <= u8::MAX)]
#[ensures(|result| result <= u8::MAX)]
pub fn gf2_affine_transform(w: u8) -> u8 {
    let mut result = 0u8;
    let c = 0x63;

    for i in 0u8..8u8 {
        loop_invariant!(|i: u8| {
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

//TODO: generalize, move and utilize
#[requires(n <= u8::MAX && modu <= u8::BITS as u8)]
#[ensures(|result| result < u8::BITS as u8)]
pub fn bitand_mod(n: u8, modu: u8) -> u8 {
    hax_lib::assume!(n & modu < u8::BITS as u8);    //TODO: make lemma?
    n & modu
}
const RCON_TABLE : [u8;11] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108];

#[cfg(not(feature = "hax"))]
const S_BOX_ARRAY : [u8;256] =
    [99, 124, 119, 123, 242, 107, 111, 197,
        48, 1, 103, 43, 254, 215, 171, 118,
        202, 130, 201, 125, 250, 89, 71, 240,
        173, 212, 162, 175, 156, 164, 114, 192,
        183, 253, 147, 38, 54, 63, 247, 204,
        52, 165, 229, 241, 113, 216, 49, 21,
        4, 199, 35, 195, 24, 150, 5, 154,
        7, 18, 128, 226, 235, 39, 178, 117,
        9, 131, 44, 26, 27, 110, 90, 160,
        82, 59, 214, 179, 41, 227, 47, 132,
        83, 209, 0, 237, 32, 252, 177, 91,
        106, 203, 190, 57, 74, 76, 88, 207,
        208, 239, 170, 251, 67, 77, 51, 133,
        69, 249, 2, 127, 80, 60, 159, 168,
        81, 163, 64, 143, 146, 157, 56, 245,
        188, 182, 218, 33, 16, 255, 243, 210,
        205, 12, 19, 236, 95, 151, 68, 23, 196,
        167, 126, 61, 100, 93, 25, 115, 96, 129,
        79, 220, 34, 42, 144, 136, 70, 238, 184,
        20, 222, 94, 11, 219, 224, 50, 58, 10,
        73, 6, 36, 92, 194, 211, 172, 98, 145,
        149, 228, 121, 231, 200, 55, 109, 141,
        213, 78, 169, 108, 86, 244, 234, 101,
        122, 174, 8, 186, 120, 37, 46, 28, 166,
        180, 198, 232, 221, 116, 31, 75, 189,
        139, 138, 112, 62, 181, 102, 72, 3, 246,
        14, 97, 53, 87, 185, 134, 193, 29, 158,
        225, 248, 152, 17, 105, 217, 142, 148,
        155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104,
        65, 153, 45, 15, 176, 84, 187, 22];
