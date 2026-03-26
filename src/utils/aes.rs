use std::cmp::Ord;
use std::iter::Map;
use std::ops::Rem;
use hax_lib::{loop_invariant, Int, ToInt};
use libcrux::drbg::{Drbg, RngCore};
use crate::utils::{math, finite_field};
use crate::utils::finite_field::{Field, Matrix};

type Word = [u8; 4];
type State = [[u8; nst]; nk];

const nk: usize = 4;
const nst: usize = 4;
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
pub fn key_expansion(key: [u8; 16]) -> Vec<Word> {
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

#[hax_lib::exclude]
fn setup_rcon_table(n: usize) -> Vec<u8> {
    let mut rcon: Vec<u8> = Vec::with_capacity(n);

    let mut value = 0x01;

    for i in 0..10 {
        rcon.push(value);
        value = gf28_multiply(value, 0x02)
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
    gf2_affine_transform(gf28_inverse(b))
}

#[hax_lib::exclude]
pub fn add_round_key(state: &mut State, keys: Vec<Word>) {
    for row in 0..4 {
        for c in 0..4 {
            state[row][c] = state[row][c] ^ keys[row][c];
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
    // dummy ?
    let a: Matrix<u8> = vec![vec![2, 3, 1, 1],
                             vec![1, 2, 3, 1],
                             vec![1, 1, 2, 3],
                             vec![3, 1, 1, 2]];

    let temp_state = gf28_matrix_multiplication(a, *state);
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
        result[i] = gf2_affine_transform(gf28_inverse(word[i]));
    }

    result
}

#[hax_lib::requires(a <= u8::MAX
                    && b <= u8::MAX
                    && a >= 0
                    && b >= 0)]
#[hax_lib::ensures(|result| result <= u8::MAX)]
pub fn gf28_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0{
            result ^= a;
        }
        let hi_bit_set = a & 0x80;      //
        a <<= 1;                            // shift left
        a &= 0xFF;                          // mod 255
        if hi_bit_set != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

#[hax_lib::opaque]
#[hax_lib::requires(a <= u8::MAX
&& a >= 0)]
#[hax_lib::ensures(|result| gf28_multiply(result, a) == 1)]
fn gf28_inverse(a: u8) -> u8 {
    if a == 0 {
        return 0;
    };

    #[hax_lib::requires(base <= u8::MAX && exp <= u8::MAX)]
    #[hax_lib::ensures(|result| result <= u8::MAX)]
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

    let result = gf28_pow(a, 254);
    assert!(result > 0);
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

#[hax_lib::requires(a.len() > 0
                    && a[0].len() > 0
                    && b.len() > 0
                    && b[0].len() > 0)]
#[hax_lib::ensures(|result| result.len() == a.len()
                    && result[0].len() == b.len())]
pub fn gf28_matrix_multiplication(a: Matrix<u8>, b: State) -> Matrix<u8> {
    assert!(a.len() > 0);
    let rows = a.len();
    let columns = b[0].len();
    let n = b.len();

    let mut res: Matrix<u8> = vec![vec![0; columns]; rows];
    assert!(n > 0);
    assert!(res.len() == a.len());
    assert!(res.len() > 0);
    assert!(res[0].len() == b.len());

    for i in 0..rows {
        loop_invariant!(|i: usize| {
            i < res.len()
            && res.len() > 0
            && res[i].len() > 0
            && i < rows
            /*
            && a.len() > 0
            && b.len() > 0
            && i < a.len()

             */
        });
        assert!(res[i].len() > 0);
        hax_lib::assert!(i < a.len());
        hax_lib::assert!(i < res.len());
        for j in 0..columns {
            loop_invariant!(|j: usize| {
                i < res.len()
                && j < res[i].len()
                && j < columns
                && res.len() > 0
                && res[i].len() > 0
                /*
                && a.len() > 0
                && b.len() > 0
                && j < res[i].len()
                && i < a.len()
                && j < b[0].len()

                 */
            });
            hax_lib::assert!(i < a.len());
            hax_lib::assert!(i < res.len() && j < res[i].len());
            let mut temp = 0u8;
            for k in 0..n {
                loop_invariant!(|k: usize| {

                    res.len() > 0
                    && i < res.len()
                    && res[i].len() > 0

                    && a.len() > 0
                    && a[i].len() > 0
                    && b.len() > 0
                    && k < n
                    && k < a[i].len()
                    && k < b.len()
                    /*
                    && a.len() > 0
                    && b.len() > 0
                    && j < res[i].len()
                    && k < res.len()
                    && k < res[i].len()
                    && i < a.len()
                    && k < a[i].len()
                    && k < b.len()
                    && j < b[k].len()

                     */
                });
                let old_len = res.len();
                hax_lib::assert!(i < res.len() && j < res[i].len());

                hax_lib::assert!(i < a.len() && k < a[i].len() && k < b.len() && j < b[k].len());
                temp ^= gf28_multiply(a[i][k], b[k][j]); // can be optimized with bit trickery


                hax_lib::assert!(res.len() == rows && res.len() == a.len());
                hax_lib::assert!(res[i].len() == columns && res[i].len() == b.len());
            }
            println!("res[{:?}][{:?}] = {:?}", i, j, temp);
            res[i][j] = temp;
        }
    }
    println!("gf28mul 87 * 69: {:?}", gf28_multiply(a[0][0], b[0][1]));
    res[0][1] =  gf28_multiply(a[0][0],b[0][1]) ^ gf28_multiply(a[0][1],b[1][1]) ^ gf28_multiply(a[0][2],b[2][1]) ^ gf28_multiply(a[0][3],b[3][1]);


    res
}