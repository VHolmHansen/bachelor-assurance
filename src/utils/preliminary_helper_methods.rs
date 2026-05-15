use crate::utils::math::xor_arrays;
use crate::utils::constants::{k_0, k_1};


//TODO
#[hax_lib::fstar::options("--z3rlimit 50")]
#[hax_lib::requires(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1))]
#[hax_lib::ensures(|result| result < 4096)]
pub fn num_rec_k0(b: &[u8; k_0]) -> u64 {
    let mut j_star = 0u64;
    for i in 0..k_0 {
        hax_lib::loop_invariant!(|i: usize| {
            i <= k_0  &&
            j_star < 1 << i &&
            j_star < 1 << k_0
        });
        let i_shift = 1u64 << i;    //TODO redundant?
        hax_lib::assert!(i_shift <= 2048 >> (k_0 - i - 1));

        hax_lib::assert!(i_shift > 0 && i_shift <= (1u64 << k_0));
        hax_lib::assert!(b[i] as u64 <= u64::MAX / i_shift);
        let bi_shift = (b[i] as u64) * i_shift;
        hax_lib::assert!(bi_shift == 2048 >> (k_0 - i - 1) || bi_shift == 0);

        hax_lib::assert!(j_star <= u64::MAX - bi_shift);
        hax_lib::assert_prop!(hax_lib::implies(b[i] != 0, bi_shift == i_shift));
        hax_lib::assert_prop!(hax_lib::implies(bi_shift != 0, j_star < bi_shift));
        j_star += bi_shift;
        hax_lib::assert!(j_star < (1 << (i + 1)));
        hax_lib::assert!(i < k_0);
        hax_lib::assert_prop!(hax_lib::implies(i < k_0 && j_star < (1 << (i + 1)), j_star < 1 << k_0));
    }
    hax_lib::assert!(j_star < 1 << k_0);
    j_star
}

//TODO
#[hax_lib::fstar::options("--z3rlimit 50")]
#[hax_lib::requires(hax_lib::forall(|i: usize| i >= b.len() || b[i] <= 1))]
#[hax_lib::ensures(|result| result < 2048)]
pub fn num_rec_k1(b: &[u8; k_1]) -> u64 {
    let mut j_star = 0u64;
    for i in 0..k_1 {
        hax_lib::loop_invariant!(|i: usize| {
            i <= k_0  &&
            j_star < 1 << i &&
            j_star < 1 << k_0
        });
        let i_shift = 1u64 << i;    //TODO redundant?
        hax_lib::assert!(i_shift <= 1024 >> (k_1 - i - 1));

        hax_lib::assert!(i_shift > 0 && i_shift <= (1u64 << k_1));
        hax_lib::assert!(b[i] as u64 <= u64::MAX / i_shift);
        let bi_shift = (b[i] as u64) * i_shift;
        hax_lib::assert!(bi_shift == 1024 >> (k_1 - i - 1) || bi_shift == 0);

        hax_lib::assert!(j_star <= u64::MAX - bi_shift);
        hax_lib::assert_prop!(hax_lib::implies(b[i] != 0, bi_shift == i_shift));
        hax_lib::assert_prop!(hax_lib::implies(bi_shift != 0, j_star < bi_shift));
        j_star += bi_shift;
        hax_lib::assert!(j_star < (1 << (i + 1)));
        hax_lib::assert!(i < k_1);
        hax_lib::assert_prop!(hax_lib::implies(i < k_0 && j_star < (1 << (i + 1)), j_star < 1 << k_0));
    }
    hax_lib::assert!(j_star < 1 << k_1);
    j_star
}


#[hax_lib::requires(INNER_LEN > 0 && OUTER_LEN > 0
&& OUTER_LEN <= usize::MAX / INNER_LEN
&& COMBINED_LEN == OUTER_LEN * INNER_LEN)]
pub fn flatten<const OUTER_LEN: usize, const INNER_LEN: usize, const COMBINED_LEN: usize>(input: [[u8; INNER_LEN]; OUTER_LEN]) -> [u8; COMBINED_LEN] {
    let mut res: [u8; COMBINED_LEN] = [0u8; COMBINED_LEN];
    for i in 0..OUTER_LEN {
        hax_lib::loop_invariant!(|i: usize| {
            i <= OUTER_LEN
            && i <= usize::MAX / INNER_LEN
        });
        for j in 0..INNER_LEN {
            hax_lib::loop_invariant!(|j: usize| {
                j <= INNER_LEN
                && j <= usize::MAX - i * INNER_LEN
                && i * INNER_LEN + j <= COMBINED_LEN
            });
            res[i * INNER_LEN + j] = input[i][j];
        }
    }
    res
}

pub fn xor_u8(x: &u8, y: &u8) -> u8 {
    x^y
}

pub fn xor_u8_16_array(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    xor_arrays::<16>(x, y)
}

