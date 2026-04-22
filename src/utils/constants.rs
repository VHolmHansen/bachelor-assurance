#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
pub const nk: usize = 4;            // code dup
pub const nst: usize = 4;           // code dup
pub const R: usize = nk + 6; // max(nk, nst) + 6
pub const lambda: usize = 128;
pub const ell : usize = (1600 + 2*128 + 16)/8;
pub const ell_bit_size : usize = 1600;
pub const tau : usize = 11;
pub const k_0 : usize = 12;
pub const k_1 : usize = 11;
pub const tau_0 : usize = 7;
pub const tau_1 : usize = 4;
pub const l_ke : usize = lambda +8* S_ke;
pub const l_enc : usize = 8 * (s_enc - 16);
pub type State = [[u8; nst]; nk];

pub const ret_size_exp_fwd : usize = lambda *(R +1);
pub const ret_size_exp_bwd : usize = 8 * S_ke;

pub const s_enc : usize = 16 * R;

pub const S_ke : usize = (56-(lambda as i128/8)+28 * (lambda as i128/256)) as usize;

pub const alpha : [u8;16] = [0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1, 0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05];

pub const beta : usize = 1; // er 1 for 128 er 2 for 192 og 256