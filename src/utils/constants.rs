#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

// BASE PARAMETERS - only these change per variant
pub const LAMBDA: usize = 128; // can be 128, 192 or 256
pub const tau    : usize = 11; // is [11, 16] for 128, [16, 24] for 192 and [22, 32] for 256
pub const ell    : usize = 1600; // can be 1600, 3264 or 4000
pub const iv_bytes: usize = 16;

// AES OWF PARAMETERS - derived from lambda
pub const nk    : usize = LAMBDA / 32;
pub const nst   : usize = 4; // always 4 for AES, only changes for Rijndael-EM
pub const R     : usize = nk + 6;
pub const beta  : usize = (LAMBDA + 127) / 128;
pub const S_ke  : usize = (56 - (LAMBDA as i128 / 8) + 28 * (LAMBDA as i128 / 256)) as usize; // 40
pub const s_enc : usize = R << 4;
pub const l_ke  : usize = LAMBDA + (S_ke << 3); // 448
pub const l_enc : usize = (s_enc - 16) << 3;
pub const big_C : usize = S_ke + beta * s_enc;

// VOLE PARAMETERS - derived from lambda and tau
pub const k_0   : usize = (LAMBDA + tau - 1) / tau;  // ceil(lambda/tau)
pub const k_1   : usize = LAMBDA / tau;               // floor(lambda/tau)
pub const tau_0 : usize = LAMBDA % tau;
pub const tau_1 : usize = tau - tau_0;
pub const k_0_pow : usize = 1 << k_0;
pub const k_1_pow : usize = 1 << k_1;

// SIZE PARAMETERS - derived from lambda, tau, ell
pub const big_b          : usize = 16;
pub const lambda_bytes   : usize = LAMBDA / 8;
pub const ell_hat        : usize = ell + 2 * LAMBDA + big_b;
pub const ell_hat_bytes  : usize = ell_hat / 8;
pub const x0_bytes       : usize = (ell + LAMBDA) / 8;
pub const x1_bytes       : usize = (LAMBDA + big_b) / 8;
pub const h_v_size       : usize = x1_bytes * LAMBDA;
pub const ell_plus_lambda: usize = ell + LAMBDA;

// CHALLENGE SIZES - derived from lambda
pub const chall1_bytes : usize = (5 * LAMBDA + 64) / 8;
pub const chall2_bytes : usize = (3 * LAMBDA + 64) / 8;
pub const chall3_bytes : usize = LAMBDA / 8;  // same as lambda_bytes

// MISC
pub const tau_minus_one : usize = tau - 1;
pub const not_deterministic_test : bool = false;

// FIELD ELEMENT SIZES
pub const ret_size_exp_fwd : usize = (R + 1) << 7;
pub const ret_size_exp_bwd : usize = S_ke << 3;


// GENERATOR ELEMENT - changes per lambda (Appendix A)

// made into a function, because of having to return differnt sizes
pub fn get_alpha() -> [u8; lambda_bytes] {
    let mut alpha_1 = [0u8; lambda_bytes];
    match LAMBDA {
        128 => {
            let src = [0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1,
                0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05];
            alpha_1.copy_from_slice(&src);
        },
        192 => {
            let src = [0x63, 0x97, 0x38, 0x6f, 0xd5, 0xa3, 0xc8, 0xcc,
                0xea, 0xbd, 0x6e, 0x96, 0x6c, 0xd7, 0x65, 0xe6,
                0x62, 0x36, 0x6b, 0x0e, 0x14, 0xc8, 0x0b, 0x31];
            alpha_1[..24].copy_from_slice(&src);
        },
        256 => {
            let src = [0xe7, 0xfe, 0xde, 0x0b, 0x42, 0x88, 0x97, 0x96,
                0x67, 0x4e, 0x47, 0xa0, 0x38, 0x8d, 0xd6, 0xbe,
                0x6a, 0xe1, 0xf1, 0xf8, 0x45, 0x98, 0x22, 0xdf,
                0x33, 0x58, 0xc9, 0x20, 0xcf, 0xa8, 0xc9, 0x04];
            alpha_1[..32].copy_from_slice(&src);
        },
        _ => {
            let src = [0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1,
                0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05];
            alpha_1.copy_from_slice(&src);
        }
    }
    alpha_1
}
// TYPE ALIASES
pub type State = [[u8; 4]; 4]; // always 4x4 for AES, nst=4 always
// extra:
pub const lambda_plus_iv : usize = lambda_bytes+iv_bytes;
pub const lambda_bytes_times_three : usize = lambda_bytes * 3;
pub const lambda_bytes_times_two : usize = lambda_bytes * 2;
pub const key_schedule_bits: usize = (R + 1) << 7;  // (R+1) * 128 bits
pub const aes_block_bits: usize = 128;  // AES block is always 128 bits
pub const l_ke_minus_lambda: usize = l_ke - LAMBDA;
pub const w_lambda_size: usize = ell - LAMBDA;      // 1600-128=1472
pub const w_enc_start: usize = l_ke;                // 448
pub const w_enc_size: usize = l_enc;                // 1152
pub const ell_bytes: usize = ell / 8;
pub const x0_padded_lambda_size: usize = (x0_bytes + lambda_bytes - 1) / lambda_bytes * lambda_bytes;
pub const x0_padded_64_size    : usize = (x0_bytes + 7) / 8 * 8;
pub const num_chunks_lambda     : usize = x0_padded_lambda_size / lambda_bytes;
pub const num_chunks_64         : usize = x0_padded_64_size / 8;