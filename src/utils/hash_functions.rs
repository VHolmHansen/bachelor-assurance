#![allow(non_upper_case_globals)]

use hax_lib::loop_invariant;
use crate::utils::constants::{beta, chall1_bytes, chall2_bytes, chall3_bytes, ell, ell_bytes, ell_hat_bytes, h_v_size, tau_minus_one, x1_bytes};
use crate::utils::constants::{iv_bytes, k_0_pow, k_1_pow, lambda, lambda_plus_iv, lambda_bytes_times_three, lambda_bytes_times_two, tau};
use crate::utils::constants::lambda_bytes;
use crate::utils::libcrux_proxy::DigestProxy;
use crate::utils::types::Pk;

// takes a k and the iv
// and returns a sd of size 128 bits and a commitment of size 256 bits
// this should be okay since we are supposed to use shake128 specified by the paper
pub fn h_0(k: [u8; lambda_bytes], iv: [u8; iv_bytes]) -> ([u8; lambda_bytes], [u8; lambda_bytes_times_two]) {
    let mut input : [u8; lambda_bytes+iv_bytes+1] = [0u8; lambda_bytes+iv_bytes+1];
    input[..lambda_bytes].copy_from_slice(&k);
    input[lambda_bytes..lambda_bytes+iv_bytes].copy_from_slice(&iv);
    input[lambda_bytes+iv_bytes] = 0;

    let output = if lambda == 128 {
        DigestProxy::shake128::<lambda_bytes_times_three>(&input)
    }
    else {
        DigestProxy::shake256::<lambda_bytes_times_three>(&input)
    };

    let sd:  [u8; lambda_bytes] = output[..lambda_bytes].try_into().unwrap();
    let com: [u8; lambda_bytes_times_two] = output[lambda_bytes..lambda_bytes_times_three].try_into().unwrap();
    // return sd and commitment
    (sd, com)
}

pub fn h_1_k0(coms: &[[u8; lambda_bytes_times_two]; k_0_pow]) -> [u8; lambda_bytes_times_two] {
    const SIZE: usize = k_0_pow * 2 * lambda_bytes + 1;
    let mut input = [0u8; SIZE];
    let mut i = 0;
    for j in 0..k_0_pow {
        loop_invariant!(|j: usize| {
            j <= 4096 &&
            i == j * 32
        });
        for k in 0..lambda_bytes_times_two {
            loop_invariant!(|k: usize| {
                k <= 32 &&
                i == j * 32 + k
            });
            input[i] = coms[j][k];
            i += 1;
        }
    }
    input[SIZE - 1] = 0x01;
    if lambda == 128 {
        DigestProxy::shake128::<lambda_bytes_times_two>(&input)
    } else {
        DigestProxy::shake256::<lambda_bytes_times_two>(&input)
    }
}

pub fn h_1_k1(coms: &[[u8; lambda_bytes_times_two]; k_1_pow]) -> [u8; lambda_bytes_times_two] {
    const SIZE: usize = k_1_pow * lambda_bytes_times_two + 1;
    let mut input = [0u8; SIZE];
    let mut i = 0;
    for j in 0..k_1_pow {
        loop_invariant!(|j: usize| {
            j <= 2048 &&
            i == j * 32
        });
        for k in 0..lambda_bytes_times_two {
            loop_invariant!(|k: usize| {
                k <= 32 &&
                i == j * 32 + k
            });
            input[i] = coms[j][k];
            i += 1;
        }
    }
    input[SIZE - 1] = 0x01;
    if lambda == 128 {
        DigestProxy::shake128::<lambda_bytes_times_two>(&input)
    } else {
        DigestProxy::shake256::<lambda_bytes_times_two>(&input)
    }
}

pub fn h_1_for_352(coms: &[u8; tau * lambda_bytes_times_two]) -> [u8; lambda_bytes_times_two] {
    let mut input = [0u8; tau * lambda_bytes_times_two+1];
    input[..tau * lambda_bytes_times_two].copy_from_slice(coms);
    input[tau * lambda_bytes_times_two] = 0x01;
    if lambda == 128 {
        DigestProxy::shake128::<lambda_bytes_times_two>(&input)
    } else {
        DigestProxy::shake256::<lambda_bytes_times_two>(&input)
    }
}

pub fn h_1_for_2304(coms: &[u8; h_v_size]) -> [u8; lambda_bytes_times_two] {
    let mut input = [0u8; h_v_size+1];
    input[..h_v_size].copy_from_slice(coms);
    input[h_v_size] = 0x01; // domain separation byte for H1
    if lambda == 128 {
        DigestProxy::shake128::<lambda_bytes_times_two>(&input)
    } else {
        DigestProxy::shake256::<lambda_bytes_times_two>(&input)
    }
}

#[hax_lib::requires(msg.len() < usize::MAX - 16 * 2 - 1)]
pub fn h_1_for_sign(pk: Pk, msg: &[u8]) -> [u8; lambda_bytes_times_two] {
    let mut input: Vec<u8> = Vec::new();

    // process all beta blocks
    for b in 0..beta {
        let (in_block, out_block) = pk[b];
        // convert bits to bytes for each block
        let mut owf_input = [0u8; 16];
        let mut owf_output = [0u8; 16];
        for i in 0..16 {
            for bit in 0..8 {
                owf_input[i] |= in_block[i * 8 + bit] << bit;
                owf_output[i] |= out_block[i * 8 + bit] << bit;
            }
        }
        input.extend_from_slice(&owf_input);
        input.extend_from_slice(&owf_output);
    }

    input.extend_from_slice(msg);
    input.push(0x01);

    if lambda == 128 {
        DigestProxy::shake128::<lambda_bytes_times_two>(&input)
    } else {
        DigestProxy::shake256::<lambda_bytes_times_two>(&input)
    }
}

pub fn h_3(sk : [u8;lambda_bytes], my : [u8;lambda_bytes_times_two], rho : [u8;lambda_bytes]) -> ([u8;lambda_bytes], [u8;iv_bytes]){
    const size_of_input : usize = lambda_bytes+lambda_bytes_times_two+lambda_bytes+1;

    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+lambda_bytes].copy_from_slice(&sk);
    offset += lambda_bytes;
    input[offset..offset+(lambda_bytes_times_two)].copy_from_slice(&my);
    offset += lambda_bytes_times_two;
    input[offset..offset+lambda_bytes].copy_from_slice(&rho);
    input[size_of_input-1] = 0x03;
    let output = if lambda == 128 {
        DigestProxy::shake128::<lambda_plus_iv>(&input)
    } else {
        DigestProxy::shake256::<lambda_plus_iv>(&input)
    };

    let r: [u8; lambda_bytes]  = output[..lambda_bytes].try_into().unwrap();
    let iv: [u8; iv_bytes] = output[lambda_bytes..].try_into().unwrap();

    (r, iv)
}

pub fn h_2_1(my : [u8;lambda_bytes_times_two], hcom : [u8;lambda_bytes_times_two], cs : &[[u8;ell_hat_bytes]; tau_minus_one], iv : [u8;iv_bytes]) -> [u8;chall1_bytes]{
    const size_of_input : usize = lambda_bytes_times_two+lambda_bytes_times_two+tau_minus_one*ell_hat_bytes+iv_bytes+1;
    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;

    input[offset..offset+lambda_bytes_times_two].copy_from_slice(&my);
    offset += lambda_bytes_times_two;
    input[offset..offset + lambda_bytes_times_two].copy_from_slice(&hcom);
    offset += lambda_bytes_times_two;
    for c in 0..cs.len() {
        loop_invariant!(|c: usize| {
            c <= cs.len() &&
            offset == 32 + 32 + (c*234)
        });
        input[offset..offset + ell_hat_bytes].copy_from_slice(&cs[c]);
        offset += ell_hat_bytes;
    }
    input[offset..offset + iv_bytes].copy_from_slice(&iv);
    offset += iv_bytes;
    input[offset] = 0x02;
    if lambda == 128 {
        DigestProxy::shake128::<chall1_bytes>(&input)
    } else {
        DigestProxy::shake256::<chall1_bytes>(&input)
    }

}

pub fn h_2_2(chall_1 : [u8;chall1_bytes], u_tilde : [u8; x1_bytes], h_v : [u8;lambda_bytes_times_two], d : [u8; ell_bytes]) -> [u8;chall2_bytes]{ // need lambda in bytes
    const size_of_input : usize = chall1_bytes+x1_bytes+lambda_bytes_times_two+ell_bytes+1;

    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+chall1_bytes].copy_from_slice(&chall_1);
    offset += chall1_bytes;
    input[offset..offset + x1_bytes].copy_from_slice(&u_tilde);
    offset += x1_bytes;
    input[offset..offset + lambda_bytes_times_two].copy_from_slice(&h_v);
    offset += lambda_bytes_times_two;
    input[offset..offset + ell_bytes].copy_from_slice(&d);
    offset += ell_bytes;
    input[offset] = 0x02;
    if lambda == 128 {DigestProxy::shake128::<chall2_bytes>(&input)} else {DigestProxy::shake256::<chall2_bytes>(&input)}
}

pub fn h_2_3(chall_2 : [u8;chall2_bytes], a_tilde : [u8;lambda_bytes], b_tilde : [u8;lambda_bytes]) -> [u8;chall3_bytes]{
    const size_of_input : usize = chall2_bytes+lambda_bytes+lambda_bytes+1;
    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+chall2_bytes].copy_from_slice(&chall_2);
    offset += chall2_bytes;
    input[offset..offset+lambda_bytes].copy_from_slice(&a_tilde);
    offset += lambda_bytes;
    input[offset..offset+lambda_bytes].copy_from_slice(&b_tilde);
    offset += lambda_bytes;
    input[offset] = 0x02;

    if lambda == 128 {DigestProxy::shake128::<chall3_bytes>(&input)} else {DigestProxy::shake256::<chall3_bytes>(&input)}
}


pub fn bits_to_bytes_for_d(bits: &[u8; ell]) -> [u8; ell_bytes] {
    let mut bytes = [0u8; ell_bytes];
    for i in 0..ell_bytes {
        for bit in 0..8 {
            bytes[i] |= bits[i * 8 + bit] << bit;
        }
    }
    bytes
}
