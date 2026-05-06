#![allow(non_upper_case_globals)]
use libcrux::digest;
use crate::utils::constants::lambda;
use crate::utils::libcrux_proxy::DigestProxy;

// takes a k and the iv
// and returns a sd of size 128 bits and a commitment of size 256 bits
// this should be okay since we are supposed to use shake128 specified by the paper
pub fn h_0(k: [u8; 16], iv: [u8; 16]) -> ([u8; 16], [u8; 32]) {
    let mut input : [u8; 32] = [0u8; 32];
    input[..16].copy_from_slice(&k);
    input[16..].copy_from_slice(&iv);

    let sd = DigestProxy::shake128::<16>(&input);
    let com = DigestProxy::shake128::<32>(&input);

    // return sd and commitment
    (sd, com)
}

pub fn h_1_k0(coms: &[[u8; 32];4096]) -> [u8; 56] {
    const size_of_input : usize = 16 + 4096*32;
    let mut input : [u8;size_of_input] = [0u8;size_of_input];
    let mut i = 0;
    for j in 0..4096{
        for k in 0..32 {
            input[i] = coms[j][k];
            i += 1;
        }
    }

    DigestProxy::shake128::<56>(&mut input)
}
pub fn h_1_k1(coms: &[[u8; 32];2048]) -> [u8; 56] {
    const size_of_input : usize = 16 + 2048*32;
    let mut input : [u8;size_of_input] = [0u8;size_of_input];
    let mut i = 0;
    for j in 0..2048{
        for k in 0..32 {
            input[i] = coms[j][k];
            i += 1;
        }
    }

    DigestProxy::shake128::<56>(&mut input)
}
/*
fn array_h_1<const dummy_n: usize>(coms: &[[u8; 32]; dummy_n]) -> [u8; 56] {
    let mut input: [u8; dummy_n * 32 + 16] = [0u8; dummy_n * 32 + 16]
    for i in 0..dummy_n {
        for j in 0..32 {
            input[16 + 32 * i + j] = coms[i][j];
        }

    }
    digest::shake128::<56>(&mut input)
}
*/


pub fn h_1_for_2304(coms: &[u8;2304]) -> [u8; 56] {
    let mut input = *coms;
    DigestProxy::shake128::<56>(&mut input)
}

pub fn h_1_for_616(coms: &[u8;616]) -> [u8; 56] {
    let mut input = *coms;
    DigestProxy::shake128::<56>(&mut input)
}

pub fn h_1_for_sign(pk : ([u8;128],[u8;128]), msg : &[u8]) -> [u8;32]{
    // Concatenate plaintext, ciphertext, and message
    let mut input: Vec<u8> = Vec::with_capacity(16 + pk.0.len() + pk.1.len() + msg.len());      //TODO: vec -> array

    // plaintext
    input.extend_from_slice(&pk.0);
    // ciphertext
    input.extend_from_slice(&pk.1);
    // message
    input.extend_from_slice(msg);
    DigestProxy::shake128::<32>(&mut input)
}

pub fn h_3(sk : [u8;16], my : [u8;32], rho : [u8;16]) -> ([u8;16], [u8;16]){
    const size_of_input : usize = 16+32+16;

    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+16].copy_from_slice(&sk);
    offset += 16;
    input[offset..offset+32].copy_from_slice(&my);
    offset += 32;
    input[offset..offset+16].copy_from_slice(&rho);


    let output = DigestProxy::shake128::<32>(&input);

    let r: [u8; 16]  = output[..16].try_into().unwrap();
    let iv: [u8; 16] = output[16..].try_into().unwrap();

    (r, iv)
}

pub fn h_2_1(my : [u8;32], hcom : [u8;56], cs : &[[u8;234]], iv : [u8;16]) -> [u8;88]{
    const size_of_input : usize = 16+32+56+10*234+16;
    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;

    input[offset..offset+32].copy_from_slice(&my);
    offset += 32;
    input[offset..offset + 56].copy_from_slice(&hcom);
    offset += 56;
    for c in cs {
        input[offset..offset + 234].copy_from_slice(c);
        offset += 234;
    }
    input[offset..offset + 16].copy_from_slice(&iv);

    DigestProxy::shake128::<88>(&input)
}

pub fn h_2_2(chall_1 : [u8;88], u_tilde : [u8; 18], h_v : [u8;56], d : [u8; 1600]) -> [u8;(3*lambda+64)/8]{
    const size_of_input : usize = 88+18+56+1600;

    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+88].copy_from_slice(&chall_1);
    offset += 88;
    input[offset..offset + 18].copy_from_slice(&u_tilde);
    offset += 18;
    input[offset..offset + 56].copy_from_slice(&h_v);
    offset += 56;
    input[offset..offset + 1600].copy_from_slice(&d);

    const ret_size : usize = (3*lambda+64)/8;
    DigestProxy::shake128::<ret_size>(&input)
}

pub fn h_2_3(chall_2 : [u8;56], a_tilde : [u8;16], b_tilde : [u8;16]) -> [u8;16]{
    const size_of_input : usize = 56+16+16;
    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+56].copy_from_slice(&chall_2);
    offset += 56;
    input[offset..offset+16].copy_from_slice(&a_tilde);
    offset += 16;
    input[offset..offset+16].copy_from_slice(&b_tilde);

    DigestProxy::shake128::<16>(&input)
}

