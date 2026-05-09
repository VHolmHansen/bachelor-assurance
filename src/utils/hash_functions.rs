#![allow(non_upper_case_globals)]
use crate::utils::libcrux_proxy::DigestProxy;

// takes a k and the iv
// and returns a sd of size 128 bits and a commitment of size 256 bits
// this should be okay since we are supposed to use shake128 specified by the paper
pub fn h_0(k: [u8; 16], iv: [u8; 16]) -> ([u8; 16], [u8; 32]) {
    let mut input : [u8; 33] = [0u8; 33];
    input[..16].copy_from_slice(&k);
    input[16..32].copy_from_slice(&iv);
    input[32] = 0;

    let output = DigestProxy::shake128::<48>(&input);

    let sd:  [u8; 16] = output[..16].try_into().unwrap();
    let com: [u8; 32] = output[16..48].try_into().unwrap();
    // return sd and commitment
    (sd, com)
}

pub fn h_1_k0(coms: &[[u8; 32]; 4096]) -> [u8; 32] {
    const SIZE: usize = (4096 << 5) + 1;
    let mut input = [0u8; SIZE];
    let mut i = 0;
    for j in 0..4096 {
        for k in 0..32 {
            input[i] = coms[j][k];
            i += 1;
        }
    }
    input[SIZE - 1] = 0x01;
    DigestProxy::shake128::<32>(&input)
}

pub fn h_1_k1(coms: &[[u8; 32]; 2048]) -> [u8; 32] {
    const SIZE: usize = (2048 << 5) + 1;
    let mut input = [0u8; SIZE];
    let mut i = 0;
    for j in 0..2048 {
        for k in 0..32 {
            input[i] = coms[j][k];
            i += 1;
        }
    }
    input[SIZE - 1] = 0x01;
    DigestProxy::shake128::<32>(&input)
}

pub fn h_1_for_352(coms: &[u8; 352]) -> [u8; 32] {
    let mut input = [0u8; 353];
    input[..352].copy_from_slice(coms);
    input[352] = 0x01;
    DigestProxy::shake128::<32>(&input)
}

pub fn h_1_for_2304(coms: &[u8; 2304]) -> [u8; 32] {
    let mut input = [0u8; 2305];
    input[..2304].copy_from_slice(coms);
    input[2304] = 0x01; // domain separation byte for H1
    DigestProxy::shake128::<32>(&input)
}

#[hax_lib::requires(msg.len() < usize::MAX - 16 * 2 - 1)]
pub fn h_1_for_sign(pk : ([u8;128],[u8;128]), msg : &[u8]) -> [u8;32]{
    // Concatenate plaintext, ciphertext, and message
    // vi er nok nød til at sætte et upper bound på message size, problemet er nemlig at vi ikke ved hvor stor message er ved compile time, en overvejelse her om vi er nød til at bibeholde vec
    // plaintext
    let mut owf_input = [0u8; 16];
    let mut owf_output = [0u8; 16];

    for i in 0..16 {
        for bit in 0..8 {
            owf_input[i] |= pk.0[i * 8 + bit] << bit;
            owf_output[i] |= pk.1[i * 8 + bit] << bit;
        }
    }
    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(&owf_input);
    input.extend_from_slice(&owf_output);
    input.extend_from_slice(msg);
    input.push(0x01); // domain separation byte for H1

    DigestProxy::shake128::<32>(&input)
}

pub fn h_3(sk : [u8;16], my : [u8;32], rho : [u8;16]) -> ([u8;16], [u8;16]){
    const size_of_input : usize = 16+32+16+1;

    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+16].copy_from_slice(&sk);
    offset += 16;
    input[offset..offset+32].copy_from_slice(&my);
    offset += 32;
    input[offset..offset+16].copy_from_slice(&rho);
    input[size_of_input-1] = 0x03;

    let output = DigestProxy::shake128::<32>(&input);

    let r: [u8; 16]  = output[..16].try_into().unwrap();
    let iv: [u8; 16] = output[16..].try_into().unwrap();

    (r, iv)
}

pub fn h_2_1(my : [u8;32], hcom : [u8;32], cs : &[[u8;234]], iv : [u8;16]) -> [u8;88]{
    const size_of_input : usize = 32+32+10*234+16+1;
    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;



    input[offset..offset+32].copy_from_slice(&my);
    offset += 32;
    input[offset..offset + 32].copy_from_slice(&hcom);
    offset += 32;
    for c in cs {
        input[offset..offset + 234].copy_from_slice(c);
        offset += 234;
    }
    input[offset..offset + 16].copy_from_slice(&iv);
    offset += 16;
    input[offset] = 0x02;

    DigestProxy::shake128::<88>(&input)
}

pub fn h_2_2(chall_1 : [u8;88], u_tilde : [u8; 18], h_v : [u8;32], d : [u8; 200]) -> [u8;56]{ // need lambda in bytes
    const size_of_input : usize = 88+18+32+200+1;

    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+88].copy_from_slice(&chall_1);
    offset += 88;
    input[offset..offset + 18].copy_from_slice(&u_tilde);
    offset += 18;
    input[offset..offset + 32].copy_from_slice(&h_v);
    offset += 32;
    input[offset..offset + 200].copy_from_slice(&d);
    offset += 200;
    input[offset] = 0x02;

    DigestProxy::shake128::<56>(&input)
}

pub fn h_2_3(chall_2 : [u8;56], a_tilde : [u8;16], b_tilde : [u8;16]) -> [u8;16]{
    const size_of_input : usize = 56+16+16+1;
    let mut input: [u8;size_of_input] = [0;size_of_input];
    let mut offset = 0;
    input[offset..offset+56].copy_from_slice(&chall_2);
    offset += 56;
    input[offset..offset+16].copy_from_slice(&a_tilde);
    offset += 16;
    input[offset..offset+16].copy_from_slice(&b_tilde);
    offset += 16;
    input[offset] = 0x02;

    DigestProxy::shake128::<16>(&input)
}


pub fn bits_to_bytes_for_d(bits: &[u8; 1600]) -> [u8; 200] {
    let mut bytes = [0u8; 200];
    for i in 0..200 {
        for bit in 0..8 {
            bytes[i] |= bits[i * 8 + bit] << bit;
        }
    }
    bytes
}
