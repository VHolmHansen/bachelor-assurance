use libcrux::digest;

// takes a k and the iv
// and returns a sd of size 128 bits and a commitment of size 256 bits
// this should be okay since we are supposed to use shake128 specified by the paper
pub fn h_0(k: [u8; 16], iv: [u8; 16]) -> ([u8; 16], [u8; 32]) {
    let mut input : [u8; 32] = [0u8; 32];
    input[..16].copy_from_slice(&k);
    input[16..].copy_from_slice(&iv);

    // you can apparently specify sizes to this (ask Gustav what he knows)
    let sd = digest::shake128::<16>(&input);
    let com = digest::shake128::<32>(&input);

    // return sd and commitment
    (sd, com)
}

pub fn h_1(coms: &Vec<[u8; 32]>) -> [u8; 56] {
    let concat_coms: Vec<u8> = coms.iter().flat_map(|c| c.to_vec()).collect();
    let mut input: Vec<u8> = vec![0u8; concat_coms.len() + 16];
    input.extend_from_slice(&concat_coms);
    digest::shake128::<56>(&mut input)
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

pub fn h_1_for_non_specific_size(coms: Vec<u8>) -> [u8; 56] {
    let mut input: Vec<u8> = vec![0u8; coms.len() + 16];
    input.extend_from_slice(&coms);
    digest::shake128::<56>(&mut input)
}

/*
fn array_h_1_for_non_specific_size<const dummy_n: usize>(coms: [u8; dummy_n]) -> [u8; 56] {
    let mut input = [0u8; coms.len() + 16]
    for i in 0..dummy_n {
        input[i + 16] = coms[i]
    }
    digest::shake128::<56>(&mut input)
}
*/