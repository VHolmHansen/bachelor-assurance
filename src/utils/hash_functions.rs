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

pub fn h_1(coms: Vec<[u8; 32]>) -> [u8; 56] {
    let concat_coms: Vec<u8> = coms.iter().flat_map(|c| c.to_vec()).collect();
    let mut input: Vec<u8> = vec![0u8; concat_coms.len() + 16];
    digest::shake128::<56>(&mut input)
}