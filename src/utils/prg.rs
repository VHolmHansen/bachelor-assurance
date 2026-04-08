use libcrux::digest;

use crate::utils::types::{ell};

// should have an extra parameter based on size, but we know size is 2 \lambda, which for us is 256
// this is also a placeholder, there need to be some implementation that uses AES in counter mode
pub fn prg(k: [u8; 16], iv: [u8; 16]) -> ([u8; 32]) {
    let mut input : [u8; 32] = [0u8; 32];
    input[..16].copy_from_slice(&k);
    input[16..].copy_from_slice(&iv);
    digest::shake128::<32>(&input)
}

pub fn prg_convert_to_vole(sd: [u8;16], iv: [u8; 16]) -> [u8; ell]{
    let mut input : [u8; 32] = [0u8; 32];
    input[..16].copy_from_slice(&sd);
    input[16..].copy_from_slice(&iv);
    digest::shake128::<ell>(&mut input)
}