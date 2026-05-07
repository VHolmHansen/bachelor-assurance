use crate::utils::constants::{ell, tau, lambda};
use crate::utils::math;
use crate::protocols::aes;
use crate::utils::libcrux_proxy::DigestProxy;

// should have an extra parameter based on size, but we know size is 2 \lambda, which for us is 256
// this is also a placeholder, there need to be some implementation that uses AES in counter mode
pub fn prg(k: [u8; 16], iv: [u8; 16], output: &mut [u8]) {
    let num_blocks = (output.len() + 15) >> 4; // ceiling division

    let iv_int = u128::from_be_bytes(iv);

    let key_ex = aes::key_expansion(k);

    for i in 0..num_blocks {
        let counter = (iv_int + i as u128).to_be_bytes();
        let counter_state = math::transform_byte_array_to_state(&counter);
        let block = aes::encrypt(counter_state, &key_ex); // your existing function
        let block_arr= math::transform_state_to_array(&block);

        let start = i << 4;

        if i == num_blocks - 1 {
            let length_of_output = output.len();
            output[start..].copy_from_slice(&block_arr[..length_of_output - start]);
        } else {
            output[start..start + 16].copy_from_slice(&block_arr);
        }

        //let start = i * 16;
        //output[start..start + 16].copy_from_slice(&block_arr);
    }
}

pub fn prg_convert_to_vole(sd: [u8;16], iv: [u8; 16]) -> [u8; ell]{
    let mut output = [0u8; ell];
    prg(sd, iv, &mut output);
    output
}

pub fn prg_vole_commit_r(r: [u8;16], iv: [u8;16]) -> [u8; (tau*lambda)/8] {
    let mut output  = [0u8; (tau * lambda) >> 3];
    prg(r, iv, &mut output);
    output
}