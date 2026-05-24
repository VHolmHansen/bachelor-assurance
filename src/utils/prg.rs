use crate::utils::constants::{iv_bytes, lambda_bytes};
use crate::utils::constants::{ell_hat_bytes, tau, LAMBDA};
use crate::utils::math;
use crate::protocols::aes;

// AES-\lambda in counter mode, is a prg, using a seed k and the iv, where it also takes output
pub fn prg(k: [u8; lambda_bytes], iv: [u8; iv_bytes], output: &mut [u8]) {
    // based on the length of output, we want to find out how many 128 aes blocks are needed, thats why it s +15/16
    let num_blocks = (output.len() + 15) >> 4; // ceiling division
    // converting iv to bits
    let iv_int = u128::from_be_bytes(iv);
    // running key ekspanion on the seed
    let key_ex = aes::key_expansion(k);
    // running ones for each block
    for i in 0..num_blocks {
        // creating counter block, based on the current iteration
        let counter = (iv_int + i as u128).to_be_bytes();
        // converting the counter to state, to be used by encrypt
        let counter_state = math::transform_byte_array_to_state(&counter);
        // Encrypting counter block with the expanded key
        let block = aes::encrypt(counter_state, &key_ex);
        // convert from state to 16 bytes
        let block_arr= math::transform_state_to_array(&block);

        let start = i << 4;

        if i == num_blocks - 1 {
            // only copy the amount of blocks that are left in the output, so not to overflow
            let length_of_output = output.len();
            output[start..].copy_from_slice(&block_arr[..length_of_output - start]);
        } else {
            // copy 16 bytes from block_arr to output
            output[start..start + 16].copy_from_slice(&block_arr);
        }

    }
}
// a wrapper for a specific function
pub fn prg_convert_to_vole(sd: [u8;lambda_bytes], iv: [u8; iv_bytes]) -> [u8; ell_hat_bytes]{
    let mut output = [0u8; ell_hat_bytes];
    prg(sd, iv, &mut output);
    output
}
// a wrapper for a specific function
pub fn prg_vole_commit_r(r: [u8;lambda_bytes], iv: [u8;iv_bytes]) -> [u8; (tau* LAMBDA)/8] {
    let mut output  = [0u8; (tau * LAMBDA) >> 3];
    prg(r, iv, &mut output);
    output
}