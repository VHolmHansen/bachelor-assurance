use hax_lib::loop_invariant;
use crate::utils::constants::{ell_hat, ell_plus_lambda, lambda_bytes, num_chunks_lambda, x0_padded_64_size, x0_padded_lambda_size, x1_bytes};
use crate::utils::constants::{chall1_bytes, x0_bytes};
use crate::utils::types::sized_array_for_q_v;
use crate::utils::constants::{ell, k_0, k_1, LAMBDA, tau, tau_0, ell_hat_bytes, chall3_bytes};
use crate::utils::galois_field::{gf128_mul, gf64_add, gf64_mul, gf_lambda_mul};
use crate::utils::helper_methods_cstrnts::bits_to_byte;
use crate::utils::math::xor_arrays;
use crate::utils::types::State;

// funktioner der bruges til at omdanne vores V og u, i sign til bits, skal nok slettes senere efter refactor
// vi lavede aldrig refactor 
pub fn vole_to_row_major(big_v: [sized_array_for_q_v;tau]) -> [[u8; LAMBDA]; ell + LAMBDA] {
    let mut v_rows: [[u8; LAMBDA]; ell + LAMBDA] = [[0u8; LAMBDA]; ell + LAMBDA];
    // flatten all columns across tau instances
    // big_v[0] has k_0 columns, big_v[1..tau_0] have k_0 columns
    // big_v[tau_0..tau] have k_1 columns
    let mut col = 0;
    for i in 0..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            // big_v[i][j] is one column of l_hat bits packed into 234 bytes
            for row in 0..(ell + LAMBDA) {
                let byte_idx = row >> 3;
                let bit_idx  = row % 8;
                let val = (big_v[i].get(j)[byte_idx] >> bit_idx) & 1;
                v_rows[row][col] = val; // [j][byte_idx]
            }
            col += 1;
        }
    }
    // col should equal lambda = 128 here
    assert_eq!(col, LAMBDA, "Column count mismatch");
    v_rows
}


pub fn u_to_1728_bits(u: &[u8; ell_hat_bytes]) -> [u8; ell_plus_lambda] {
    let mut bits = [0u8; ell_hat];  // ell_hat = ell + 2*lambda + B (all bits)
    let mut idx = 0;
    for b in 0..u.len() {
        let byte = u[b];
        for i in 0..8 {
            bits[idx] = (byte >> i) & 1;
            idx += 1;
        }
    }
    bits[0..ell_plus_lambda].try_into().unwrap()
}


pub fn expand_bits_56(input: [u8; 56]) -> [u8; 448] {
    let mut output = [0u8; 448];
    for (i, byte) in input.iter().enumerate() {
        for bit in 0..8 {
            // extract each bit, MSB first
            output[i * 8 + bit] = (byte >> (7 - bit)) & 1;
        }
    }
    output
}



pub fn chall3_to_bits(chall_3: &[u8;chall3_bytes]) -> [u8; LAMBDA] {
    let mut bits = [0u8; LAMBDA];
    let mut idx = 0;
    for &byte in chall_3 {
        for i in 0..8 {
            bits[idx] = (byte >> i) & 1;
            idx += 1;
        }
    }
    bits
}

// turn pk and sk into states:
pub fn bits_to_state(text: &[u8; 128]) -> State {
    let mut state = [[0u8; 4]; 4];
    for (i, chunk) in text.chunks(8).enumerate() {
        let byte = bits_to_byte(chunk);
        let col = i >> 2;
        let row = i % 4;
        state[col][row] = byte;  // ← swap col and row here
    }
    state
}

// Implements the VOLEHash function from Section 4.2.3 of the FAEST spec (Figure 4.4).
// Takes a seed sd, a bit string x0 of length ell+lambda bits, and a masking value x1
// of length lambda+B bits, and compresses them into a single output of length lambda+B bits.
// vole hash function: den bruger som udgangspunkt tobits og tofield, men i specificationen forklarer de at man godt kan skip det, på baggrund af ens repræsentation af binary fields
pub fn vole_hash(sd: &[u8; chall1_bytes], x0: &[u8; x0_bytes], x1: &[u8; x1_bytes]) -> [u8; x1_bytes] {
    // splits up the seed value, instead of using to field, we just have them in the right field
    let r0: [u8; lambda_bytes] = sd[0..lambda_bytes].try_into().unwrap();
    let r1: [u8; lambda_bytes] = sd[lambda_bytes..2*lambda_bytes].try_into().unwrap();
    let r2: [u8; lambda_bytes] = sd[2*lambda_bytes..3*lambda_bytes].try_into().unwrap();
    let r3: [u8; lambda_bytes] = sd[3*lambda_bytes..4*lambda_bytes].try_into().unwrap();
    let s:  [u8; lambda_bytes] = sd[4*lambda_bytes..5*lambda_bytes].try_into().unwrap();
    let t:  [u8; 8]            = sd[5*lambda_bytes..chall1_bytes].try_into().unwrap();
    let mut x0_padded_lambda = [0u8; x0_padded_lambda_size];
    x0_padded_lambda[..x0_bytes].copy_from_slice(x0); // corresponds to y_hat
    let mut x0_padded_64 = [0u8; x0_padded_64_size]; // corresponds to y_overline
    x0_padded_64[..x0_bytes].copy_from_slice(x0);
    // we do the calculation
    let mut h0 = [0u8; lambda_bytes];
    for i in 0..num_chunks_lambda { // h_0 calc
        let chunk: [u8; lambda_bytes] = x0_padded_lambda[i*lambda_bytes..(i+1)*lambda_bytes].try_into().unwrap();
        h0 = xor_arrays(&gf_lambda_mul(&h0, &s), &chunk);
    }
    let mut h1 = [0u8; 8];
    let total_64_chunks = num_chunks_lambda * lambda_bytes / 8;
    for i in 0..total_64_chunks { // h_1 calc
        let chunk: [u8; 8] = x0_padded_lambda[i*8..(i+1)*8].try_into().unwrap();
        h1 = gf64_add(&gf64_mul(&h1, &t), &chunk);
    }
    let mut h1_prime = [0u8; lambda_bytes];
    h1_prime[0..8].copy_from_slice(&h1); // h_1_mark calc
    let h2 = xor_arrays(&gf_lambda_mul(&r0, &h0), &gf_lambda_mul(&r1, &h1_prime)); // h2 calc
    let h3 = xor_arrays(&gf_lambda_mul(&r2, &h0), &gf_lambda_mul(&r3, &h1_prime)); // h3 calc
    // moving h into the right field
    let mut h = [0u8; x1_bytes];
    h[0..lambda_bytes].copy_from_slice(&h2);
    h[lambda_bytes..x1_bytes].copy_from_slice(&h3[0..x1_bytes-lambda_bytes]);
    // xoring with x1
    for i in 0..x1_bytes {
        h[i] ^= x1[i];
    }
    // returning h
    h
}