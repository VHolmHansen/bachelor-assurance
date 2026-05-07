use crate::utils::types::sized_array_for_q_v;
use crate::utils::constants::{big_b, ell_bit_size, k_0, k_1, lambda, tau, tau_0};
use crate::utils::galois_field::{gf128_mul, gf64_add, gf64_mul};
use crate::utils::helper_methods_cstrnts::bits_to_byte;
use crate::utils::math::xor_arrays;
use crate::utils::types::State;

// funktioner der bruges til at omdanne vores V og u, i sign til bits, skal nok slettes senere efte refactor
pub fn vole_to_row_major(big_v: [sized_array_for_q_v;11]) -> [[u8; lambda];ell_bit_size+lambda] {
    let mut v_rows: [[u8; lambda];ell_bit_size+lambda] = [[0u8; lambda]; ell_bit_size + lambda];

    // flatten all columns across tau instances
    // big_v[0] has k_0 columns, big_v[1..tau_0] have k_0 columns
    // big_v[tau_0..tau] have k_1 columns
    let mut col = 0;
    for i in 0..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            // big_v[i][j] is one column of l_hat bits packed into 234 bytes
            for row in 0..(ell_bit_size+lambda) {
                let byte_idx = row >> 3;
                let bit_idx  = row % 8;
                v_rows[row][col] = (big_v[i].get(j)[byte_idx] >> bit_idx) & 1; // [j][byte_idx]
            }
            col += 1;
        }
    }
    // col should equal lambda = 128 here
    assert_eq!(col, lambda, "Column count mismatch");
    v_rows
}


pub fn u_to_1728_bits(u: &[u8; 234]) -> [u8; 1728] {
    let mut bits = [0u8; 1872];
    let mut idx = 0;
    for b in 0..u.len() {
        let byte = u[b];
        for i in 0..8 {
            bits[idx] = (byte >> i) & 1;
            idx += 1;
        }
    }
    bits[0..1728].try_into().unwrap()
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



pub fn chall3_to_bits(chall_3: &[u8;16]) -> [u8;128] {
    let mut bits = [0u8; 128];
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

// vole hash function: den bruger som udgangspunkt tobits og tofield, men i specificationen forklarer de at man godt kan skip det, på baggrund af ens repræsentation af binary fields
pub fn vole_hash(sd: &[u8], x0: &[u8], x1: &[u8]) -> [u8; 18] {
    // parse sd into r0,r1,r2,r3,s (16 bytes each) and t (8 bytes)
    let r0: [u8; 16] = sd[0..16].try_into().unwrap();
    let r1: [u8; 16] = sd[16..32].try_into().unwrap();
    let r2: [u8; 16] = sd[32..48].try_into().unwrap();
    let r3: [u8; 16] = sd[48..64].try_into().unwrap();
    let s:  [u8; 16] = sd[64..80].try_into().unwrap();
    let t:  [u8;  8] = sd[80..88].try_into().unwrap();


    let lambda_bytes = 16usize; // 128 bits / 8
    let chunk_64 = 8usize;      // 64 bits / 8

    // number of lambda-sized chunks (ceiling division)
    let num_chunks_lambda = (x0.len() + lambda_bytes - 1) / lambda_bytes; // 14

    // number of 64-bit chunks (ceiling division)
    let num_chunks_64 = (x0.len() + chunk_64 - 1) / chunk_64; // 27

    // pad x0 to multiple of lambda_bytes
    let mut x0_padded_lambda = vec![0u8; num_chunks_lambda * lambda_bytes]; // 224 bytes
    x0_padded_lambda[..x0.len()].copy_from_slice(x0);

    // pad x0 to multiple of 8 bytes
    let mut x0_padded_64 = vec![0u8; num_chunks_64 * chunk_64]; // 216 bytes
    x0_padded_64[..x0.len()].copy_from_slice(x0);

    // h0: polynomial hash over F_{2^128} using Horner's method
    let mut h0 = [0u8; 16];
    for i in 0..num_chunks_lambda {
        let chunk: [u8; 16] = x0_padded_lambda[i << 4..(i + 1) << 4].try_into().unwrap();
        h0 = xor_arrays(&gf128_mul(&h0, &s), &chunk);
    }


    // h1: polynomial hash over F_{2^64} using Horner's method
    let mut h1 = [0u8; 8];
    let total_64_chunks = num_chunks_lambda * lambda_bytes / 8; // 28
    for i in 0..total_64_chunks {
        let chunk: [u8; 8] = x0_padded_lambda[i << 3..(i + 1) << 3].try_into().unwrap();
        h1 = gf64_add(&gf64_mul(&h1, &t), &chunk);
    }


    // zero-pad h1 to lambda bytes
    let mut h1_prime = [0u8; 16];
    h1_prime[0..8].copy_from_slice(&h1);

    // matrix multiply:
    // h2 = r0*h0 + r1*h1'
    // h3 = r2*h0 + r3*h1'
    let h2 = xor_arrays(&gf128_mul(&r0, &h0), &gf128_mul(&r1, &h1_prime));
    let h3 = xor_arrays(&gf128_mul(&r2, &h0), &gf128_mul(&r3, &h1_prime));


    // take first lambda+B = 128+16 = 144 bits = 18 bytes
    // = all 16 bytes of h2 + first 2 bytes of h3
    let mut h = [0u8; 18];
    h[0..16].copy_from_slice(&h2);
    h[16..18].copy_from_slice(&h3[0..2]);

    // XOR with x1
    for i in 0..18 {
        h[i] ^= x1[i];
    }

    h
}