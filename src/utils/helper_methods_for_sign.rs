use crate::utils::types::sized_array_for_q_v;
use crate::utils::constants::{big_b, ell, ell_bit_size, k_0, k_1, lambda, tau, tau_0};
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
                let byte_idx = row / 8;
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
    for &byte in u.iter() {
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

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = vec![];
    for &byte in bytes {
        for i in 0..8 {
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

pub fn chall3_to_bits(chall_3: &[u8;16]) -> [u8;128] {
    let bits = bytes_to_bits(chall_3);
    bits.try_into().unwrap()
}

// turn pk and sk into states:
pub fn bits_to_state(text: &[u8; 128]) -> State {
    let mut state = [[0u8; 4]; 4];
    for (i, chunk) in text.chunks(8).enumerate() {
        let byte = bits_to_byte(chunk);
        let col = i / 4;
        let row = i % 4;
        state[col][row] = byte;  // ← swap col and row here
    }
    state
}

// vole hash function:
pub fn vole_hash(sd: &[u8], x0: &[u8], x1: &[u8]) -> [u8;18] {
    // sd is 5*lambda + 64 bits = 5*16 + 8 = 88 bytes
    // parse sd into r0,r1,r2,r3 (lambda bits each) and s (lambda bits) and t (64 bits)
    let r0: [u8;16] = sd[0..16].try_into().unwrap();
    let r1: [u8;16] = sd[16..32].try_into().unwrap();
    let r2: [u8;16] = sd[32..48].try_into().unwrap();
    let r3: [u8;16] = sd[48..64].try_into().unwrap();
    let s:  [u8;16] = sd[64..80].try_into().unwrap();
    let t:  [u8; 8] = sd[80..88].try_into().unwrap();

    // pad x0 to multiple of lambda bits
    let l_prime = lambda * ((x0.len() + lambda - 1) / lambda);
    let mut x0_padded = x0.to_vec();
    x0_padded.resize(l_prime / 8, 0u8);

    // compute h0 as polynomial hash in F2^lambda
    // parse x0_padded as lambda-bit field elements
    let num_chunks_lambda = l_prime / lambda;
    let mut h0 = [0u8; 16];
    for i in 0..num_chunks_lambda {
        let chunk: [u8;16] = x0_padded[i*16..(i+1)*16].try_into().unwrap();
        // h0 = h0 * s + chunk
        h0 = xor_arrays(&gf128_mul(&h0, &s), &chunk);
    }

    // compute h1 as polynomial hash in F2^64
    let num_chunks_64 = l_prime / 64;
    let mut h1 = [0u8; 8];
    for i in 0..num_chunks_64 {
        let chunk: [u8;8] = x0_padded[i*8..(i+1)*8].try_into().unwrap();
        // h1 = h1 * t + chunk  (in F2^64)
        h1 = gf64_add(&gf64_mul(&h1, &t), &chunk);
    }

    // pad h1 to lambda bits
    let mut h1_prime = [0u8; 16];
    h1_prime[0..8].copy_from_slice(&h1);

    // h2 = r0*h0 + r1*h1'
    // h3 = r2*h0 + r3*h1'
    let h2 = xor_arrays(&gf128_mul(&r0, &h0), &gf128_mul(&r1, &h1_prime));
    let h3 = xor_arrays(&gf128_mul(&r2, &h0), &gf128_mul(&r3, &h1_prime));

    // take first lambda + B bits of (h2 | h3) and XOR with x1
    let mut h = [0u8; (lambda + big_b) / 8]; // (128 + 16) / 8 = 18 bytes
    h[0..16].copy_from_slice(&h2);
    h[16..18].copy_from_slice(&h3[0..2]); // first B=16 bits of h3

    // XOR with x1
    for i in 0..h.len() {
        h[i] ^= x1[i];
    }

    h
}