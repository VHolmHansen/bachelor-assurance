use rand::RngExt;
use crate::utils::types::{sized_array_for_coms, sized_array_for_cop, sized_array_for_q_v};
use crate::utils::vector_commit::{vec_open_k0, vec_open_k1};
use crate::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
use crate::protocols::faest_prove_and_verify::faest_aes_prove;
use crate::utils::types::{ret_value, sized_array_16, Tree};
use crate::protocols::fs_vole::{chall_dec, FAEST_VOLE_commit};
use crate::utils::constants::{ell, ell_bit_size, k_0, k_1, lambda, tau, tau_0, tau_1};
use crate::utils::hash_functions::{h_1_for_non_specific_size, h_1_for_sign, h_2_1, h_2_2, h_2_3, h_3};
use crate::utils::helper_methods_cstrnts::{bits_to_byte, byte_to_bits};
use crate::utils::helper_methods_for_sign::{bits_to_state, expand_bits_56, u_to_bits, vole_hash, vole_to_row_major};
use crate::utils::math::transform_byte_array_to_state;


pub fn faest_sign(msg : &[u8], sk : &[u8;16], pk : &([u8;lambda], [u8;lambda])) -> ([[u8;234];tau], Vec<u8>, Vec<u8>, [u8; 16], Vec<(sized_array_for_cop, [u8; 32])>, [u8; 16], [u8; 16]) {
    println!("sign start - remaining stack: {:?}", stacker::remaining_stack());
    let mut rng = rand::rng();

    let my : [u8;32]= h_1_for_sign(pk.clone(), msg);
    let rho: [u8; 16] = rng.random();

    let (r, iv) : ([u8;16], [u8;16])= h_3(*sk, my, rho);
    let (h_com, decoms, c_bytes, u_bytes, v_bytes) : ([u8; 56], [([u8;16], [u8;16], sized_array_for_coms); tau], [[u8;234]; tau], [u8; 234], [sized_array_for_q_v;tau])= FAEST_VOLE_commit(r, iv);
    println!("sign after vole_commit - remaining stack: {:?}", stacker::remaining_stack());
    let chall_1 : [u8;88] = h_2_1(my, h_com, &c_bytes, iv);

    // få u tilde
    let u_x_0 = &u_bytes[0..216];
    let u_x_1 = &u_bytes[216..234];
    let u_tilde = vole_hash(&chall_1, u_x_0, u_x_1);

    let inners: Vec<&[[u8; ell]]> = v_bytes.iter().map(|v| match v {
        sized_array_for_q_v::sized_array_1(inner) => inner.as_slice(),
        sized_array_for_q_v::sized_array_2(inner) => inner.as_slice(),
    }).collect();

    // få v_tilde
    let mut v_tilde : [[u8; 18];tau_0*k_0+tau_1*k_1] = [[0u8; 18]; tau_0*k_0+tau_1*k_1];       // len : ( tau_0 * k_0 + tau_1*k_1 )
    let mut index = 0;
    for i in 0..tau {
        let k_b = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            let col = &inners[i][j]; // [u8; 234]
            let x0_col = &col[0..216];
            let x1_col = &col[216..234];
            let col_hash = vole_hash(&chall_1, x0_col, x1_col);
            let col_hash_arr: [u8; 18] = col_hash.try_into().unwrap();
            v_tilde[index] = col_hash_arr;
            index += 1;
        }
    }

    // man skla have hashed h_V

    let mut h_v_val = [0u8; 18 * (tau_0*k_0+tau_1*k_1)];
    for i in 0..(tau_0*k_0+tau_1*k_1) {
        for j in 0..(18) {
            h_v_val[i * 18 + j] = v_tilde[i][j];
        }
    }

    let h_v = h_1_for_non_specific_size(&h_v_val);

    // u_bytes og v_bytes skal pakkes om til bits, siden det er sådan de bliver brugt senere
    let u_bits: Vec<u8> = u_to_bits(&u_bytes);
    let u_bits = u_bits[..ell_bit_size + lambda].to_vec();

    let v_bytes_unwrapped: Vec<Vec<[u8; ell]>> = v_bytes.iter().map(|v| match v {
        sized_array_for_q_v::sized_array_1(inner) => inner.to_vec(),
        sized_array_for_q_v::sized_array_2(inner) => inner.to_vec(),
    }).collect();


    let v_rows: Vec<[u8; lambda]> = vole_to_row_major(&v_bytes_unwrapped);



    // plaintext til state
    let pt_state = bits_to_state(pk.clone().0.to_vec());
    let ct_state = bits_to_state(pk.clone().1.to_vec());

    // extended_witness, de siger i pseudo koden, at den kun skal have in, men det kan altså ikke passe
    let extended_witness = faest_aes_extend_witness(*sk, (pt_state, ct_state));

    let mut d: Vec<u8> = vec![];
    for i in 0..ell_bit_size {
        d.push(extended_witness[i] ^ u_bits[i]);
    }

    let chall_2 : [u8;56] = h_2_2(chall_1, u_tilde.clone(), h_v, d.clone());

    let u_arr: [u8; ell_bit_size + lambda] = u_bits.try_into().unwrap();
    let V_arr: [[u8; lambda]; ell_bit_size + lambda] = v_rows.try_into().unwrap();


    let (a_tilde, b_tilde) = faest_aes_prove(extended_witness.try_into().unwrap(), u_arr, V_arr, (pk.0.try_into().unwrap(),pk.1.try_into().unwrap()), expand_bits_56(chall_2));


    let chall_3 = h_2_3(chall_2, a_tilde, b_tilde);

    // pdecoms
    let mut pdecoms : Vec<(sized_array_for_cop, [u8; 32])> = vec![];
    for i in 0..tau {
        let s_i = chall_dec(chall_3, i);

        let pdecom = if s_i.len() == k_0 {
            vec_open_k0(&decoms[i], s_i.clone(), s_i.len() as i128)
        } else {
            vec_open_k1(&decoms[i], s_i.clone(), s_i.len() as i128)
        };

        pdecoms.push(pdecom);
    }
    let signature = (c_bytes, u_tilde, d, a_tilde, pdecoms, chall_3, iv);
    signature

}



