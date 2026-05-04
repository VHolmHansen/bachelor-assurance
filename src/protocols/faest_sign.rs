use rand::RngExt;
use rand::rngs::ThreadRng;
use crate::utils::types::{sized_array_for_coms, sized_array_for_cop, sized_array_for_q_v, State};
use crate::utils::vector_commit::{vec_open_k0, vec_open_k1};
use crate::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
use crate::protocols::faest_prove_and_verify::faest_aes_prove;
use crate::utils::types::{ret_value, sized_array_16};
use crate::protocols::fs_vole::{chall_dec, chall_dec_k0, chall_dec_k1, FAEST_VOLE_commit};
use crate::utils::constants::{ell, ell_bit_size, k_0, k_1, lambda, tau, tau_0, tau_1};
use crate::utils::hash_functions::{h_1_for_non_specific_size, h_1_for_sign, h_2_1, h_2_2, h_2_3, h_3};
use crate::utils::helper_methods_cstrnts::{bits_to_byte, byte_to_bits};
use crate::utils::helper_methods_for_sign::{bits_to_state, expand_bits_56, u_to_1728_bits, vole_hash, vole_to_row_major};
use crate::utils::math::transform_byte_array_to_state;


pub fn faest_sign(msg : &[u8], sk : &[u8;16], pk : &([u8;lambda], [u8;lambda])) -> ([[u8; 234]; 11], [u8; 18], [u8; 1600], [u8; 16], [(sized_array_for_cop, [u8; 32]); 11], [u8; 16], [u8; 16]) {
    let mut rng : ThreadRng = rand::rng();

    let my : [u8;32]= h_1_for_sign(pk.clone(), msg);
    let rho: [u8; 16] = rng.random();

    let (r, iv) : ([u8;16], [u8;16])= h_3(*sk, my, rho);
    let vec_start = std::time::Instant::now();
    let (h_com, decoms, c_bytes, u_bytes, v_bytes) : ([u8; 56], [([u8;16], [u8;16], sized_array_for_coms); tau], [[u8;234]; tau], [u8; 234], [sized_array_for_q_v;tau])= FAEST_VOLE_commit(r, iv);
    println!("vec_commit took: {:?}", vec_start.elapsed());
    let chall_1 : [u8;88] = h_2_1(my, h_com, &c_bytes, iv);




    // få u tilde
    let u_x_0 : &[u8] = &u_bytes[0..216];
    let u_x_1 : &[u8]= &u_bytes[216..234];
    let u_tilde: [u8;18] = vole_hash(&chall_1, u_x_0, u_x_1);

    // få v_tilde
    let mut v_tilde : [[u8; 18];tau_0*k_0+tau_1*k_1] = [[0u8; 18]; tau_0*k_0+tau_1*k_1];       // len : ( tau_0 * k_0 + tau_1*k_1 )
    let mut index : usize = 0;
    for i in 0..tau {
        let k_b : usize = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            let col : &[u8;234] = v_bytes[i].get(j); // [u8; 234]
            let x0_col : &[u8] = &col[0..216];
            let x1_col : &[u8] = &col[216..234];
            let col_hash : [u8;18] = vole_hash(&chall_1, x0_col, x1_col);
            let col_hash_arr: [u8; 18] = col_hash;
            v_tilde[index] = col_hash_arr;
            index += 1;
        }
    }

    // man skla have hashed h_V

    let mut h_v_val : [u8;2304] = [0u8; 18 * (tau_0*k_0+tau_1*k_1)];
    for i in 0..(tau_0*k_0+tau_1*k_1) {
        for j in 0..(18) {
            h_v_val[i * 18 + j] = v_tilde[i][j];
        }
    }

    let h_v : [u8;56] = h_1_for_non_specific_size(&h_v_val);

    // u_bytes og v_bytes skal pakkes om til bits, siden det er sådan de bliver brugt senere
    let u_bits: &[u8;1728] = &u_to_1728_bits(&u_bytes);


    let v_rows: &[[u8; lambda];ell_bit_size+lambda] = &vole_to_row_major(v_bytes);

    // plaintext til state
    let pt_state : State = bits_to_state(&pk.0);
    let ct_state : State = bits_to_state(&pk.1);

    let extend_start = std::time::Instant::now();
    // extended_witness, de siger i pseudo koden, at den kun skal have in, men det kan altså ikke passe
    let extended_witness : [u8;1600] = faest_aes_extend_witness(*sk, (pt_state, ct_state));
    println!("extend_witness took: {:?}", extend_start.elapsed());


    let mut d: [u8;ell_bit_size] = [0; ell_bit_size];
    for i in 0..ell_bit_size {
        d[i] = extended_witness[i] ^ u_bits[i];
    }

    let chall_2 : [u8;56] = h_2_2(chall_1, u_tilde.clone(), h_v, d.clone());

    let prove_start = std::time::Instant::now();
    let (a_tilde , b_tilde) : ([u8;16],[u8;16]) = faest_aes_prove(extended_witness.try_into().unwrap(), u_bits, v_rows, (pk.0.try_into().unwrap(),pk.1.try_into().unwrap()), expand_bits_56(chall_2));
    println!("prove took: {:?}", prove_start.elapsed());

    let chall_3 : [u8;16] = h_2_3(chall_2, a_tilde, b_tilde);

    let open_start = std::time::Instant::now();
    // pdecoms
    let mut pdecoms : [(sized_array_for_cop, [u8; 32]);tau] = [(sized_array_for_cop::sized_array_1([[0u8;16];k_0]),[0u8;32]);tau];
    for i in 0..tau {
        let pdecom = if i < tau_0 {
            let s_i : [u8;12] = chall_dec_k0(chall_3, i);
            vec_open_k0(&decoms[i], &s_i, s_i.len() as i128)
        } else {
            let s_i : [u8;11] = chall_dec_k1(chall_3, i);
            vec_open_k1(&decoms[i], &s_i, s_i.len() as i128)
        };

        pdecoms[i] = pdecom;
    }
    println!("open took: {:?}", open_start.elapsed());
    let signature = (c_bytes, u_tilde, d, a_tilde, pdecoms, chall_3, iv);
    signature

}



