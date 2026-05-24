use crate::utils::hash_functions::bits_to_bytes_for_d;
use crate::utils::types::{sized_array_for_coms, sized_array_for_cop, sized_array_for_q_v, State, Pk, PkBlock};
use crate::utils::vector_commit::{vec_open_k0, vec_open_k1};
use crate::protocols::faest_aes_extended_witness::faest_aes_extend_witness;
use crate::protocols::faest_prove_and_verify::faest_aes_prove;
use crate::protocols::fs_vole::{chall_dec_k0, chall_dec_k1, FAEST_VOLE_commit};
use crate::utils::constants::{ell, k_0, k_1, LAMBDA, lambda_bytes, not_deterministic_test, tau, tau_0, tau_1, tau_minus_one, ell_hat_bytes, x1_bytes, iv_bytes, chall1_bytes, x0_bytes, h_v_size, ell_plus_lambda, chall2_bytes, chall3_bytes, ell_hat, ell_bytes};
use crate::utils::hash_functions::{h_1_for_2304, h_1_for_sign, h_2_1, h_2_2, h_2_3, h_3};
use crate::utils::helper_methods_for_sign::{bits_to_state, u_to_1728_bits, vole_hash, vole_to_row_major};
use crate::utils::libcrux_proxy::{DigestProxy, RandGenProxy};

// function for generating a signature, based on a message, and the secret key public key pair for the zk proof
pub fn faest_sign(msg : &[u8], sk : &[u8;lambda_bytes], pk : &Pk) -> ([[u8; ell_hat_bytes]; tau_minus_one], [u8; x1_bytes], [u8; ell], [u8; lambda_bytes], [(sized_array_for_cop, [u8; 2*lambda_bytes]); tau], [u8; chall3_bytes], [u8; iv_bytes]) {
    // generating a random value
    let mut rng = RandGenProxy::get_rand_gen_sha256();
    // generating my (random value/first challenge) based on the public key and message
    let my : [u8;2*lambda_bytes]= h_1_for_sign(*pk, msg);
    // random value rho, for test it is activally 42, since that fits with the test vectors, but for any real world impl then not_deterministic_test flag should be true
    let mut rho: [u8; lambda_bytes] = [0x42; lambda_bytes];
    if not_deterministic_test {rng.fill_bytes(&mut rho);}
    // greating r and iv, to be used for vole_commit, based on the priveous tape
    let (r, iv) : ([u8;lambda_bytes], [u8;iv_bytes])= h_3(*sk, my, rho);
    // getting the hash, decoms, correction values, u0 and the vole tags
    let (h_com, decoms, c_bytes, u_bytes, v_bytes) : ([u8; 2*lambda_bytes], [([u8;lambda_bytes], [u8;iv_bytes], sized_array_for_coms); tau], [[u8;ell_hat_bytes]; tau_minus_one], [u8; ell_hat_bytes], [sized_array_for_q_v;tau])= FAEST_VOLE_commit(r, iv);
    // first challenge based on the priveous tape
    let chall_1 : [u8;chall1_bytes] = h_2_1(my, h_com, &c_bytes, iv);
    // getting u_tilde
    let u_x_0 : &[u8;x0_bytes] = &u_bytes[0..x0_bytes].try_into().unwrap();
    let u_x_1 : &[u8;x1_bytes]= &u_bytes[x0_bytes..ell_hat_bytes].try_into().unwrap();
    // u_tilde will be part of the signature, it is part of a consistency check
    // the verifier will recompute it from Q to check
    let u_tilde: [u8;x1_bytes] = vole_hash(&chall_1, u_x_0, u_x_1);
    // compute v_tilde for each column of the VOLE tag matrix V.
    // the tag matrix V has tau block-columns, each block i having k_b columns of ell_hat bits.
    // for each column, we apply VOLEHash with chall1 to compress it into lambda+B bits.
    // the verifier will recompute these hashes from its VOLE keys Q and check consistency
    let mut v_tilde : [[u8; x1_bytes]; LAMBDA] = [[0u8; x1_bytes]; LAMBDA];       // len : ( tau_0 * k_0 + tau_1*k_1 )
    let mut index : usize = 0;
    for i in 0..tau {
        // the same k_b check used in the fs_vole functions
        let k_b : usize = if i < tau_0 { k_0 } else { k_1 };
        for j in 0..k_b {
            let col : &[u8;ell_hat_bytes] = v_bytes[i].get(j); // [u8; 234]
            let x0_col : &[u8;x0_bytes] = &col[0..x0_bytes].try_into().unwrap();
            let x1_col : &[u8;x1_bytes] = &col[x0_bytes..ell_hat_bytes].try_into().unwrap();
            let col_hash : [u8;x1_bytes] = vole_hash(&chall_1, x0_col, x1_col);
            v_tilde[index] = col_hash;
            index += 1;
        }
    }
    // flatten v_tilde into a single byte array and hash it into h_V using H1.
    // sending h_V instead of v_tilde directly saves communication, since v_tilde is large
    // (lambda columns of lambda+B bits each). the verifier recomputes h_V from its Q keys
    // and checks it against the value derived from chall1
    let mut h_v_val : [u8;h_v_size] = [0u8; h_v_size];
    for i in 0..(tau_0*k_0+tau_1*k_1) { // is equivalent to lambda
        for j in 0..x1_bytes {
            h_v_val[i * x1_bytes + j] = v_tilde[i][j];
        }
    }
    let h_v : [u8;2*lambda_bytes] = h_1_for_2304(&h_v_val);
    // u_bytes and v_bytes are repacked into bits, since that is how we use them later
    let u_bits: &[u8;ell_plus_lambda] = &u_to_1728_bits(&u_bytes);
    let v_rows: &[[u8; LAMBDA]; ell_plus_lambda] = &vole_to_row_major(v_bytes);
    // calculating extended_witness based on the secret key and public key
    let extended_witness : [u8;ell] = faest_aes_extend_witness(*sk, *pk);
    // masking the extended witness with u, this value d is later to be used by the verifer
    let mut d: [u8; ell] = [0; ell];
    for i in 0..ell {
        d[i] = extended_witness[i] ^ u_bits[i];
    }
    // turning d into bytes
    let d_bytes = bits_to_bytes_for_d(&d);
    // next challenge generation based on the priveous tape
    let chall_2 : [u8;chall2_bytes] = h_2_2(chall_1, u_tilde.clone(), h_v, d_bytes);
    // getting a_tilde and b_tilde from the zk_prove function
    let (a_tilde , b_tilde) : ([u8;lambda_bytes],[u8;lambda_bytes]) = faest_aes_prove(extended_witness.try_into().unwrap(), u_bits, v_rows, *pk, chall_2);
    // getting chall_3 which is supposed to be Delta, from the priveous tape
    let chall_3 : [u8;chall3_bytes] = h_2_3(chall_2, a_tilde, b_tilde);
    // pdecoms, lastly calling vec_open with the Delta and the decoms from commit
    let mut pdecoms : [(sized_array_for_cop, [u8; 2*lambda_bytes]);tau] = [(sized_array_for_cop::sized_array_1([[0u8;lambda_bytes];k_0]),[0u8;2*lambda_bytes]);tau];
    for i in 0..tau {
        let pdecom = if i < tau_0 {
            let s_i : [u8;k_0] = chall_dec_k0(chall_3, i);
            vec_open_k0(&decoms[i], &s_i)
        } else {
            let s_i : [u8;k_1] = chall_dec_k1(chall_3, i);
            vec_open_k1(&decoms[i], &s_i)
        };
        pdecoms[i] = pdecom;
    }
    // the signature consist of correction bytes, u_tilde, d, a_tilde, pdecoms for reconstruct, Delta to compare with and the iv
    let signature = (c_bytes, u_tilde, d, a_tilde, pdecoms, chall_3, iv);
    signature

}



