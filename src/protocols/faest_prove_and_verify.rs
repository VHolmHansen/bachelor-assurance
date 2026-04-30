#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::protocols::faest_key_enc_cstrnts::{faest_aes_enc_cstrnts_prover, faest_aes_enc_cstrnts_verifier};
use crate::protocols::faest_key_exp_cstrnts::{faest_aes_exp_cstrnts_qDelta, faest_aes_exp_cstrnts_wv};
use crate::utils::constants::{ell_bit_size, l_ke, lambda, l_enc, S_ke};
use crate::utils::galois_field::gf128_mul;
use crate::utils::helper_methods_prove_verify::{to_field, zk_hash};
use crate::utils::math::{field_pow, xor_arrays};

pub fn faest_aes_prove(
            w : [u8; ell_bit_size],
            u : [u8; ell_bit_size+lambda],
            V : [[u8; lambda]; ell_bit_size+lambda],
            pk : ([u8;lambda], [u8;lambda]),
            chall : [u8;3*lambda+64]) -> ([u8;16],[u8;16]
)
{

    // nyt v, lidt rodet, basically V|_i betyder kolonne i, og vi skal tage og sige to_field for kolonne i
    let v: Vec<[u8;16]> = (0..ell_bit_size+lambda)
        .map(|row| {
            to_field(&V[row], lambda)[0]
        })
        .collect();


    let in_of_in_and_out = pk.0;
    let out_of_in_and_out = pk.1;

    let w_tilde_exp = &w[0..l_ke];
    let v_tilde_exp  = &v[0..l_ke];


    let (a_tilde_0_exp, a_tilde_1_exp, k, v_k) : ([[u8;16];S_ke], [[u8;16];S_ke], [u8;1408],[[u8;16];1408]) = faest_aes_exp_cstrnts_wv(w_tilde_exp.to_vec(), v_tilde_exp.to_vec(), false);


    let w_tilde_enc = &w[l_ke..(l_ke+l_enc)];
    // forsøger at gøre den her til den specifikke størrelse, det er noget vi skla kigge på senere
    let v_tilde_enc: [[u8;16]; l_enc] = v[l_ke..(l_ke+l_enc)]
        .try_into()
        .unwrap();

    let (a_tilde_0_enc, a_tilde_1_enc) = faest_aes_enc_cstrnts_prover(
        1, in_of_in_and_out.to_vec(),
        out_of_in_and_out.to_vec(),
        w_tilde_enc.to_vec(),
        v_tilde_enc,
        k,
        v_k,
        false
    );


    let a_0: [[u8;16]; 200] = a_tilde_0_exp.to_vec()
        .into_iter()
        .chain(a_tilde_0_enc.to_vec().into_iter())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let a_1: [[u8;16]; 200] = a_tilde_1_exp.to_vec()
        .into_iter()
        .chain(a_tilde_1_enc.to_vec().into_iter())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut new_u : [[u8;16];lambda] = [[0;16];lambda];
    for i in 0..lambda {
        new_u[i] = to_field(&[u[ell_bit_size+i]], 1)[0];
    }
    

    let mut alpha = [0u8; 16];
    alpha[0] = 0x02; // bit 1 set = x^1

    let mut u_star = [0u8; 16];
    for i in 0..lambda {
        let alpha_pow = field_pow(&alpha, i);
        let term = gf128_mul(&new_u[i], &alpha_pow);
        u_star = xor_arrays(&u_star, &term);
    }

    // v*
    let mut v_star = [0u8; 16];
    for i in 0..lambda {
        let alpha_pow = field_pow(&alpha, i);
        let term = gf128_mul(&v[ell_bit_size + i], &alpha_pow);
        v_star = xor_arrays(&v_star, &term);
    }


    let alpha_tilde = zk_hash(&chall, &a_1, &u_star);
    let beta_tilde = zk_hash(&chall, &a_0, &v_star);
    

    (alpha_tilde, beta_tilde)
}

pub fn faest_aes_verify(d : [u8; ell_bit_size], Q : [[u8; lambda]; ell_bit_size+lambda], chall_2 : [u8; 3*lambda+64], chall_3 : [u8;lambda], a_tilde : [u8;16],pk : ([u8;lambda], [u8;lambda])) -> [u8;16]
{
    let delta = to_field(&chall_3, lambda)[0];
    let in_of_in_and_out = pk.0;
    let out_of_in_and_out = pk.1;

    // linje 5
    // Det her skal forstås som en reconstruction af det Q (en matrix), som er blevet sendt rundt på et tidligere tidspunkt
    let mut Q_mut = Q.clone();

    
    
    for row in 0..ell_bit_size {
        if d[row] == 1 {
            for col in 0..lambda {
                Q_mut[row][col] ^= chall_3[col]; // chall_3[col] is already a bit (0 or 1)
            }
        }
    }
    

    // After correction - row 0 should now equal v[0] from sign since d[0]=w[0] XOR u[0]
    let q: Vec<[u8;16]> = (0..ell_bit_size+lambda)
        .map(|row| {
            to_field(&Q_mut[row], lambda)[0]
        })
        .collect();


    // til 13

    let (b1, q_k) = faest_aes_exp_cstrnts_qDelta(delta, q[0..l_ke].to_vec(), true);


    let q_for_enc_cstrnts: [[u8;16]; l_enc] = q[l_ke..(l_ke+l_enc)]
        .try_into()
        .unwrap();

    let b2 = faest_aes_enc_cstrnts_verifier(
            128, &in_of_in_and_out.to_vec(),
            &out_of_in_and_out.to_vec(),
            &q_for_enc_cstrnts,
            &q_k,
            delta,
            true
            );


    let b: [[u8;16]; 200] = b1.to_vec()
        .into_iter()
        .chain(b2.to_vec().into_iter())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();


    // getting q_star like with u_star and v_star
    let mut alpha = [0u8; 16];
    alpha[0] = 0x02;
    let mut q_star = [0u8; 16];
    for i in 0..lambda {
        let alpha_pow = field_pow(&alpha, i);
        let term = gf128_mul(&q[ell_bit_size + i], &alpha_pow);
        q_star = xor_arrays(&q_star, &term);
    }


    let q_tilde = zk_hash(&chall_2, &b, &q_star);
    let a_tilde_times_delta = gf128_mul(&a_tilde, &delta);
    let q_tilde_minus_a_tilde_times_delta = xor_arrays(&q_tilde, &a_tilde_times_delta);


 


    q_tilde_minus_a_tilde_times_delta
}