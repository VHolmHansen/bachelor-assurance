#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::protocols::faest_key_enc_cstrnts::{faest_aes_enc_cstrnts_prover, faest_aes_enc_cstrnts_verifier};
use crate::protocols::faest_key_exp_cstrnts::{faest_aes_exp_cstrnts_qDelta, faest_aes_exp_cstrnts_wv};
use crate::utils::constants::{ell, l_ke, LAMBDA, l_enc, S_ke, ell_plus_lambda, chall2_bytes, lambda_bytes, key_schedule_bits, s_enc, big_C, beta};
use crate::utils::galois_field::gf_lambda_mul;
use crate::utils::helper_methods_prove_verify::{to_field, zk_hash};
use crate::utils::math::{field_pow, xor_arrays};
use crate::utils::types::Pk;

// this function takes v, u, the extended witness, the public key and a challenge
// it wants to using the constraints values A0 and A1, compute a_tilde and b_tilde
pub fn faest_aes_prove(
    w : [u8; ell],
    u : &[u8; ell_plus_lambda],
    V : &[[u8; LAMBDA]; ell_plus_lambda],
    pk : Pk,
    chall : [u8;chall2_bytes]) -> ([u8;lambda_bytes],[u8;lambda_bytes]
)
{

    // convert each row V[i] of the VOLE tag matrix from a bit string of length lambda
    // into a single F_{2^lambda} element, giving a vector v of ell+lambda field elements.
    // V|_i denotes column i of the tag matrix; ToField maps it into F_{2^lambda}
    let mut v: [[u8;lambda_bytes]; ell + LAMBDA] = [[0u8;lambda_bytes]; ell + LAMBDA];
    for i in 0..ell + LAMBDA {
        v[i] = to_field::<LAMBDA, LAMBDA,1>(&V[i])[0] // k=lambda
    }
    // part of witness and v needed for expand constraints
    let w_tilde_exp: [u8;l_ke] = w[0..l_ke].try_into().unwrap();
    let v_tilde_exp: [[u8;lambda_bytes];l_ke]  = v[0..l_ke].try_into().unwrap();
    // calculating A0, A1 for the expanded key, along with the expanded key k and vole tags v_k
    let (a_tilde_0_exp, a_tilde_1_exp, k, v_k) : ([[u8;lambda_bytes];S_ke], [[u8;lambda_bytes];S_ke], [u8;key_schedule_bits],[[u8;lambda_bytes];key_schedule_bits]) = faest_aes_exp_cstrnts_wv(w_tilde_exp, v_tilde_exp, false);
    // making arrays for a0 and a1 for encryption constraints
    let mut a_tilde_0_enc = [[0u8; lambda_bytes]; big_C - S_ke];
    let mut a_tilde_1_enc = [[0u8; lambda_bytes]; big_C - S_ke];
    for b in 0..beta {
        // extracting part of witness to be used for encryption constraints
        let w_enc_start = l_ke + b * l_enc;
        let w_enc: [u8; l_enc] = w[w_enc_start..w_enc_start + l_enc].try_into().unwrap();
        // extracting part of vole tags needed for encryption constraints
        let v_tilde_enc: [[u8; lambda_bytes]; l_enc] = v[w_enc_start..w_enc_start + l_enc].try_into().unwrap();
        // A0 and A1 for encryption constraints
        let (a0, a1) = faest_aes_enc_cstrnts_prover(
            1, pk[b].0, pk[b].1,
            w_enc, v_tilde_enc, k, v_k, false
        );
        // adding them to the array
        for i in 0..s_enc {
            a_tilde_0_enc[b * s_enc + i] = a0[i];
            a_tilde_1_enc[b * s_enc + i] = a1[i];
        }
    }

    // concatanating the two constraint arrays for both A0 and A1
    let a_0 : [[u8;lambda_bytes];big_C] = concat_arrays(a_tilde_0_exp, a_tilde_0_enc);
    let a_1 : [[u8;lambda_bytes];big_C] = concat_arrays(a_tilde_1_exp, a_tilde_1_enc);
    // compute the zero-knowledge masking value u* from the last lambda elements of u.
    // u* = sum_{i=0}^{lambda-1} u[ell+i] * alpha^i, where alpha = x^1 in F_{2^lambda}.
    // this lifts the lambda scalar bits u[ell], ..., u[ell+lambda-1] into a single
    // F_{2^lambda} element by treating them as polynomial coefficients
    let mut new_u : [[u8;lambda_bytes]; LAMBDA] = [[0;lambda_bytes]; LAMBDA];
    for i in 0..LAMBDA {
        // lift each scalar bit u[ell+i] into F_{2^lambda} via ToField
        new_u[i] = to_field::<1,1,1>(&[u[ell +i]])[0]; // k = 1
    }
    // alpha = x^1 in F_{2^lambda}, the generator used for the polynomial lifting
    let mut alpha : [u8;lambda_bytes] = [0u8;lambda_bytes];
    alpha[0] = 0x02; // bit 1 set = x^1

    let mut u_star : [u8;lambda_bytes] = [0u8;lambda_bytes];
    for i in 0..LAMBDA {
        // accumulate u[ell+i] * alpha^i into u_star
        let alpha_pow : [u8;lambda_bytes] = field_pow(&alpha, i);
        let term : [u8;lambda_bytes] = gf_lambda_mul(&new_u[i], &alpha_pow);
        u_star = xor_arrays(&u_star, &term);
    }

    // compute the zero-knowledge masking value v* from the last lambda elements of v,
    // using the same polynomial lifting as u* but with the VOLE tags v[ell..ell+lambda).
    // v* masks u* in the verifier's VOLE key q*, ensuring zero-knowledge
    let mut v_star : [u8;lambda_bytes] = [0u8;lambda_bytes];
    for i in 0..LAMBDA {
        let alpha_pow : [u8;lambda_bytes] = field_pow(&alpha, i);
        let term : [u8;lambda_bytes] = gf_lambda_mul(&v[ell + i], &alpha_pow);
        v_star = xor_arrays(&v_star, &term);
    }
    // compress the constraint values and masking values using ZKHash with challenge chall.
    // alpha_tilde = ZKHash(chall, A_1 || u*) and beta_tilde = ZKHash(chall, A_0 || v*)
    // these are the two components of the QuickSilver proof sent to the verifier.
    // the ZKHash compresses big_C field elements plus the masking value into a single
    // F_{2^lambda} element, saving communication compared to sending all big_C pairs
    let alpha_tilde : [u8;lambda_bytes] = zk_hash(&chall, &a_1, &u_star);
    let beta_tilde : [u8;lambda_bytes] = zk_hash(&chall, &a_0, &v_star);
    // at the end return alpha_tilde and beta_tilde
    (alpha_tilde, beta_tilde)
}
// this gets d = w-u, the vole correlated Q, chall2, chall3 = Delta, a_tilde, pk
// it is supposed to calculate q_tilde - a_tilde * Delta, which should be equivalent to b_tilde
pub fn faest_aes_verify(d : [u8; ell], Q : [[u8; LAMBDA]; ell + LAMBDA], chall_2 : [u8; chall2_bytes], chall_3 : [u8; LAMBDA], a_tilde : [u8;lambda_bytes], pk : Pk) -> [u8;lambda_bytes]
{
    // reconstruct Delta as a field element in F_{2^lambda} from the VOLE challenge chall_3.
    // Delta is the verifier's global VOLE key, used in all QuickSilver checks
    let delta : [u8;lambda_bytes] = to_field::<LAMBDA, LAMBDA,1>(&chall_3)[0]; // k = lambda
    // Det her skal forstås som en reconstruction af det Q (en matrix), som er blevet sendt rundt på et tidligere tidspunkt
    let mut Q_mut : [[u8; LAMBDA]; ell_plus_lambda] = Q.clone();
    // correct the VOLE keys Q to account for the witness commitment d = w XOR u.
    // the prover sent d instead of w, so the verifier must adjust its VOLE keys by
    // adding d[row] * Delta to each column, which implements q[i] := q[i] + d[i] * Delta
    // column-wise. after this correction, Q encodes VOLE keys for the actual witness w
    // rather than the masking value u., i.e. this removes u from the equation ,so now it should mainly consist of w
    for row in 0..ell {
        if d[row] == 1 {
            for col in 0..LAMBDA {
                // chall_3[col] is a single bit of Delta; XORing it into Q[row][col]
                // adds delta_col * d[row] to the VOLE key, correcting for the masking
                Q_mut[row][col] ^= chall_3[col]; // chall_3[col] is already a bit (0 or 1)
            }
        }
    }
    // After correction - row 0 should now equal v[0] from sign since d[0]=w[0] XOR u[0]
    let mut q: [[u8;lambda_bytes]; ell + LAMBDA] = [[0u8;lambda_bytes]; ell + LAMBDA];
    for i in 0..ell + LAMBDA {
        q[i] = to_field::<LAMBDA, LAMBDA,1>(&Q_mut[i])[0] // k = lambda
    }
    // calculate B value that align with A0 and A1, and the vole keys q_k needed fr enc_cstrnts
    let q_for_q_delta : [[u8;lambda_bytes]; l_ke] = q[0..l_ke].try_into().unwrap();
    let (b1, q_k) : ([[u8;lambda_bytes]; S_ke], [[u8;lambda_bytes]; key_schedule_bits])= faest_aes_exp_cstrnts_qDelta(delta, q_for_q_delta, true);
    // the other B values that align with A0 and A1
    let mut b2 = [[0u8; lambda_bytes]; big_C - S_ke];
    for b in 0..beta {
        // the same moves as with prove
        let q_enc_start = l_ke + b * l_enc;
        let q_for_enc: [[u8; lambda_bytes]; l_enc] = q[q_enc_start..q_enc_start + l_enc].try_into().unwrap();
        // calculating the B encryption values, for each block
        let b2_block = faest_aes_enc_cstrnts_verifier(
            128, &pk[b].0, &pk[b].1,
            &q_for_enc, &q_k, delta, true
        );
        for i in 0..s_enc {
            b2[b * s_enc + i] = b2_block[i];
        }
    }
    // concat the two B values
    let b: [[u8;lambda_bytes]; big_C] = concat_arrays(b1, b2);
    // getting q_star like with u_star and v_star
    let mut alpha : [u8;lambda_bytes] = [0u8;lambda_bytes];
    alpha[0] = 0x02;
    let mut q_star = [0u8;lambda_bytes];
    for i in 0..LAMBDA {
        let alpha_pow : [u8;lambda_bytes] = field_pow(&alpha, i);
        let term : [u8;lambda_bytes] = gf_lambda_mul(&q[ell + i], &alpha_pow);
        q_star = xor_arrays(&q_star, &term);
    }
    // using ZK hash to get q_tilde
    let q_tilde : [u8;lambda_bytes] = zk_hash(&chall_2, &b, &q_star);
    // calculating a_tilde * Delta
    let a_tilde_times_delta : [u8;lambda_bytes] = gf_lambda_mul(&a_tilde, &delta);
    // calculating q_tilde - a_tilde * Delta
    let q_tilde_minus_a_tilde_times_delta : [u8;lambda_bytes] = xor_arrays(&q_tilde, &a_tilde_times_delta);
    // returning the value that should be equivalent to b_tilde
    q_tilde_minus_a_tilde_times_delta
}

fn concat_arrays(b1: [[u8;lambda_bytes]; S_ke], b2: [[u8;lambda_bytes]; big_C - S_ke]) -> [[u8;lambda_bytes]; big_C] {
    let mut result = [[0u8;lambda_bytes]; big_C];
    let mut idx = 0;
    for i in 0..S_ke {
        result[idx] = b1[i];
        idx += 1;
    }
    for i in 0..(big_C - S_ke) {
        result[idx] = b2[i];
        idx += 1;
    }
    result
}

pub fn bits_to_bytes_56(bits: &[u8; chall2_bytes*8]) -> [u8; chall2_bytes] {
    let mut bytes = [0u8; chall2_bytes];
    for i in 0..chall2_bytes {
        for bit in 0..8 {
            bytes[i] |= bits[i * 8 + bit] << bit;
        }
    }
    bytes
}