use crate::utils::types::ret_value;

// m is size of elements
// x is the extended witness, vole tags or vole keys
// x_k expanded key values, vle tags or vole keys
// in_out is in or out, depending on who calls, where it AES plaintext or ciphertext block
// mtag same as for key_exp
// mkey same as for key_exp
// Delta, global vole key if mkey = 1 else none
pub fn faest_aes_enc_fwd<T : ret_value>(m : usize, x: T, x_k : T, in_out : Vec<u8>, mtag : bool, mkey : bool, Delta : [u8;16]){

}