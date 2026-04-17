use crate::utils::helper_methods_cstrnts::byte_combine;
use crate::utils::math::xor_arrays;
use crate::utils::types::{ret_value, s_enc};

// m is size of elements
// x is the extended witness, vole tags or vole keys
// x_k expanded key values, vle tags or vole keys
// in_out is in or out, depending on who calls, where it AES plaintext or ciphertext block
// mtag same as for key_exp
// mkey same as for key_exp
// Delta, global vole key if mkey = 1 else none
// in_out should be size 128, where each u8 in it corresponds to one bit
// should never be called with mtag=1 and mkey= 1
pub fn faest_aes_enc_fwd<T : ret_value>(m : usize, x: T, x_k : T, in_out : Vec<u8>, mtag : bool, mkey : bool, Delta : <T as ret_value>::Elem){
    if mtag && mkey {
        panic!("called with wrong values")
    }
    let mut y : [<T as ret_value>::Elem;s_enc] = [<T as ret_value>::dummy_value;s_enc];
    for i in 0..16 {
        let mut x_in : [<T as ret_value>::Elem;8] = [<T as ret_value>::dummy_value;8];
        for j in 0..8 {
            if mtag { // do nothing
            } else if mkey {
                x_in[j] = if in_out[8*i+j] == 1 {Delta.clone()} else {<T as ret_value>::dummy_value};
            } else {
                x_in[j] = if in_out[8*i+j] == 1 {<T as ret_value>::value_of_one} else {<T as ret_value>::dummy_value};
            }
        }
        let x_k_slice = x_k.get_slice(8*i,8*i+8);

        let parameter_1 = byte_combine(x_in[0..8]);
        let parameter_2 = byte_combine(x_k_slice);

    }
}