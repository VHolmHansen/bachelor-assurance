use crate::protocols::aes::{add_round_key, setup_rcon_table, R};
use crate::utils::types::{k_0, k_1, tau_0, State};
use crate::protocols::aes::{key_expansion, mix_columns, nk, shift_rows, sub_bytes};
use crate::utils::math::{transform_byte_array_to_state, xor_arrays};
use crate::utils::types::{lambda, Word};

// pk, is a tuple with a in message and out that is 128 * (\lambda / 128)
fn faest_aes_extend_witness(k :[u8;16], pk : (State,State)) -> Vec<Word>{
    let (in_aes, out_aes) = pk;
    let k_overline = key_expansion(k);
    let mut witness : Vec<Word> = k_overline[0..nk].to_vec();

    let mut ik = nk;

    let ske = ((-(lambda as i128)/8) + 56 + 28*((lambda as i128) / 256))/4;

    for j in 0..ske{

        witness.push(k_overline[ik]);

        ik = if lambda == 192 { ik+6 } else { ik+4 };
    }
    let Beta = lambda / 128;
    for b in 0..Beta{
        let mut state_new = in_aes;
        add_round_key(&mut state_new, k_overline[0..4].to_vec());
        for j in 0..R{
            sub_bytes(&mut state_new);
            shift_rows(&mut state_new);
            for i in 0..nk{
                witness.push(state_new[i]);
            }
            mix_columns(&mut state_new);
            add_round_key(&mut state_new, k_overline[4*j..4*j+4].to_vec());
        }
    }
    witness
}
// m = 1 for mtag=0 and mkey=0
// m = lambda for mtag=1 and mkey=0
// m = lambda for mtag=0 and mkey=lambda
fn faest_aes_key_exp_fwd(m : usize, x: Vec<Word>, mtag : bool, mkey : bool) -> Vec<Word> {
    if mtag && mkey{
        panic!("invalid tags")
    }
    let mut y = x[0..lambda].to_vec();
    let mut iwd = lambda;
    for j in nk..4*(R+1){
        let cond = (j % nk) == 0 || (nk > 6 && j % nk == 4);
        if cond {
            y.extend_from_slice(&x[iwd..iwd+32]);
            iwd += 32;
        }  else {
            for i in 0..32 {
                let value_to_pushed = xor_arrays(&y[32*(j-nk)+i], &y[32*(j-1)+i]);
                y.push(value_to_pushed);
            }
        }
    }
    y
}

fn faest_aes_key_exp_bkwd(m : usize, x: Vec<Word>, x_k : Vec<Word>, mtag: bool, mkey : bool, Delta : [u8;16]){
    if mtag && mkey{
        panic!("invalid tags")
    }
    let mut iwd = 0;
    let mut c = 0;
    let rmvRcon = true;
    let mut i_rcon = 0;

    let mut y = vec![];

    let ske = ((-(lambda as i128)/8) + 56 + 28*((lambda as i128) / 256))/4;

    for j in 0..ske{
        let parameter_a : [u8; 8] = x[(8*j as usize)..(8*(j as usize)+8)].try_into().expect("failed to make array of size 7");
        let parameter_b : [u8; 8] = x[iwd+8*c..iwd+8*c+8].try_into().expect("failed to make array of size 7");
        let mut x_tilde = xor_arrays(&parameter_a, &parameter_b);
        if !mtag && rmvRcon && c == 0 {
            let rcon_table = setup_rcon_table(10);
            let mut rcon_value = rcon_table[i_rcon];
            i_rcon += 1;
            for i in 0..8{
                let r = if (rcon_value & 1) == 0 {[0;16]} else {if mkey {Delta} else {[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]}};
                x_tilde[i] = x_tilde[i]- r[i];
                rcon_value = rcon_value >> 1;
            }
        }
    }
}