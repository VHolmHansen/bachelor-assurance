use hax_lib::{Int, ToInt};
use libcrux::drbg::Drbg;
use crate::utils::libcrux_proxy::RandGenProxy;
use crate::utils::types::Matrix;
use crate::utils::math;

//TODO: dead code + rewrite for hax compat + use proxy
#[allow(dead_code)]
fn generate_random_matrix(m: usize, n: usize) -> Matrix<Int> {
    let mut result_matrix: Matrix<Int> = vec![vec![0.to_int(); n]; m];
    let mut rand_gen = RandGenProxy::get_rand_gen_sha256();


    for i in 0..m {
        for j in 0..n {
            let mut rand_bytes = [0u8; 16];
            // rand_gen.generate(&mut rand_bytes);
            rand_gen.generate(rand_bytes);
            let rand_num = math::convert_byte_array_to_int(&rand_bytes);
            result_matrix[i][j] = rand_num;
        }
    }

    result_matrix
}


