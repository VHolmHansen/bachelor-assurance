use hax_lib::{Int, ToInt};
use libcrux::drbg::Drbg;
use crate::utils::types::Matrix;
use crate::utils::math;

fn main() {
    let l = 10; // dimension m
    let r = 20;
    let tau = 30;
    let r_tau = r * tau; // dimension n
}

fn get_challenge() -> Int {
    0.to_int()

}

fn generate_random_matrix(m: usize, n: usize) -> Matrix<Int> {
    let mut result_matrix: Matrix<Int> = vec![vec![0.to_int(); n]; m];

    let mut rand_gen = match Drbg::new(libcrux::digest::Algorithm::Sha256) {
        Ok(drbg) => drbg,
        Err(e) => panic!("{}", e)
    };

    for i in 0..m {
        for j in 0..n {
            let mut rand_bytes = [0u8; 16];

            match rand_gen.generate(&mut rand_bytes) {
                Ok(_) => (),
                Err(e) => panic!("{}", e)
            };

            let rand_num = math::convert_byte_array_to_int(&rand_bytes);
            result_matrix[i][j] = rand_num;
        }
    }

    result_matrix
}
