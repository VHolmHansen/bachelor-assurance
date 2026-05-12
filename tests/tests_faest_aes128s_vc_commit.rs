// #[cfg(all(test, feature = "lambda_128s"))]
#[cfg(test)]
mod tests{
    use bachelor_assurance::utils::constants::{iv_bytes, k_0, k_0_pow, k_1, k_1_pow, lambda_bytes};
    use bachelor_assurance::utils::preliminary_helper_methods::{num_rec_k0, num_rec_k1};
    use bachelor_assurance::utils::types::sized_array_for_sds;
    use bachelor_assurance::utils::vector_commit::{vec_commit_k0, vec_commit_k1, vec_open_k0, vec_open_k1, vec_reconstruct_k0, vec_reconstruct_k1};
    use rand::Rng;

    // testing that correlation between vec_commit and vec_reconstruct works
    // for a random index
    #[test]
    fn test_vec_com_rec_k0_correlation(){
        for i in 0..10{
            let r: [u8; lambda_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let iv: [u8; iv_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let b: [u8; k_0] = std::array::from_fn(|_| rand::random::<bool>() as u8);

            let (h_com, decom, sds_to_return) = vec_commit_k0(r, iv);
            let pdecom = vec_open_k0(&decom, &b);
            let (h_rec, sds)= vec_reconstruct_k0(&pdecom, b, iv);
            assert_eq!(h_com, h_rec);
            let array_sds_to_return = match sds_to_return {
                sized_array_for_sds::sized_array_1(array) => array,
                _ => panic!("should not happen"),
            };
            let array_sds = match sds {
                sized_array_for_sds::sized_array_1(array) => array,
                _ => panic!("should not happen"),
            };

            for i in 0..k_0_pow{
                if i == num_rec_k0(&b) as usize {

                } else {
                    assert_eq!(array_sds_to_return[i], array_sds[i]);
                }
            }
        }
    }
    // same as above just for k1
    #[test]
    fn test_vec_com_rec_k1_correlation(){
        for i in 0..10{
            let r: [u8; lambda_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let iv: [u8; iv_bytes] = std::array::from_fn(|_| rand::random::<u8>());
            let b: [u8; k_1] = std::array::from_fn(|_| rand::random::<bool>() as u8);

            let (h_com, decom, sds_to_return) = vec_commit_k1(r, iv);
            let pdecom = vec_open_k1(&decom, &b);
            let (h_rec, sds)= vec_reconstruct_k1(&pdecom, b, iv);
            assert_eq!(h_com, h_rec);
            let array_sds_to_return = match sds_to_return {
                sized_array_for_sds::sized_array_2(array) => array,
                _ => panic!("should not happen"),
            };
            let array_sds = match sds {
                sized_array_for_sds::sized_array_2(array) => array,
                _ => panic!("should not happen"),
            };

            for i in 0..k_1_pow{
                if i == num_rec_k1(&b) as usize {

                } else {
                    assert_eq!(array_sds_to_return[i], array_sds[i]);
                }
            }
        }
    }
}