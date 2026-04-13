#[cfg(test)]
mod tests {
    use Bachelor_Assurance::utils::types::*;
    use Bachelor_Assurance::utils::galois_field::*;
    
    
     #[test]
         fn test_gf28_matrix_multiplication_identity() {
             let A: Matrix<u8> = vec![vec![1, 0, 0, 0],
                                      vec![0, 1, 0, 0],
                                      vec![0, 0, 1, 0],
                                      vec![0, 0, 0, 1]];
     
             let B: State = [[2, 3, 1, 1],
                 [1, 2, 3, 1],
                 [1, 1, 2, 3],
                 [3, 1, 1, 2]];
     
             let expected: Matrix<u8> = vec![vec![2, 3, 1, 1],
                                             vec![1, 2, 3, 1],
                                             vec![1, 1, 2, 3],
                                             vec![3, 1, 1, 2]];
     
             assert_eq!(gf28_matrix_multiplication(A, B), expected);
     
         }
     
     
     #[test]
     fn test_gf28_matrix_mul_with_inverse() {
         let a: Matrix<u8> = vec![vec![9, 0, 0, 0],
         vec![0, 27, 0, 0],
         vec![0, 0, 42, 0],
         vec![0, 0, 0, 3]];
 
         let b: State = [[gf28_inverse(9), 0, 0, 0],
         [0, gf28_inverse(27), 0, 0],
         [0, 0, gf28_inverse(42), 0],
         [0, 0, 0, gf28_inverse(3)]];
 
         let expected: Matrix<u8> = vec![vec![1, 0, 0, 0],
                                       vec![0, 1, 0, 0],
                                       vec![0, 0, 1, 0],
                                       vec![0, 0, 0, 1]];
 
         println!("b state: {:?}", b);
         println!("a mul b: {:?}", gf28_matrix_multiplication(a.clone(), b.clone()));
         assert_eq!(gf28_matrix_multiplication(a, b), expected);
     }
    
    #[test]    
    fn test_gf28_full_matrix_mul_with_inverse() {    
        let a: Matrix<u8> = vec![vec![9, 3, 9, 7],
                                 vec![4, 27, 13, 6],
                                 vec![87, 31, 42, 2],
                                 vec![1, 54, 29, 3]];

        let b: State = [[gf28_inverse(9), gf28_inverse(4), gf28_inverse(87), gf28_inverse(1)],
            [gf28_inverse(3), gf28_inverse(27), gf28_inverse(31), gf28_inverse(54)],
            [gf28_inverse(9), gf28_inverse(13), gf28_inverse(42), gf28_inverse(29)],
            [gf28_inverse(7), gf28_inverse(6), gf28_inverse(2), gf28_inverse(3)]];

        let expected: Matrix<u8> = vec![vec![0, 0, 0, 0],
                                        vec![0, 0, 0, 0],
                                        vec![0, 0, 0, 0],
                                        vec![0, 0, 0, 0]];
        let res = gf28_matrix_multiplication(a, b);
        assert_eq!([res[0][0], res[1][1], res[2][2], res[3][3]], [expected[0][0], expected[1][1], expected[2][2], expected[3][3]]);
    }

    #[test]    
    fn test_gf28_matrix_multiplication() {    
        /*    
        let A: Matrix<u8> = vec![vec![87,  131, 1,   0  ],    
                                 vec![2,   87,  131, 1  ],    
                                 vec![1,   2,   87,  131],    
                                 vec![131, 1,   2,   87 ]];    
        */    
        let B: State = [[19,  69,  0,   1  ],    
                        [1,   19,  69,  0  ],    
                        [0,   1,   19,  69 ],    
                        [69,  0,   1,   19 ]];    
        /*    
        let expected: Matrix<u8> = vec![vec![125, 108, 73,  122],    
                                        vec![122, 125, 108, 73 ],    
                                        vec![73,  122, 125, 108],    
                                        vec![108, 73,  122, 125]];    
    
         */    
    
        let A: Matrix<u8> = vec![vec![1, 2, 3, 4],vec![5, 6, 7, 8]];    
    
        let expected: Matrix<u8> = vec![vec![30, 96, 187, 130], vec![71, 39, 244, 93]];

        assert_eq!(gf28_matrix_multiplication(A, B), expected);

    }

    #[test]
    fn test_gf28_multiply() {    
        let a: [u8; 6] = [69, 0x57, 0x57, 1, 0, 42];    
        let b: [u8; 6] = [87, 0x02, 0x04, 1, 0, 3];    
        let mut res = vec![];    
    
        for i in 0..a.len() {    
            res.push(gf28_multiply(a[i], b[i]));    
        }    
    
        let expected: [u8; 6] = [12, 0xAE, 0x47, 1, 0, 126];    
        assert_eq!(gf28_multiply(0x57, 0x05), 0x10);    
        assert_eq!(res, expected);    
    }    
    
    #[test]    
    fn test_gf28_inverse() {    
        let x = 9;    
        println!("inverse of {:?}: {:?}", x, gf28_inverse(x));    
        assert_eq!(gf28_multiply(gf28_inverse(x), x), 1);    
    }    
}