#[cfg(test)]
#[cfg(all(test, feature = "lambda_128s"))]
mod tests {
    use bachelor_assurance::utils::types::*;
    use bachelor_assurance::utils::galois_field::*;
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

    #[test]
    fn test_gf128_mul_by_zero() {
        // anything * 0 = 0
        let a: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let zero = [0u8; 16];
        assert_eq!(gf128_mul(&a, &zero), zero);
    }

    #[test]
    fn test_gf128_mul_by_one() {
        // anything * 1 = itself
        let a: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut one = [0u8; 16];
        one[0] = 0x01;
        assert_eq!(gf128_mul(&a, &one), a);
    }

    #[test]
    fn test_gf128_mul_commutativity() {
        // a * b = b * a
        let a: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let b: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        assert_eq!(gf128_mul(&a, &b), gf128_mul(&b, &a));
    }

    #[test]
    fn test_gf128_mul_associativity() {
        // (a * b) * c = a * (b * c)
        let a: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let b: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let c: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        assert_eq!(
            gf128_mul(&gf128_mul(&a, &b), &c),
            gf128_mul(&a, &gf128_mul(&b, &c))
        );
    }

    #[test]
    fn test_gf128_mul_distributivity() {
        // a * (b + c) = a*b + a*c  (where + is XOR)
        let a: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let b: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let c: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];

        // b + c (XOR)
        let mut b_plus_c = [0u8; 16];
        for i in 0..16 {
            b_plus_c[i] = b[i] ^ c[i];
        }

        // a * (b + c)
        let lhs = gf128_mul(&a, &b_plus_c);

        // a*b + a*c (XOR)
        let ab = gf128_mul(&a, &b);
        let ac = gf128_mul(&a, &c);
        let mut rhs = [0u8; 16];
        for i in 0..16 {
            rhs[i] = ab[i] ^ ac[i];
        }

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_gf128_mul_alpha_squared() {
        // multiplying x * x should give x^2
        // x = 0x02 (just the bit for degree 1)
        // x^2 = 0x04 (just the bit for degree 2)
        let mut x = [0u8; 16];
        x[0] = 0x02;

        let result = gf128_mul(&x, &x);

        let mut x_squared = [0u8; 16];
        x_squared[0] = 0x04;

        assert_eq!(result, x_squared);
    }

    #[test]
    fn test_gf128_mul_reduction() {
        // x^128 should reduce to x^7 + x^2 + x + 1 (= 0x87)
        // via P128 = x^128 + x^7 + x^2 + x + 1
        // so x^128 = x^7 + x^2 + x + 1
        let mut x_64 = [0u8; 16];
        x_64[8] = 0x01; // x^64

        let result = gf128_mul(&x_64, &x_64); // x^64 * x^64 = x^128

        // x^128 mod P128 = x^7 + x^2 + x + 1 = 0b10000111 = 0x87
        let mut expected = [0u8; 16];
        expected[0] = 0x87;

        assert_eq!(result, expected);
    }
    #[test]
    fn test_gf128_mul_basic() {
        use bachelor_assurance::utils::galois_field::gf_lambda_mul;

        // [2] = x^1 in little-endian bit representation (bit 1 of byte 0 set)
        // x^1 * x^1 = x^2 = [4]
        let a = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = gf_lambda_mul(&a, &b);
        println!("x^1 * x^1 = {:?}", result);
        println!("expected  = {:?}", [4u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(result[0], 4, "x^1 * x^1 should equal x^2");

        // [1] = x^0 = 1, so [1]*[1] = [1]
        let one = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result2 = gf_lambda_mul(&one, &one);
        assert_eq!(result2, one, "1 * 1 should equal 1");

        // also check the high degree reduction:
        // x^127 * x^1 = x^128 = x^7 + x^2 + x + 1 = [0b10000111] = [0x87]
        let mut x127 = [0u8; 16];
        x127[15] = 0x80; // bit 127 = MSB of last byte in little-endian
        let x1 = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result3 = gf_lambda_mul(&x127, &x1);
        println!("x^127 * x^1 = {:?}", result3);
        println!("expected    = {:?}", [0x87u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(result3[0], 0x87, "x^128 should reduce to x^7+x^2+x+1 = 0x87");
    }
}