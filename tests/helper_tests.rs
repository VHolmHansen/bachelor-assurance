mod tests{
    use bachelor_assurance::utils::galois_field::{gf128_mul, gf64_mul};
    use bachelor_assurance::utils::hash_functions::h_3;
    use bachelor_assurance::utils::libcrux_proxy::DigestProxy;

    #[test]
    fn test_h3() {
        let sk: [u8; 16] = [
            0xaa, 0x6a, 0x6f, 0x17, 0x13, 0xd2, 0x7a, 0x71,
            0xfe, 0x98, 0x9e, 0x93, 0xdc, 0x79, 0xd2, 0x7d,
        ];

        // mu you computed
        let mu: [u8; 32] = [
            228, 84, 30, 237, 5, 6, 205, 203, 90, 110, 148, 198, 113, 19, 177, 223,
            132, 119, 230, 107, 76, 51, 81, 225, 224, 73, 241, 59, 166, 54, 224, 176,
        ];

        let rho: [u8; 16] = [0x42; 16];

        // H3 = SHAKE128(sk || mu || rho || 3, 32 bytes)
        let mut input = Vec::new();
        input.extend_from_slice(&sk);
        input.extend_from_slice(&mu);
        input.extend_from_slice(&rho);
        input.push(3u8); // domain separation byte

        let output = libcrux::digest::shake128::<32>(&input);

        println!("rootkey (r): {:?}", &output[..16]);
        println!("iv: {:?}", &output[16..]);
    }
    #[test]
    fn test_mu_and_h3() {
        let owf_input: [u8; 16] = [
            0xc0, 0xcd, 0x0b, 0xed, 0xbe, 0x6a, 0x4c, 0x04,
            0xb3, 0x75, 0x89, 0x7d, 0x36, 0x9b, 0x7e, 0x62,
        ];
        let owf_output: [u8; 16] = [
            0x48, 0xf3, 0x63, 0x29, 0x08, 0x45, 0xaa, 0xdf,
            0x51, 0x7f, 0x82, 0x4c, 0x91, 0xfb, 0x57, 0xf5,
        ];
        let sk: [u8; 16] = [
            0xaa, 0x6a, 0x6f, 0x17, 0x13, 0xd2, 0x7a, 0x71,
            0xfe, 0x98, 0x9e, 0x93, 0xdc, 0x79, 0xd2, 0x7d,
        ];
        let rho: [u8; 16] = [0x42; 16];
        let msg = b"This document describes and specifies the FAEST digital signature algorithm.";

        // compute mu directly from bytes
        let mut mu_input: Vec<u8> = Vec::new();
        mu_input.extend_from_slice(&owf_input);
        mu_input.extend_from_slice(&owf_output);
        mu_input.extend_from_slice(msg);
        mu_input.push(0x01);
        let mu = DigestProxy::shake128::<32>(&mu_input);
        println!("mu: {:?}", mu);

        // compute r and iv
        let (r, iv) = h_3(sk, mu, rho);
        println!("r:  {:?}", r);
        println!("iv: {:?}", iv);
    }
    #[test]
    fn test_gf_mul() {
        // simple known values
        let one = {
            let mut a = [0u8; 16];
            a[0] = 1;
            a
        };
        let two = {
            let mut a = [0u8; 16];
            a[0] = 2;
            a
        };

        // 1 * 2 = 2
        let result = gf128_mul(&one, &two);
        println!("1 * 2 = {:x?}", result);
        assert_eq!(result, two);

        // 2 * 2 = 4
        let four = {
            let mut a = [0u8; 16];
            a[0] = 4;
            a
        };
        let result2 = gf128_mul(&two, &two);
        println!("2 * 2 = {:x?}", result2);
        assert_eq!(result2, four);
    }
    #[test]
    fn test_gf64_mul() {
        let one = {
            let mut a = [0u8; 8];
            a[0] = 1;
            a
        };
        let two = {
            let mut a = [0u8; 8];
            a[0] = 2;
            a
        };

        // 1 * 2 = 2
        let result = gf64_mul(&one, &two);
        println!("1 * 2 = {:x?}", result);
        assert_eq!(result, two);

        // 2 * 2 = 4
        let four = {
            let mut a = [0u8; 8];
            a[0] = 4;
            a
        };
        let result2 = gf64_mul(&two, &two);
        println!("2 * 2 = {:x?}", result2);
        assert_eq!(result2, four);

        // test reduction: multiply by alpha^64 should reduce
        // alpha^64 = alpha^4 + alpha^3 + alpha + 1 (from P64)
        let high_bit = {
            let mut a = [0u8; 8];
            a[7] = 0x80; // alpha^63
            a
        };
        let result3 = gf64_mul(&high_bit, &two); // alpha^64 = reduction
        println!("alpha^63 * 2 = alpha^64 reduced = {:x?}", result3);
        // should equal alpha^4 + alpha^3 + alpha + 1 = 0x1b
        let expected = {
            let mut a = [0u8; 8];
            a[0] = 0x1b; // 0b00011011 = alpha^4 + alpha^3 + alpha + 1
            a
        };
        assert_eq!(result3, expected);
    }
}