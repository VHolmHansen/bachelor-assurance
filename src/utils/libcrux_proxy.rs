use libcrux::drbg::{Drbg, RngCore};
use libcrux::digest;

pub enum alg {
    Sha256
}

pub struct RandGenProxy {
    rand_gen: Drbg
}

impl RandGenProxy{
    pub fn get_rand_gen_sha256() -> Self {
        let mut rand_gen = match Drbg::new(libcrux::digest::Algorithm::Sha256) {
            Ok(drbg) => drbg,
            Err(e) => panic!("{}", e)
        };
        Self { rand_gen }
    }

    pub fn fill_bytes(&mut self, key: &mut [u8; 16]) {
        self.rand_gen.fill_bytes(key)
    }

    pub fn generate(&mut self, mut rand_bytes: [u8; 16]) {
        match self.rand_gen.generate(&mut rand_bytes) {
                Ok(_) => (),
                Err(e) => panic!("{}", e)
            };
    }

}

pub struct DigestProxy;

impl DigestProxy {
    pub fn shake128<const LEN: usize>(input: &[u8]) -> [u8; LEN] {     //TODO: nor sure if u8; 16
        digest::shake128::<LEN>(&input)
    }
}
