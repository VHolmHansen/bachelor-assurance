#[cfg(not(hax))]
use libcrux;

#[cfg(hax)]
mod libcrux {
    pub mod digest {
        #[derive(Clone, Copy)]
        pub enum Algorithm {
            Sha256,
        }

        pub fn shake128<const LEN: usize>(_input: &[u8]) -> [u8; LEN] {
            hax_lib::assume!(false); // unreachable placeholder
            [0u8; LEN]
        }
    }

    pub mod drbg {
        pub struct Drbg;

        pub trait RngCore {
            fn fill_bytes(&mut self, dest: &mut [u8]);
        }

        impl Drbg {
            pub fn new(
                _alg: super::digest::Algorithm,
            ) -> Result<Self, &'static str> {
                Ok(Self)
            }

            pub fn generate(
                &mut self,
                _out: &mut [u8],
            ) -> Result<(), &'static str> {
                Ok(())
            }
        }

        impl RngCore for Drbg {
            fn fill_bytes(&mut self, _dest: &mut [u8]) {}
        }
    }
}

pub struct RandGenProxy {
    rand_gen: libcrux::drbg::Drbg,
}

#[hax_lib::attributes]
impl RandGenProxy{
    #[hax_lib::opaque]
    pub fn get_rand_gen_sha256() -> Self {
        let rand_gen = match libcrux::drbg::Drbg::new(libcrux::digest::Algorithm::Sha256) {
            Ok(drbg) => drbg,
            Err(e) => panic!("{}", e)
        };
        Self { rand_gen }
    }

    #[hax_lib::opaque]
    pub fn fill_bytes(&mut self, key: &mut [u8; 16]) {
        libcrux::drbg::RngCore::fill_bytes(&mut self.rand_gen, key)
    }

    #[hax_lib::opaque]
    pub fn generate(&mut self, mut rand_bytes: [u8; 16]) {
        match self.rand_gen.generate(&mut rand_bytes) {
                Ok(_) => (),
                Err(e) => panic!("{}", e)
            };
    }

}

pub struct DigestProxy;

#[hax_lib::attributes]
impl DigestProxy {

    #[hax_lib::opaque]
    pub fn shake128<const LEN: usize>(input: &[u8]) -> [u8; LEN] {
        libcrux::digest::shake128::<LEN>(&input)
    }
}
