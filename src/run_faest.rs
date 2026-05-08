use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify::faest_verify;

pub fn run() {
    let (sk, pk) = faest_key_gen();
    let msg = b"oh boi";
    let sig = faest_sign(msg, &sk, &pk);
    faest_verify(msg, &pk, &sig);
}