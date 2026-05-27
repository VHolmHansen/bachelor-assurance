use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify::faest_verify;

#[hax_lib::fstar::options("--z3rlimit 5000")]
pub fn run() {
    let (sk, pk) = faest_key_gen();
    let msg = b"oh boi";
    hax_lib::assert!(msg.len() < usize::MAX - 16 * 2 - 1);
    let sig = faest_sign(msg, &sk, &pk);
    faest_verify(msg, &pk, &sig);
}