use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify;
use crate::protocols::faest_verify::faest_verify;

pub fn run() {
    let (sk, pk) = faest_key_gen();
    println!("done with key_gen");
    let msg = b"baaaa";
    let sig = faest_sign(msg, &sk, &pk);
    println!("done with sign");
    let sig_to_return = faest_verify(msg, &pk, &sig);
    println!("done with verify, it became {:?}", sig_to_return);
}

