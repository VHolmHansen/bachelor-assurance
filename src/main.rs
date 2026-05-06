
use crate::protocols::faest_key_gen::faest_key_gen;
use crate::protocols::faest_sign::faest_sign;
use crate::protocols::faest_verify::faest_verify;


pub mod utils;
pub mod protocols;


#[hax_lib::exclude]
fn main() {
    
    let builder = std::thread::Builder::new().stack_size(32 * 1024 * 1024); // 64MB
    let handler = builder.spawn(|| {
        let start = std::time::Instant::now();
        let (key, pk) = faest_key_gen();
        println!("key_gen took: {:?}", start.elapsed());

        let msg: &[u8] = b"baaaaaaaahhhhhhh";

        let sign_start = std::time::Instant::now();
        let sig = faest_sign(msg, &key, &pk);
        println!("sign took: {:?}", sign_start.elapsed());

        let verify_start = std::time::Instant::now();
        let great_succes = faest_verify(msg, &pk, &sig);
        println!("verify took: {:?}", verify_start.elapsed());
        println!("verify succes: {:?}", great_succes);
        // println!("sig is: {:?}", sig);
    }).unwrap();
    handler.join().unwrap();




    // test_vector()
}


fn test_vector(){
    let builder = std::thread::Builder::new().stack_size(32 * 1024 * 1024); // 64MB
    let handler = builder.spawn(|| {
        let pk : [u8;32] = [0xc1, 0xa3, 0xc0, 0x22, 0xe7, 0x18, 0x93, 0x5f, 0x46, 0x63, 0x03,
            0x86, 0xaf, 0xa3, 0xd3, 0xf2, 0xe1, 0x57, 0x09, 0xfe, 0x67, 0xa8,
            0xb5, 0x37, 0xb5, 0x35, 0x89, 0x15, 0x52, 0x4e, 0xb6, 0xf0];
        let sk : [u8;16] = [0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19, 0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f, 0xbe, 0x52];
        let pk = pk_to_bits(&pk);
        let msg = [0x54, 0x68, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74,
            0x20, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x73, 0x20, 0x61, 0x6e,
            0x64, 0x20, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x46, 0x41, 0x45, 0x53, 0x54, 0x20, 0x64, 0x69, 0x67, 0x69,
            0x74, 0x61, 0x6c, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
            0x20, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e];


        let sig = faest_sign(&msg, &sk, &pk);
        println!("sig is: {:#x?}", sig.0);
    }).unwrap();
    handler.join().unwrap();


}

fn pk_to_bits(pk: &[u8; 32]) -> ([u8; 128], [u8; 128]) {
    let mut first = [0u8; 128];
    let mut second = [0u8; 128];

    for (i, &byte) in pk[..16].iter().enumerate() {
        for bit in 0..8 {
            first[i * 8 + bit] = (byte >> (7 - bit)) & 1;
        }
    }

    for (i, &byte) in pk[16..].iter().enumerate() {
        for bit in 0..8 {
            second[i * 8 + bit] = (byte >> (7 - bit)) & 1;
        }
    }

    (first, second)
}
