use std::time::Duration;
use bachelor_assurance::run_faest;

pub mod utils;
pub mod protocols;

#[hax_lib::include]
fn main() {
    let n = 10;
    let mut total_kg = Duration::ZERO;
    let mut total_sign = Duration::ZERO;
    let mut total_verify = Duration::ZERO;

    for _ in 0..n {
        let (kg, s, v, good) = run_faest::run_bench();
        assert!(good);
        total_kg += kg;
        total_sign += s;
        total_verify += v;
    }

    println!("avg key_gen: {:?}", total_kg / n);
    println!("avg sign:    {:?}", total_sign / n);
    println!("avg verify:  {:?}", total_verify / n);
}

// average time for faest-128s
/*
avg key_gen: 149.046779ms
avg sign:    1.298432237s
avg verify:  1.158871021s
 */
// average time for faest-128f
/*
avg key_gen: 156.100279ms
avg sign:    416.132741ms
avg verify:  268.389929ms
 */
// average time for faest-192s
/*
avg key_gen: 108.421087ms
avg sign:    4.305083224s
avg verify:  4.246821495s
 */
// average time for faest-192f
/*
avg key_gen: 103.81862ms
avg sign:    587.546129ms
avg verify:  474.625112ms
 */
// average time for faest-256s
/*
avg key_gen: 1.992680991s
avg sign:    8.993392508s
avg verify:  8.149921349s
 */
// average time for faest-256f
/*
avg key_gen: 1.981085162s
avg sign:    3.181789141s
avg verify:  2.208704349s
 */