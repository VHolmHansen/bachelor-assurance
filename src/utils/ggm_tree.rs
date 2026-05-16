#![allow(non_upper_case_globals)]
use crate::utils::prg::prg;
use crate::utils::types::{sized_array_16, sized_option_array, Log2Number};
#[hax_lib::fstar::options("--z3rlimit 50")]
#[hax_lib::requires(size_pow > 0 && d <= 12 && ((d == 0 && size_pow == 1) || (d > 0 && size_pow == 2 << (d-1))))]
pub fn get_leaves_node_from_root<const size_pow: usize>(r: &[u8; 16], iv: [u8; 16], d: usize) -> sized_array_16<size_pow>{
    let mut leaves: [[u8; 16]; size_pow] = [[0u8;16]; size_pow];
    //hax_lib::assume!(size_pow == 2 << (d - 1)); //TODO
    leaves[0] = *r;
    if d >= 1 {
        for i in 1..(d + 1) {
            hax_lib::loop_invariant!(|i: usize| {
                i <= d + 1 &&
                d >= 1 &&
                i >= 1
            });
            hax_lib::assert!(size_pow == 2 << (d - 1));
            let current_leaves: [[u8; 16]; size_pow] = leaves;
            for j in 0..((2 << (i - 1)) >> 1) {
                hax_lib::loop_invariant!(|j: usize| {
                    j <= leaves.len() >> (d+1-i) &&
                    leaves.len() == 2 << (d - 1) &&
                    (j == (leaves.len() >> 1) || (j <= (leaves.len() >> 1) - 1 && j << 1 < leaves.len() && (j << 1) + 1 < leaves.len()))
                });
                // get parent value for prg
                let ran_value = current_leaves[j];

                let mut nodes = [0u8; 32];
                prg(ran_value, iv, &mut nodes);

                // get child values for left and right
                let left_node_value: [u8; 16] = nodes[..16].try_into().unwrap();
                let right_node_value: [u8; 16] = nodes[16..].try_into().unwrap();

                // insert child values
                hax_lib::assert!(j << 1 < leaves.len());
                hax_lib::assert!((j << 1) + 1 < leaves.len());
                leaves[j << 1].copy_from_slice(&left_node_value);   //TODO: subtyping
                leaves[(j << 1) + 1].copy_from_slice(&right_node_value);
            }
        }
    }
    // returns correct size
    leaves
}

#[hax_lib::requires(size > 0)]
pub fn get_cop<const size: usize>(r: [u8;16], iv: [u8;16], b: u64) -> sized_array_16<size> {
    let mut cop = [[0u8; 16]; size];
    let mut current_node = r;

    for i in 0..size {
        let is_left = get_if_left((size - i - 1) as u64, b);

        let mut nodes = [0u8; 32];
        prg(current_node, iv, &mut nodes);

        // get child values for left and right
        let left_node_value : [u8;16]= nodes[..16].try_into().unwrap();
        let right_node_value : [u8;16] = nodes[16..].try_into().unwrap();

        // move right direction
        if is_left {
            current_node = left_node_value;
            cop[i] = right_node_value;
        } else {
            current_node = right_node_value;
            cop[i] = left_node_value;
        }
    }
    cop
}


// ensure level < tree size
pub fn get_if_left(level : u64, index : u64) -> bool{
    let mut index = index;
    let mut i = level;
    while i > 0 {
        hax_lib::loop_decreases!(i);
        if index % 2 == 1 {
            index = (index - 1) >> 1
        } else {
            index = (index) >> 1
        }
        i -= 1;
    }

    if index % 2 == 1 {
        false
    } else {
        true
    }
}

#[hax_lib::fstar::options("--z3rlimit 50")]
#[hax_lib::requires(size > 0 && size <= 12 && size_pow <= 4096 && 1 << size == size_pow &&
                    (size_pow >> 1 == 1 || size_pow >> 1 == 2 || size_pow >> 1 == 4 || size_pow >> 1 == 8
                        || size_pow >> 1 == 16 || size_pow >> 1 == 32 || size_pow >> 1 == 64 || size_pow >> 1 == 128
                        || size_pow >> 1 == 256 || size_pow >> 1 == 512 || size_pow >> 1 == 1024 || size_pow >> 1 == 2048))]
pub fn get_leaves_from_cop_and_b<const size : usize, const size_pow : usize>(cop : &sized_array_16<size>, iv : [u8;16], b: u64) -> sized_option_array<size_pow> {
    let mut leaves: sized_option_array<size_pow> = [None; size_pow];
    let mut current_start = 0;
    let mut current_end = size_pow;
    let mut match_value = Log2Number::wrap(size_pow >> 1);


    //TODO: needs a serious revisit
    for c in 0..cop.len() {
        hax_lib::loop_invariant!(|c: usize| {
            c <= size &&
            1 << size == size_pow &&
            current_end <= size_pow &&
            match_value.value() == size_pow >> (c + 1) &&
            current_end >= match_value.value() << 1 &&
            current_start == current_end - (match_value.value() << 1)

            //current_end >= size_pow >> c &&
            //current_start == current_end - (size_pow >> c) &&

        });
        hax_lib::assert!(c < cop.len());
        hax_lib::assert!(size_pow > 0);
        hax_lib::assert!(size_pow <= 4096);
        hax_lib::assert!(current_end <= size_pow);
        //hax_lib::assert!(current_end >= size_pow >> ( c + 1));
        //hax_lib::assert!(match_value.value() <= usize::MAX / 2);
        //hax_lib::assert!(current_start <= current_end - 2 * match_value.value());
        hax_lib::assert!(current_end >= 2 * match_value.value());
        hax_lib::assert!(current_start >= current_end - 2 * match_value.value());
        (current_start, current_end) = match match_value {
            Log2Number::twothousandsandfortyeight => {
                cop_helper::<2048, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::one => {
                cop_helper::<1, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::two => {
                cop_helper::<2, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::four => {
                cop_helper::<4, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::eight => {
                cop_helper::<8, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::sixteen => {
                cop_helper::<16, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::thirtytwo => {
                cop_helper::<32, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::sixtyfour => {
                cop_helper::<64, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::onehundredandtwentyeight => {
                cop_helper::<128, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::twohundredandfiftysix => {
                cop_helper::<256, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::fivehundredandtwelve => {
                cop_helper::<512, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::onethousandandtwentyfour => {
                cop_helper::<1024, size_pow>(&cop[c], &mut leaves, iv, b, current_start, current_end)}
            Log2Number::zero => {(current_start, current_end)}

        };
        if match_value.value() > 0 { match_value = match_value.log_reduce() }
    }
    leaves
}
//*current_start <= 2048 && *current_end >= 0 && *current_end < size_pow
#[hax_lib::fstar::options("--z3rlimit 50")]
#[hax_lib::requires(N >= 1 && N <= 2048 && (N >> 1 == 0 || N >> 1 == 1 || N >> 1 == 2 || N >> 1 == 4 || N >> 1 == 8
                    || N >> 1 == 16 || N >> 1 == 32 || N >> 1 == 64 || N >> 1 == 128
                    || N >> 1 == 256 || N >> 1 == 512 || N >> 1 == 1024)
                    && size_pow > 0 && size_pow <= 4096
                    && end >= 2 * N && start == end - 2 * N
                    && end <= size_pow)]
#[hax_lib::ensures(|(current_start, current_end)| current_end >= N && current_end - N == current_start && current_end <= size_pow)]
fn cop_helper<const N: usize, const size_pow: usize>(c: &[u8; 16], leaves: &mut [Option<[u8; 16]>; size_pow], iv: [u8; 16], b: u64, start: usize, end: usize) -> (usize, usize){
    let d = N.ilog2() as usize;
    let mut current_start = start;
    let mut current_end = end;
    /*let mut d: usize = 0;
    let mut found = false;
    for i in 0..12_usize {
        hax_lib::loop_invariant!(|i: usize| {
            hax_lib::Prop::from(i <= 12)
            .and(hax_lib::Prop::from(d <= 12))
            .and(hax_lib::implies(i >= 11, found))
                .and(hax_lib::implies(!found, d == 0)
                    .and(hax_lib::implies(found, ((d == 0 && N == 1) || (d > 0 && N == 2 << (d-1))))))

        });
        if !found && N >> i == 1 {d = i; found = true; hax_lib::assert!(d <= 12);};
    }
    hax_lib::assert!(found);
    //let d = if d == 0 { d } else { d - 1};

     */
    //TODO revisit these assumptions
    hax_lib::assume!(d <= 12);
    hax_lib::assume!(N > 0 && d <= 12 && ((d == 0 && N == 1) || (d > 0 && N == 2 << (d-1))));
    let leaves_to_add = get_leaves_node_from_root::<N>(c, iv, d);
    hax_lib::assert!(leaves_to_add.len() == N);
    if get_if_left(d as u64, b) {
        hax_lib::assert!(current_start <= usize::MAX - N);
        hax_lib::assert!(current_start + N <= current_end);
        for i in (current_start+N)..current_end {
            hax_lib::loop_invariant!(|i: usize| {
                    i <= current_end &&
                    i >= current_start + N
                });
            hax_lib::assert!(i - (current_start + N) < leaves_to_add.len());
            hax_lib::assert!(i < leaves.len());
            leaves[i] = Some(leaves_to_add[i-(current_start+N)]);
            hax_lib::assert!(leaves.len() == size_pow);
        }
        hax_lib::assert!(current_end >= N);
        current_end -= N;
        hax_lib::assert!(current_end - N == current_start);
    } else {
        for i in 0..N {
            hax_lib::assert!(i < leaves_to_add.len());
            leaves[i+current_start] = Some(leaves_to_add[i]);
            hax_lib::assert!(leaves.len() == size_pow);
        }
        hax_lib::assert!(current_start <= usize::MAX - N);
        current_start += N;
        hax_lib::assert!(current_end - N == current_start);
        hax_lib::assert!(leaves.len() == size_pow);
    }
    hax_lib::assert!(leaves.len() == size_pow);
    hax_lib::assert!(current_end >= N);
    hax_lib::assert!(current_end - N == current_start);
    (current_start, current_end)
}

/*
//TODO: should be deleted?
#[cfg(not(hax))]
pub fn main(){
    const pow_of_k_1 : usize = 2048;
    let leaves1 = get_leaves_node_from_root::<pow_of_k_1>(&[1;16], [0;16], k_1);

    let cop = get_cop::<k_1>([1;16], [0;16], 2047, k_1 as i128);

    let leaves = get_leaves_from_cop_and_b::<k_1,pow_of_k_1>(&cop, [0;16], 2047);


    for i in 0..2048{
        match leaves[i] {
            Some(leaf) => {
                assert!(leaf == leaves1[i]);
            }
            None => {}
        }
    }

}

 */
