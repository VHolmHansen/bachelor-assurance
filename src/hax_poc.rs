use hax_lib::*;
use hax_lib::Refinement;

/*
#[hax_lib::refinement_type(|x| x >= MIN && x <= MAX)]
pub struct BoundedU8<const MIN: u8, const MAX: u8>(u8);

pub fn bounded_u8(x: BoundedU8<12, 15>, y: BoundedU8<10, 11>) -> BoundedU8<22, 26> {
    let z: u8 = BoundedU8::<22, 26>::new(x.get() + y.get()).get();
    hax_lib::assert!(z >= 22 && z <= 26);
    BoundedU8::new(z)
}

 */



/*
pub fn bounded_u8_2(x: BoundedU8<12, 15>, y: BoundedU8<10, 11>) -> BoundedU8<1, 23>{
    hax_lib::RefineAs::into_checked(x.0 + y.0);
    // the trait bound `u64: RefineAs<_>` is not satisfied
    // the trait `RefineAs<_>` is not implemented for `u64`

    // When compiling with hax -> x.0 and y.0 are private fields

    // Can't use functions in implementations either:
    let z = hax_lib::Refinement::get(x);
    // the trait bound `hax_poc::BoundedU64<12, 15>: Refinement` is not satisfied [E0277]
    // unsatisfied trait bound
    // Help: the trait `Refinement` is not implemented for `hax_poc::BoundedU64<12, 15>

    // Obviously cannot initialize a tuple struct like so because of private fields
    BoundedU8(z)
}

pub fn bounded_usize(x: Refinement<InnerType=(MatrixWrapper)>) -> BoundedU8<12, 15> {
    x
}



#[hax_lib::refinement_type(|x| x.len() > 0)]
pub struct NonEmptyVec<T>(Vec<T>);

#[hax_lib::attributes]
impl <T> NonEmptyVec<T> {
    #[hax_lib::ensures(|res| res > 0)]
    fn len(self) -> usize {
        self.get().len()
    }
}

pub fn non_empty_vec_test() {
    let v: Vec<usize> = vec![1, 2, 3];
    let nv = NonEmptyVec::<usize>::new(v);
    nv.len()
}

 */

