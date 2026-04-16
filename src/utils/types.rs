use std::any::TypeId;
use hax_lib::{Int, Prop, Refinement};
use crate::utils::galois_field;
use crate::utils::constants::*;
use hax_lib::Prop as prop;
pub type Word = [u8; 4];


pub type Matrix<T> = Vec<Vec<T>>;


const nk: usize = 4;            // code dup
const nst: usize = 4;           // code dup
pub type State = [[u8; nst]; nk];

#[hax_lib::opaque]
#[hax_lib::ensures(|result|
                    prop::from(result.len() == nk)
                    .and(hax_lib::forall(
                    |i: usize| hax_lib::implies(
                    i < result.len(), result[i].len() == nst)))
)]
pub fn from_state_to_matrix(s: State) -> Matrix<u8> {
    let mut m = Vec::with_capacity(nk);
    for i in s {
        m.push(i.to_vec());
    }
    m
}

#[hax_lib::refinement_type(|x| x >= MIN && x <= MAX)]
pub struct BoundedU64<const MIN: u64, const MAX: u64>(u64);


#[hax_lib::refinement_type(|m|
    hax_lib::forall(|i: usize|
        i >= m.len() ||
        match m.get(i) {
            Some(row) => row.len() > 0,
            None => true,
        }
    )
)]
pub struct MatrixWrapper(Matrix<u8>);

/*
impl<T: Clone> Clone for MatrixWrapper<T> {
    fn clone(&self) -> Self {
        MatrixWrapper(self.0.clone())
    }
}

 */
/*
impl hax_lib::RefineAs<_> for u64 {
    fn into_checked(self) -> _ {

    }
}

 */

/*
impl<T> MatrixWrapper<T> {

    pub(crate) fn cloned(&self) -> Self {
        *self.clone()
    }

    pub fn length(&self) -> usize {
        Vec::len(&self)
    }
}

 */






/*
impl<T> Matrix<T> {
    pub(crate) fn clone(&self) -> Matrix<T> {
        self.clone()
    }
}

 */
/*
impl<T> Matrix<T> {
    pub(crate) fn len(&self) -> usize {
        self.len()
    }
}

 */
/*
#[hax_lib::attributes]/*
#[hax_lib::refinement_type(|m|
    length() > 0 &&
    hax_lib::forall(|i: usize|
        i >= length() ||
        self[i].len() > 0
    )
)]
*/
pub struct MatrixWrapper<T>(Matrix<T>);

#[hax_lib::attributes]
impl<T> MatrixWrapper<T> {
    /*
    #[hax_lib::refine()

    (hax_lib::forall(|i: usize| hax_lib::implies(
        i < foo.len(),
        bar[foo[i] as usize] != SENTINEL
    )))]

     */
    //pub fn length(&self) -> usize {self.len()}
}

 */

/*
#[hax_lib::attributes]
struct MatrixWrapper<T> {

    #[refine(
        hax_lib::forall(|i: usize| hax_lib::implies(
        i < rows.len(),
        rows[i].len() > 0
    )))]
    data: Vec<Vec<T>>
}

 */

/*
#[hax_lib::attributes]
struct NonZeroVecUsize {
    #[refine]
    content: Vec<usize>,
}


#[hax_lib::attributes]
impl<T> NonZeroVecUsize {

    #[refine(|content| content.len() > 0)]
    fn new(content: Vec<T>) -> Option<Self> {
        if content.is_empty() {
            None
        } else {
            Some(Self { content })
        }
    }
}


 */
/*
#[hax_lib::attributes]
struct NonEmptyUsizeVec {
    #[refine(|v| !vec.is_empty())]
    v: Vec<usize>
}

#[hax_lib::attributes]
impl NonEmptyUsizeVec for [usize] {
    fn new(v: Vec<usize>) -> Option<Self> {
        if !v.is_empty() {
            Some(Self { v })
        }
        else {
            None
        }
    }
}

#[hax_lib::attributes]
impl<T> NonEmptyUsizeVec for Vec<usize> {
    type Output = T;
    fn index(&self, index: SafeIndex) -> &Self::Output {
        &self[index.i]
    }
}

 */

/*
pub fn props (ps: Vec<Prop>) -> Prop {
    let mut acc = hax_lib::Prop::from(true);
    for i in 0..ps.len() {
        acc = acc.and(ps[i]);
    }
    acc
}

 */