use crate::utils::types::{Matrix, MatrixWrapper, State};
use hax_lib as hax;
use hax_lib::Prop as prop;


/*
#[hax_lib::requires(v.is_empty() == false)]
#[hax_lib::ensures(|result| v.is_empty() == false)]
pub fn ensure_non_zero_vec<T>(v: Vec<T>) -> bool {
    hax_lib::assert!(!v.is_empty());
    !v.is_empty()
}

 */


#[hax_lib::requires(prop::from(!m.is_empty()).and(
    hax::forall(|i: usize| hax::implies( i < m.len(), !m[i].is_empty())))
)]
#[hax_lib::ensures(|result| prop::from(!m.is_empty()).and(
    hax::forall(|i: usize| hax::implies( i < m.len(), !m[i].is_empty())))
)]
pub fn ensure_non_zero_matrix<T>(m: Matrix<T>) -> bool {
    let mut is_inner_empty = false;
    hax_lib::assert!(!m.is_empty(), "Empty matrix by rows");
    hax_lib::assert_prop!(hax_lib::forall(|i: usize| hax_lib::implies(i < m.len(), !m[i].is_empty())));

    /*
    for i in 0..m.len() {
        hax_lib::loop_invariant!(|i: usize| {
            i <= m.len()
        });
        hax_lib::assert!(!m[i].is_empty(), {is_inner_empty = true; "Empty matrix by columns"});
    }

     */
    !(m.is_empty() && is_inner_empty)
}


// TODO: check if second precondition should be present
// TODO: check if assumption is necessary
#[hax_lib::exclude]
#[hax_lib::requires(!s.is_empty() && !s[0].is_empty())]
#[hax_lib::ensures(|result| !s.is_empty()
                    && (0..s.len()).fold(true, |acc, i| {
                        hax_lib::assume!(i < s.len());
                        acc && !s[i].is_empty()})
                    )]
pub fn ensure_non_zero_state(s: State) -> bool {
    let mut acc = true;
    hax_lib::assert!(!s.is_empty(), "Empty matrix by rows");
    hax_lib::assert_prop!(hax_lib::forall(|i: usize| hax_lib::implies(i < s.len(), !s[i].is_empty())));
    /*
    for i in 0..s.len() {
        hax_lib::assert!(!s[i].is_empty(), {acc = acc && !s[i].is_empty(); "Empty matrix by columns"});
    }

     */
    !s.is_empty() && !acc


}





#[hax_lib::requires(prop::from(!indices.is_empty()
                            && !lengths.is_empty()).and(
                    hax::forall(|i: usize|
                            hax::forall(|j: usize|
                            hax::implies(
                            i < indices.len() && j < lengths.len(),
                            indices[i] < lengths[j])))
))]
#[hax_lib::ensures(|result| hax::forall(|i: usize|
                            hax::forall(|j: usize|
                            hax::implies(
                            i < indices.len() && j < lengths.len(),
                            indices[i] < lengths[j])))
)]
pub fn ensure_inbounds_indexing(indices: Vec<usize>, lengths: Vec<usize>) -> bool {
    //let mw = MatrixWrapper(arrays.clone());
    let mut bounded = true;
    /*
    for i in 0..indices.len() {
        for a in &arrays {
            hax_lib::assert!(i < a.len(), {bounded = false; "Out of bounds indexing"});
        }
    }

     */
    hax::assert_prop!(hax::forall(|i: usize| hax::forall(|j: usize|
                                    hax::implies(i < indices.len() && j < lengths.len(),
                                    indices[i] < lengths[j]))));
    bounded
}


/*
(0..indices.len()).fold(true, |acc, i| {
                                (0..arrays.len()).fold(acc, |acc, j| {
                                    indices[i] < arrays[j].len()
                                })
                            })
 */

