use crate::utils::galois_field;
pub type Word = [u8; 4];
pub type Matrix<T> = Vec<Vec<T>>;

const nk: usize = 4;            // code dup
const nst: usize = 4;           // code dup
pub type State = [[u8; nst]; nk];