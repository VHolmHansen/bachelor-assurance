use rand::{random, Rng, RngExt};
use crate::utils::*;
use hax_lib::*;
use crate::utils::finite_field::check_less_than_vec;

#[include]
struct Prover {
    a: Vec<Int>,
    b: Vec<Int>,
}

#[include]
struct Verifier {
    alpha: Int,
    v: Vec<Int>,
}

#[include]
fn field() -> finite_field::Field {
    finite_field::Field { p: 257.to_int()}
}

#[exclude]
pub fn main() {
    let mut rng = rand::rng();

    let x: Int = rng.random_range(0..field().p.to_i128()).to_int();
    let y: Int = rng.random_range(0..field().p.to_i128()).to_int();
    let z: Int = field().multiplication(x, y);

    let b1: Int = rng.random_range(0..field().p.to_i128()).to_int();
    let b2: Int = rng.random_range(0..field().p.to_i128()).to_int();
    let b3: Int = rng.random_range(0..field().p.to_i128()).to_int();
    let b4: Int = rng.random_range(0..field().p.to_i128()).to_int();

    let prover = generate_prover(x, y, z, b1, b2, b3, b4);
    let verifier = generate_verifier();
    let new_verifier = vole(prover, verifier);
    new_verifier.check_relation();
}

//#[hax_lib::ensures(|result| result[2] - result[1] * result[0] == 0)]
#[include]
#[requires(x < field().p
                    && y < field().p
                    && z < field().p
                    && z == (x * y).rem_euclid(field().p)
                    && b1 < field().p
                    && b2 < field().p
                    && b3 < field().p
                    && b3 >= 0.to_int()
                    && b4 < field().p
                    && b4 >= 0.to_int()
                    )]
#[ensures(|result| result.a.len() > 0 && result.b.len() > 0)]
fn generate_prover(x: Int, y: Int, z: Int, b1: Int, b2: Int, b3: Int, b4: Int) -> Prover {

    let xb2 = field().multiplication(x, b2);
    let yb1 = field().multiplication(y, b1);
    let xb2yb1 = field().addition(xb2, yb1);
    let inverseb3 = field().additive_inverse(b3);

    let b1b2 = field().multiplication(b1, b2);
    let inverseb4 = field().additive_inverse(b4);

    let vec1 = vec![x, y, z, field().addition(xb2yb1, inverseb3), 0.to_int()];
    let vec2 = vec![b1, b2, b3, b4, field().addition(b1b2, inverseb4)];

    Prover {
        a: vec1,
        b: vec2,
    }
}

#[exclude]
fn generate_random_for_verifier() -> Int {
    let mut rng = rand::rng();
    rng.random_range(0..field().p.to_i128()).to_int()
}

#[exclude]
fn generate_verifier() -> Verifier {
    Verifier {
        alpha: generate_random_for_verifier(),
        v: Vec::new()
    }
}

#[include]
#[attributes]
impl Verifier {

    #[requires(self.v.len() >= 5
                && self.v[0] < field().p
                && self.v[1] < field().p
                && self.v[2] < field().p
                && self.v[3] < field().p
                && self.v[4] < field().p
                && self.v[3] >= 0.to_int()
                && self.v[4] >= 0.to_int()
                && self.alpha < field().p)]
    fn check_relation(&self) -> bool {
        let v_1 = self.v[0];
        let v_2 = self.v[1];
        let v_3 = self.v[2];
        let v_4 = self.v[3];
        let v_5 = self.v[4];
        let alpha = self.alpha;

        let v_1v_2 = field().multiplication(v_1, v_2);
        let v_3alpha = field().multiplication(v_3, alpha);
        hax_lib::assert!(v_3alpha >= 0.to_int());
        let v_3alpha_minus = field().additive_inverse(v_3alpha);
        let v_4_minus = field().additive_inverse(v_4);
        let v_5_minus = field().additive_inverse(v_5);
        let v_1v_2v_3alpha = field().addition(v_1v_2, v_3alpha_minus);
        let v_1v_2v_3alphav_4_minus = field().addition(v_1v_2v_3alpha, v_4_minus);
        let result = field().addition(v_1v_2v_3alphav_4_minus, v_5_minus);
        println!("Result = {}", result);

        if result == 0.to_int() {
            return true
        }

        false
    }
}

#[include]
#[requires(prover.a.len() > 0
            && prover.b.len() > 0
            && verifier.v.len() > 0
            && prover.a.len() == verifier.v.len()
            && prover.b.len() == verifier.v.len()
            && verifier.alpha > 0.to_int()
            && verifier.alpha < field().p
            && finite_field::check_less_than_vec(prover.a, field().p)
            && finite_field::check_less_than_vec(prover.b, field().p)
            && finite_field::check_less_than_vec(verifier.v, field().p)
            )]
#[ensures(|result| result.v.len() == prover.a.len() && result.alpha < field().p)]
fn vole(prover: Prover, verifier: Verifier) -> Verifier {
    let left_vec = field().vector_scalar(prover.a, verifier.alpha);

    hax_lib::assert!(finite_field::check_less_than_vec(left_vec.clone(), field().p));
    hax_lib::assert!(left_vec.len() > 0);

    hax_lib::assert!(left_vec.len() == prover.b.len());
    let vec = field().vector_add(left_vec, prover.b);

    Verifier {
        v: vec,
        alpha: verifier.alpha
    }
}
