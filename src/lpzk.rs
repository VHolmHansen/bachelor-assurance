use rand::{random, Rng, RngExt};
use crate::utils::*;


struct Prover {
    a: Vec<i128>,
    b: Vec<i128>,
}

struct Verifier {
    alpha: i128,
    v: Vec<i128>,
}

const FIELD: finite_field::Field = finite_field::Field {
    p: 257
};

pub fn main() {
    let prover = generate_prover();
    let verifier = generate_verifier();
    let new_verifier = vole(prover, verifier);
    new_verifier.check_relation();
}

//#[hax_lib::ensures(|result| result[2] - result[1] * result[0] == 0)]
fn generate_prover() -> Prover {

    let (x, y, z, b1, b2, b3, b4) = generate_prover_rands();

    let xb2 = FIELD.multiplication(x, b2);
    let yb1 = FIELD.multiplication(y, b1);
    let xb2yb1 = FIELD.addition(xb2, yb1);
    let inverseb3 = FIELD.additive_inverse(b3);

    let b1b2 = FIELD.multiplication(b1, b2);
    let inverseb4 = FIELD.additive_inverse(b4);

    let vec1 = vec![x, y, z, FIELD.addition(xb2yb1, inverseb3), 0];
    let vec2 = vec![b1, b2, b3, b4, FIELD.addition(b1b2, inverseb4)];

    Prover {
        a: vec1,
        b: vec2,
    }
}
#[hax_lib::exclude]
fn generate_prover_rands() -> (i128, i128, i128, i128, i128, i128, i128) {
    let mut rng = rand::rng();

    let x: i128 = rng.random_range(0..FIELD.p);
    let y: i128 = rng.random_range(0..FIELD.p);
    let z: i128 = FIELD.multiplication(x, y);

    let b1: i128 = rng.random_range(0..FIELD.p);
    let b2: i128 = rng.random_range(0..FIELD.p);
    let b3: i128 = rng.random_range(0..FIELD.p);
    let b4: i128 = rng.random_range(0..FIELD.p);

    (x, y, z, b1, b2, b3, b4)
}

#[hax_lib::exclude]
fn generate_rand_for_verifier() -> i128 {
    let mut rng = rand::rng();
    rng.random_range(0..FIELD.p)
}

fn generate_verifier() -> Verifier {
    Verifier {
        alpha: generate_rand_for_verifier(),
        v: Vec::new()
    }
}

impl Verifier {
    fn check_relation(self) -> bool {
        let v_1 = self.v[0];
        let v_2 = self.v[1];
        let v_3 = self.v[2];
        let v_4 = self.v[3];
        let v_5 = self.v[4];
        let alpha = self.alpha;

        let v_1v_2 = FIELD.multiplication(v_1, v_2);
        let v_3alpha = FIELD.multiplication(v_3, alpha);
        let v_3alpha_minus = FIELD.additive_inverse(v_3alpha);
        let v_4_minus = FIELD.additive_inverse(v_4);
        let v_5_minus = FIELD.additive_inverse(v_5);
        let v_1v_2v_3alpha = FIELD.addition(v_1v_2, v_3alpha_minus);
        let v_1v_2v_3alphav_4_minus = FIELD.addition(v_1v_2v_3alpha, v_4_minus);
        let result = FIELD.addition(v_1v_2v_3alphav_4_minus, v_5_minus);
        println!("Result = {:?}", result);

        if result == 0 {
            return true
        }

        false
    }
}

fn vole(prover: Prover, verifier: Verifier) -> Verifier {
    let leftvec = FIELD.vector_scalar(prover.a, verifier.alpha);
    let vec = FIELD.vector_add(leftvec, prover.b);

    Verifier {
        v: vec,
        alpha: verifier.alpha
    }
}