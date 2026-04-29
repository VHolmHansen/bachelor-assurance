#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
use crate::utils::galois_field::gf128_mul;
use crate::utils::math::xor_arrays;
use crate::utils::preliminary_helper_methods::num_rec;
use crate::utils::prg::prg;
use crate::utils::types::Tree::{Leaf, Node};
use crate::utils::constants::{nst, nk, k_0, k_1};

pub type Word = [u8; 4];
pub type Matrix<T> = Vec<Vec<T>>;

pub type State = [[u8; nst]; nk];
pub type sized_array<const size: usize> = [[u8;16];size];

pub trait ret_value {
    type Elem: Clone;
    const dummy_value : Self::Elem;
    const value_of_one : Self::Elem;
    const value_of_two : Self::Elem;
    const value_of_three : Self::Elem;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem];
    fn get_element(&self, x : usize) -> Self::Elem;
    fn push_value(self, x : Self::Elem) -> Self;
    fn xor_array(x : &Self::Elem, y : &Self::Elem) -> Self::Elem;
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self;
    fn set_element(&mut self, index : usize, value : &Self::Elem);
    fn new_with_size(size: usize, value: Self::Elem) -> Self;
    fn len(&self) -> usize;
    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16];
    fn turn_array_to_T(x : &[Self::Elem]) -> Self;
}
impl ret_value for Vec<[u8;16]> {
    type Elem = [u8;16];
    const dummy_value : Self::Elem = [0;16];
    const value_of_one : Self::Elem = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const value_of_two : Self::Elem = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const value_of_three : Self::Elem = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem] {
        &self[x..y]
    }
    fn get_element(&self, x : usize) -> [u8;16] {
        self[x]
    }
    fn push_value(mut self, x: [u8;16]) -> Self {
        self.push(x);
        self
    }
    fn xor_array(x : &[u8;16], y : &[u8;16]) -> [u8;16]{
        xor_arrays(x, y)
    }

    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self {
        let mut res: Vec<[u8;16]> = vec![];
        for i in 0..8 {
            let value_to_push = Self::xor_array(&x[i], &y[i]);
            res.push(value_to_push);
        }
        res
    }

    fn set_element(&mut self, index : usize, value : &Self::Elem) {
        self[index] = *value;
    }
    fn new_with_size(size: usize, value: Self::Elem) -> Self {
        vec![value; size]
    }
    fn len(&self) -> usize{
        self.len()
    }

    fn multiply_with_alpha(x : Self::Elem, alpha_val : [u8;16]) -> [u8;16]{
        gf128_mul(&x, &alpha_val)
    }
    fn turn_array_to_T(x : &[Self::Elem]) -> Vec<Self::Elem> {
        x.to_vec()
    }
}

impl ret_value for Vec<u8> {
    type Elem = u8;
    const dummy_value : Self::Elem = 0;
    const value_of_one : Self::Elem = 1;
    const value_of_two: Self::Elem = 2;
    const value_of_three : Self::Elem = 3;
    fn get_slice(&self, x : usize, y: usize) -> &[Self::Elem] {
        &self[x..y]
    }
    fn get_element(&self, x : usize) -> u8 {
        self[x]
    }
    fn push_value(mut self, x: u8) -> Self {
        self.push(x);
        self
    }
    fn xor_array(x : &u8, y : &u8) -> u8{
        x ^ y
    }
    fn xor_two_array(x : &[Self::Elem], y : &[Self::Elem]) -> Self {
        let mut res: Vec<u8> = vec![];
        for i in 0..8 {
            let value_to_push = Self::xor_array(&x[i], &y[i]);
            res.push(value_to_push);
        }
        res
    }

    fn set_element(&mut self, index : usize, value : &Self::Elem) {
        self[index] = *value;
    }
    fn new_with_size(size: usize, value: Self::Elem) -> Self {
        vec![value; size]
    }
    fn len(&self) -> usize{
        self.len()
    }

    fn multiply_with_alpha(x: u8, alpha_val: [u8; 16]) -> [u8; 16] {
        // x is a scalar bit (0 or 1)
        // result is either 0 or alpha_val
        if x == 0 {
            [0u8; 16]
        } else {
            alpha_val
        }
    }
    fn turn_array_to_T(x : &[Self::Elem]) -> Vec<Self::Elem> {
        x.to_vec()
    }
}



#[derive(Clone, Debug)]
pub enum Tree {
    Leaf(Option<[u8; 16]>),
    Node(Box<Tree_node>)
}

#[derive(Clone, Debug)]
struct Tree_node {
    value: Option<[u8; 16]>,
    left: Option<Box<Tree>>,
    right: Option<Box<Tree>>
}

impl Tree {
    pub fn construct_tree(r: [u8; 16], iv: [u8; 16], wanted_length: i128) -> Self {
        // if i want a tree of size 8, the typical with 128 leaves, then i want to call the inner function with wanted_length=7
        // because the root is made outside
        let (root_left_node, root_right_node) = Self::construct_tree_rec(iv, r, 0, wanted_length - 1);
        let root_tree_node = Tree_node {
            value: Some(r),
            left: Some(Box::from(root_left_node)),
            right: Some(Box::from(root_right_node))
        };
        let tree = Node(Box::from(root_tree_node));
        tree
    }

    fn construct_tree_rec(iv: [u8; 16], r: [u8; 16], tree_length: i128, tree_length_to_be: i128) -> (Self, Self) {
        let mut nodes = [0u8; 32];
        prg(r, iv, &mut nodes);
        let left_node_value = nodes[..16].try_into().unwrap();
        let right_node_value = nodes[16..].try_into().unwrap();

        if tree_length == tree_length_to_be {
            (Leaf(Some(left_node_value)), Leaf(Some(right_node_value)))
        } else {
            let (left_left_node, left_right_node) = Self::construct_tree_rec(iv, left_node_value, tree_length + 1, tree_length_to_be);
            let (right_left_node, right_right_node) = Self::construct_tree_rec(iv, right_node_value, tree_length + 1, tree_length_to_be);
            let left_tree_node = Tree_node { value: Some(left_node_value), left: Some(Box::from(left_left_node)), right: Some(Box::from(left_right_node)) };
            let right_tree_node = Tree_node { value: Some(right_node_value), left: Some(Box::from(right_left_node)), right: Some(Box::from(right_right_node)) };
            (Node(Box::from(left_tree_node)), Node(Box::from(right_tree_node)))
        }
    }

    pub fn get_all_leaf_nodes(tree: &Self) -> Vec<[u8; 16]> {
        fn helper(t: &Tree, leaves: &mut Vec<[u8; 16]>) {
            match t {
                Leaf(Some(v)) => leaves.push(*v),
                Leaf(None) => {}
                Node(node) => {
                    if let Some(left) = &node.left {
                        helper(left, leaves);
                    }
                    if let Some(right) = &node.right {
                        helper(right, leaves);
                    }
                }
            }
        }
        let mut leaves = Vec::new();
        helper(&tree, &mut leaves);
        leaves
    }

    pub fn get_cop(b: Vec<u8>, tre: Self, d: i128) -> Vec<[u8; 16]> {
        fn get_cop_helper(b: u64, tre: &Tree, mut acc: Vec<[u8; 16]>, level: i128, height_of_tree: i128) -> Vec<[u8; 16]> {
            let is_left;
            if level == height_of_tree + 1 {
                is_left = true;
            } else {
                is_left = Tree::if_left_at_index_at_level(b, level, height_of_tree);
            }

            // might have made a mistake therefore !
            match tre {
                Leaf(Some(_v)) => { acc },
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(_v), left: Some(ln), right: Some(rn) } => {
                            if is_left {
                                acc.push(Tree::get_value_of_node(rn).unwrap());
                                get_cop_helper(b, ln, acc, level + 1, height_of_tree)
                            } else {
                                acc.push(Tree::get_value_of_node(ln).unwrap());
                                get_cop_helper(b, rn, acc, level + 1, height_of_tree)
                            }
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        }
        let cop: Vec<[u8; 16]> = Vec::with_capacity(b.len());
        let _length_of_b = b.len() as u64;
        let value_of_b = num_rec(b, d as u64);

        get_cop_helper(value_of_b, &tre, cop, 1, d)
    }
    // got a bunch of overflows, so changed it to use an accumulator, and not so much recursion
    pub fn get_leaves_from_cop_and_b(b: u64, cop: Vec<[u8; 16]>, iv: [u8; 16]) -> Vec<Option<[u8; 16]>> {
        let mut leaves_acc: Vec<Option<[u8; 16]>> = Vec::new();
        let length_of_cop = cop.len() as u64;
        let cop_len_minus_1 = length_of_cop - 1;
        let is_b_left = Self::if_left_at_index_at_level(b, length_of_cop as i128, length_of_cop as i128);
        for i in (0..cop_len_minus_1).rev() {
            let tre = Self::construct_tree_at_certain_levels(cop[i as usize], iv, ((cop_len_minus_1 - 1) - i) as i128);
            let is_left_compared_to_b = Self::if_left_at_index_at_level(b, (i + 1) as i128, cop.len() as i128);
            let leaves = Self::get_all_leaf_nodes(&tre);

            let mut acc = 0;
            for l in leaves {
                if is_left_compared_to_b {
                    leaves_acc.push(Some(l));
                } else {
                    leaves_acc.insert(acc, Some(l));
                    acc += 1;
                }
            }
        }

        if is_b_left {
            leaves_acc.insert(b as usize, None);
            leaves_acc.insert((b + 1) as usize, Some(cop[cop.len() - 1]));
        } else {
            leaves_acc.insert((b - 1) as usize, Some(cop[cop.len() - 1]));
            leaves_acc.insert(b as usize, None);
        }


        leaves_acc
    }


    fn if_left_at_index_at_level(b: u64, level: i128, d: i128) -> bool {
        (b >> (d - level)) & 1 == 0
    }

    fn construct_tree_at_certain_levels(r: [u8; 16], iv: [u8; 16], levels: i128) -> Self {
        let (root_left_node, root_right_node) = Tree::construct_tree_rec(iv, r, 0, levels);
        let root_tree_node = Tree_node {
            value: Some(r),
            left: Some(Box::from(root_left_node)), right: Some(Box::from(root_right_node))
        };
        let tree = Node(Box::from(root_tree_node));
        tree
    }

    fn get_value_of_node(tre: &Self) -> Option<[u8; 16]> {
        match tre {
            Leaf(Some(v)) => Some(*v),
            Node(node) => match &**node {
                Tree_node { value: Some(v), left: Some(_ln), right: Some(_rn) } => {
                    Some(*v)
                }
                _ => unreachable!()
            }
            _ => None
        }
    }
}

/*
impl Tree {
    pub fn construct_tree(r: [u8; 16], iv: [u8; 16], wanted_length: i128) -> Self {
        // if i want a tree of size 8, the typical with 128 leaves, then i want to call the inner function with wanted_length=7
        // because the root is made outside
        let (root_left_node, root_right_node) = Self::construct_tree_rec(iv, r, 0, wanted_length - 1);
        let root_tree_node = Tree_node {
            value: Some(r),
            left: Some(Box::from(root_left_node)),
            right: Some(Box::from(root_right_node))
        };
        let tree = Node(Box::from(root_tree_node));
        tree
    }

    fn construct_tree_rec(iv: [u8; 16], r: [u8; 16], tree_length: i128, tree_length_to_be: i128) -> (Self, Self) {
        let mut nodes = [0u8; 32];
        prg(r, iv, &mut nodes);
        let left_node_value = nodes[..16].try_into().unwrap();
        let right_node_value = nodes[16..].try_into().unwrap();

        if tree_length == tree_length_to_be {
            (Leaf(Some(left_node_value)), Leaf(Some(right_node_value)))
        } else {
            let (left_left_node, left_right_node) = Self::construct_tree_rec(iv, left_node_value, tree_length + 1, tree_length_to_be);
            let (right_left_node, right_right_node) = Self::construct_tree_rec(iv, right_node_value, tree_length + 1, tree_length_to_be);
            let left_tree_node = Tree_node { value: Some(left_node_value), left: Some(Box::from(left_left_node)), right: Some(Box::from(left_right_node)) };
            let right_tree_node = Tree_node { value: Some(right_node_value), left: Some(Box::from(right_left_node)), right: Some(Box::from(right_right_node)) };
            (Node(Box::from(left_tree_node)), Node(Box::from(right_tree_node)))
        }
    }

    pub fn get_all_leaf_nodes<const dummy_size: usize>(tree: &Self) -> [[u8; 16]; dummy_size] {     //TODO: verify length
        fn helper(t: &Tree, leaves: &mut [[u8; 16]; dummy_size]) {      //TODO: verify length
            match t {
                Leaf(Some(v)) => leaves.push(*v),
                Leaf(None) => {}
                Node(node) => {
                    if let Some(left) = &node.left {
                        helper(left, leaves);
                    }
                    if let Some(right) = &node.right {
                        helper(right, leaves);
                    }
                }
            }
        }
        let mut leaves = [[0u8; 16]; dummy_size];        //TODO: verify length
        helper(&tree, &mut leaves);
        leaves
    }


    //done
    pub fn get_cop<const dummy_n: usize, const dummy_m: usize>(b: [u8; dummy_n], tre: Self, d: i128) -> [[u8; 16]; dummy_m] { //TODO: verify length

        const dummy_len: usize = 42;        //TODO: NO USE DUMMY

        fn get_cop_helper<const dummy_a: usize, const dummy_b: usize>(b: u64, tre: &Tree, mut acc: [[u8; 16]; dummy_a], level: i128, height_of_tree: i128) -> [[u8; 16]; dummy_b] {
            let is_left;
            if level == height_of_tree + 1 {
                is_left = true;
            } else {
                is_left = Tree::if_left_at_index_at_level(b, level, height_of_tree);
            }

            let mut i = acc.len();
            // might have made a mistake therefore !
            match tre {
                Leaf(Some(_v)) => { acc },
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(_v), left: Some(ln), right: Some(rn) } => {
                            if is_left {
                                acc[i] = Tree::get_value_of_node(rn).unwrap();
                                i += 1;
                                get_cop_helper::<acc.len(), dummy_len>(b, ln, acc, level + 1, height_of_tree)       //TODO: verify length
                            } else {
                                acc[i] = Tree::get_value_of_node(ln).unwrap();
                                i += 1;
                                get_cop_helper::<acc.len(), dummy_len>(b, rn, acc, level + 1, height_of_tree)       //TODO: verify length
                            }
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        }
        let cop: [[u8; 16]; b.len()] = [[0u8; 16]; b.len()];        //TODO: beware inital zeroes
        let _length_of_b = b.len() as u64;
        let value_of_b = num_rec(b, d as u64);

        get_cop_helper::<cop.len(), dummy_len>(value_of_b, &tre, cop, 1, d)
    }
    // got a bunch of overflows, so changed it to use an accumulator, and not so much recursion
    pub fn get_leaves_from_cop_and_b<const dummy_n: usize, const dummy_m: usize>(b: u64, cop: [[u8; 16]; dummy_n], iv: [u8; 16]) -> [Option<[u8; 16]>; dummy_m] {
        const dummy_len: usize = 42;               //TODO: dumb dummy
        let mut leaves_acc: [Option<[u8; 16]>; dummy_len] = [None; dummy_len];        //TODO: beware initial Nones & verify length
        let length_of_cop = cop.len() as u64;
        let cop_len_minus_1 = length_of_cop - 1;
        let is_b_left = Self::if_left_at_index_at_level(b, length_of_cop as i128, length_of_cop as i128);
        for i in (0..cop_len_minus_1).rev() {
            let tre = Self::construct_tree_at_certain_levels(cop[i as usize], iv, ((cop_len_minus_1 - 1) - i) as i128);
            let is_left_compared_to_b = Self::if_left_at_index_at_level(b, (i + 1) as i128, cop.len() as i128);
            let leaves = Self::get_all_leaf_nodes(&tre);

            let mut acc = 0;
            for l in leaves {
                if is_left_compared_to_b {
                    leaves_acc[leaves_acc.size()] = Some(l);
                } else {
                    leaves_acc.insert(acc, Some(l));            //TODO: this needs complete rewrite
                    acc += 1;
                }
            }
        }

        //TODO: this needs complete rewrite
        if is_b_left {
            leaves_acc.insert(b as usize, None);
            leaves_acc.insert((b + 1) as usize, Some(cop[cop.len() - 1]));
        } else {
            leaves_acc.insert((b - 1) as usize, Some(cop[cop.len() - 1]));
            leaves_acc.insert(b as usize, None);
        }


        leaves_acc
    }


    fn if_left_at_index_at_level(b: u64, level: i128, d: i128) -> bool {
        (b >> (d - level)) & 1 == 0
    }

    fn construct_tree_at_certain_levels(r: [u8; 16], iv: [u8; 16], levels: i128) -> Self {
        let (root_left_node, root_right_node) = Tree::construct_tree_rec(iv, r, 0, levels);
        let root_tree_node = Tree_node {
            value: Some(r),
            left: Some(Box::from(root_left_node)), right: Some(Box::from(root_right_node))
        };
        let tree = Node(Box::from(root_tree_node));
        tree
    }

    fn get_value_of_node(tre: &Self) -> Option<[u8; 16]> {
        match tre {
            Leaf(Some(v)) => Some(*v),
            Node(node) => match &**node {
                Tree_node { value: Some(v), left: Some(_ln), right: Some(_rn) } => {
                    Some(*v)
                }
                _ => unreachable!()
            }
            _ => None
        }
    }
}

 */
