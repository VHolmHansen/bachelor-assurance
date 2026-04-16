use std::thread::current;
use crate::utils::galois_field;
use crate::utils::preliminary_helper_methods::num_rec;
use crate::utils::prg::prg;
use crate::utils::types::Tree::{Leaf, Node};

pub type Word = [u8; 4];
pub type Matrix<T> = Vec<Vec<T>>;

const nk: usize = 4;            // code dup
const nst: usize = 4;           // code dup
pub const lambda: usize = 128;
pub const ell : usize = (1600 + 2*128 + 16)/8;
pub const tau : usize = 11;
pub const k_0 : usize = 12;
pub const k_1 : usize = 11;
pub const tau_0 : usize = 7;
pub const tau_1 : usize = 4;
pub type State = [[u8; nst]; nk];

pub const S_ke : usize = (56-(lambda as i128/8)+28 * (lambda as i128/256)) as usize;


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


pub fn construct_tree(r: [u8; 16], iv: [u8; 16], wanted_length: i128) -> Tree {
    fn construct_tree_rec(iv: [u8; 16], r: [u8; 16], tree_length: i128, wanted_length :i128) -> (Tree, Tree) {
        let mut nodes = [0u8; 32];
        prg(r, iv, &mut nodes);
        let left_node_value = nodes[..16].try_into().unwrap();
        let right_node_value = nodes[16..].try_into().unwrap();

        if tree_length == wanted_length {
            (Leaf(Some(left_node_value)), Leaf(Some(right_node_value)))
        } else {
            let (left_left_node, left_right_node) = construct_tree_rec(iv, left_node_value, tree_length + 1, wanted_length);
            let (right_left_node, right_right_node) = construct_tree_rec(iv, right_node_value, tree_length + 1, wanted_length);
            let left_tree_node = Tree_node {value: Some(left_node_value), left: Some(Box::from(left_left_node)), right: Some(Box::from(left_right_node))};
            let right_tree_node = Tree_node {value: Some(right_node_value), left: Some(Box::from(right_left_node)), right: Some(Box::from(right_right_node))};
            (Node(Box::from(left_tree_node)), Node(Box::from(right_tree_node)))
        }
    }
    // if i want a tree of size 8, the typical with 128 leaves, then i want to call the inner function with wanted_length=7
    // because the root is made outside
    let (root_left_node, root_right_node) = construct_tree_rec(iv, r, 0, wanted_length-1);
    let root_tree_node = Tree_node {
        value: Some(r), left: Some(Box::from(root_left_node)), right: Some(Box::from(root_right_node))
    };
    let tree = Node(Box::from(root_tree_node));
    tree
}

pub fn get_all_leaf_nodes(tree: &Tree) -> Vec<[u8; 16]> {
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

pub fn get_cop(b: Vec<u8>, tre: Tree, d : i128) -> Vec<[u8; 16]> {
    fn get_cop_helper(b: u64, tre: &Tree, mut acc: Vec<[u8; 16]>, level : i128, height_of_tree : i128) -> Vec<[u8; 16]> {
        let is_left;
        if level == height_of_tree+1 {
            is_left = true;
        } else {
            is_left = if_left_at_index_at_level(b, level, height_of_tree);
        }

        // might have made a mistake therefore !
        if is_left {
            match tre {
                Leaf(Some(v)) => { acc},
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(v), left: Some(ln), right: Some(rn) } => {
                            acc.push(get_value_of_node(rn).unwrap());
                            get_cop_helper(b, ln, acc, level + 1, height_of_tree)
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        } else {
            match tre {
                Leaf(Some(v)) => { acc},
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(v), left: Some(ln), right: Some(rn) } => {
                            acc.push(get_value_of_node(ln).unwrap());
                            get_cop_helper(b, rn, acc, level + 1, height_of_tree)
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        }
    }
    let cop: Vec<[u8; 16]> = Vec::with_capacity(b.len());
    let length_of_b = b.len() as u64;
    let value_of_b = num_rec(b, d as u64);

    get_cop_helper(value_of_b, &tre, cop,1, d)
}
// got a bunch of overflows, so changed it to use an accumulator, and not so much recursion
pub fn get_leaves_from_cop_and_b(b: u64, cop: Vec<[u8; 16]>, iv: [u8;16]) -> Vec<Option<[u8; 16]>> {
    let mut leaves_acc : Vec<Option<[u8; 16]>> = Vec::new();
    let length_of_cop = cop.len() as u64;
    let cop_len_minus_1 = length_of_cop - 1;
    let is_b_left = if_left_at_index_at_level(b, length_of_cop as i128, length_of_cop as i128);
    for i in (0..cop_len_minus_1).rev(){
        let tre = construct_tree_at_certain_levels(cop[i as usize], iv, ((cop_len_minus_1-1) - i) as i128);
        let is_left_compared_to_b = if_left_at_index_at_level(b, (i + 1) as i128, cop.len() as i128);
        let leaves = get_all_leaf_nodes(&tre);

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
        leaves_acc.insert((b+1) as usize, Some(cop[cop.len()-1]));
    } else {
        leaves_acc.insert((b-1) as usize, Some(cop[cop.len()-1]));
        leaves_acc.insert(b as usize, None);
    }


    leaves_acc
}


fn if_left_at_index_at_level(b: u64, level: i128, d : i128) -> bool {
    (b >> (d - level)) & 1 == 0
}

fn construct_tree_at_certain_levels(r: [u8; 16], iv: [u8; 16], levels: i128) -> Tree {
    fn construct_tree_rec(iv: [u8; 16], r: [u8; 16], tree_length: i128, tree_length_to_be: i128) -> (Tree, Tree){
        let mut nodes = [0u8; 32];
        prg(r, iv, &mut nodes);
        let left_node_value = nodes[..16].try_into().unwrap();
        let right_node_value = nodes[16..].try_into().unwrap();

        if tree_length == tree_length_to_be {
            (Leaf(Some(left_node_value)), Leaf(Some(right_node_value)))
        } else {
            let (left_left_node, left_right_node) = construct_tree_rec(iv, left_node_value, tree_length + 1, tree_length_to_be);
            let (right_left_node, right_right_node) = construct_tree_rec(iv, right_node_value, tree_length + 1, tree_length_to_be);
            let left_tree_node = Tree_node {value: Some(left_node_value), left: Some(Box::from(left_left_node)), right: Some(Box::from(left_right_node))};
            let right_tree_node = Tree_node {value: Some(right_node_value), left: Some(Box::from(right_left_node)), right: Some(Box::from(right_right_node))};
            (Node(Box::from(left_tree_node)), Node(Box::from(right_tree_node)))
        }
    }

    let (root_left_node, root_right_node) = construct_tree_rec(iv, r, 0, levels);
    let root_tree_node = Tree_node {
        value: Some(r), left: Some(Box::from(root_left_node)), right: Some(Box::from(root_right_node))
    };
    let tree = Node(Box::from(root_tree_node));
    tree
}

fn get_value_of_node(tre: &Tree) -> Option<[u8; 16]> {
    match tre {
        Leaf(Some(v)) => Some(*v),
        Node(node) => match &**node {
            Tree_node { value: Some(v), left: Some(ln), right: Some(rn) } => {
                Some(*v)
            }
            _ => unreachable!()
        }
        _ => None
    }
}