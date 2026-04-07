use std::thread::current;
use crate::utils::galois_field;
use crate::utils::prg::prg;
use crate::utils::types::Tree::{Leaf, Node};

pub type Word = [u8; 4];
pub type Matrix<T> = Vec<Vec<T>>;

const nk: usize = 4;            // code dup
const nst: usize = 4;           // code dup
pub type State = [[u8; nst]; nk];


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


pub fn construct_tree(r: [u8; 16], iv: [u8; 16]) -> Tree {
    fn construct_tree_rec(iv: [u8; 16], r: [u8; 16], tree_length: i128) -> (Tree, Tree){
        let nodes:[u8; 32] = prg(r, iv);
        let left_node_value = nodes[..16].try_into().unwrap();
        let right_node_value = nodes[16..].try_into().unwrap();

        if tree_length == 6 {
            (Leaf(Some(left_node_value)), Leaf(Some(right_node_value)))
        } else {
            let (left_left_node, left_right_node) = construct_tree_rec(iv, left_node_value, tree_length + 1);
            let (right_left_node, right_right_node) = construct_tree_rec(iv, right_node_value, tree_length + 1);
            let left_tree_node = Tree_node {value: Some(left_node_value), left: Some(Box::from(left_left_node)), right: Some(Box::from(left_right_node))};
            let right_tree_node = Tree_node {value: Some(right_node_value), left: Some(Box::from(right_left_node)), right: Some(Box::from(right_right_node))};
            (Node(Box::from(left_tree_node)), Node(Box::from(right_tree_node)))
        }
    }

    let (root_left_node, root_right_node) = construct_tree_rec(iv, r, 0);
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

pub fn get_cop(b: u8, tre: Tree) -> Vec<[u8; 16]> {
    fn get_cop_helper(b: u8, tre: &Tree, mut acc: Vec<[u8; 16]>, level : i128) -> Vec<[u8; 16]> {
        let is_left = if_left_at_index_at_level(b, level);
        // might have made a mistake therefore !
        if is_left {
            match tre {
                Leaf(Some(v)) => { acc},
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(v), left: Some(ln), right: Some(rn) } => {
                            acc.push(get_value_of_node(rn).unwrap());
                            get_cop_helper(b, ln, acc, level + 1)
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
                            get_cop_helper(b, rn, acc, level + 1)
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        }
    }
    let cop: Vec<[u8; 16]> = Vec::with_capacity(8);
    get_cop_helper(b, &tre, cop,1)
}
// got a bunch of overflows, so changed it to use an accumulator, and not so much recursion
pub fn get_leaves_from_cop_and_b(b: u8, cop: Vec<[u8; 16]>, iv: [u8;16]) -> Vec<Option<[u8; 16]>> {
    let mut leaves_acc : Vec<Option<[u8; 16]>> = Vec::new();
    let mut current_length = 0;
    let is_b_left = if_left_at_index_at_level(b, 7);
    for i in (0..6).rev(){
        let tre = construct_tree_at_certain_levels(cop[i as usize], iv, 5-i);
        let leaves = get_all_leaf_nodes(&tre);
        for l in leaves {
            if is_b_left {
                if current_length == b {
                    leaves_acc.push(None);
                    leaves_acc.push(Some(cop[6]));
                }
            } else {
                if current_length == b-1{
                    leaves_acc.push(Some(cop[6]));
                    leaves_acc.push(None);
                }
            }
            leaves_acc.push(Some(l));
            current_length += 1;
        }
    }
    leaves_acc
}


fn if_left_at_index_at_level(b: u8, level: i128) -> bool {
    let mut index = b;
    for i in 0..(7-level) {
           if index & 1 == 0 {
               index = 2*index / 4
           } else {
               index = (2*index - 2) / 4
           }
    }

    if index & 1 == 0 {
        return true;
    }
    false
}

fn construct_tree_at_certain_levels(r: [u8; 16], iv: [u8; 16], levels: i128) -> Tree {
    fn construct_tree_rec(iv: [u8; 16], r: [u8; 16], tree_length: i128, tree_length_to_be: i128) -> (Tree, Tree){
        let nodes:[u8; 32] = prg(r, iv);
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