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

pub fn get_all_leaf_nodes(tree: Tree) -> Vec<[u8; 16]> {
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
        if is_left {
            match tre {
                Leaf(Some(v)) => { acc.push(*v); acc },
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(v), left: Some(ln), right: rn } => {
                            acc.push(*v);
                            get_cop_helper(b, ln, acc, level + 1)
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        } else {
            match tre {
                Leaf(Some(v)) => { acc.push(*v); acc },
                Node(node) => {
                    match &**node {
                        Tree_node { value: Some(v), left: Some(ln), right: rn } => {
                            acc.push(*v);
                            get_cop_helper(b, ln, acc, level + 1)
                        }
                        _ => unreachable!()
                    }
                },
                _ => unreachable!()
            }
        }
    }
    let cop: Vec<[u8; 16]> = Vec::with_capacity(8);
    get_cop_helper(b, &tre, cop,0)
}

pub fn get_tree_from_cop_and_b(b: u8, cop: Vec<[u8; 16]>, iv: [u8;16]) -> Tree {
    fn get_tree_from_cop_and_b_helper(b: u8, cop: Vec<[u8; 16]>, current_level: i128,iv: [u8;16]) -> Tree {
        let node: Tree_node;
        let node_from_cop :  Option<Box<Tree>>;
        let node_unknown :  Option<Box<Tree>>;
        if current_level == 7 {
            node_from_cop = Some(Box::from(Leaf(Some(cop[current_level as usize]))));
                node_unknown = Some(Box::from(Leaf(None)));
        } else {
            node_from_cop = Some(Box::from(construct_tree_at_certain_levels(cop[current_level as usize], iv, 7 - current_level)));
            node_unknown = Some(Box::from(get_tree_from_cop_and_b_helper(b, cop, current_level+1, iv)));
        }
        if if_left_at_index_at_level(b, current_level){
                node = Tree_node {
                    value: None, left: node_from_cop, right: node_unknown
                };
                Node(Box::from(node))

        } else {
            node = Tree_node {
                value: None, left: node_unknown, right: node_from_cop
            };
            Node(Box::from(node))
        }
    }
    get_tree_from_cop_and_b_helper(b, cop, 0, iv)
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

        if tree_length_to_be == 6 {
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