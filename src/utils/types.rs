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


fn construct_tree(r: [u8; 16], iv: [u8; 16]) -> Tree {
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

fn get_all_leaf_nodes(tree: Tree) -> Vec<[u8; 16]> {
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

