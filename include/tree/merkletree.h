#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stddef.h>

#define SHA256_HEXLEN (64)

struct merkle_tree_node {
    void* key;
    void* value;
    struct merkle_tree_node* left;
    struct merkle_tree_node* right;
    int is_leaf;
    char expected_hash[SHA256_HEXLEN];
    char computed_hash[SHA256_HEXLEN];
};


struct merkle_tree {
    struct merkle_tree_node* root;
    size_t n_nodes;
};

struct merkle_tree* initializtion_merkle_tree();
void free_merkle_tree_node(struct merkle_tree_node *node);
void free_merkle_tree(struct merkle_tree *tree);
struct merkle_tree_node* create_merkle_tree_node(const char *expected_hash, int is_leaf);
void compute_SHA256_hash(const char *data, size_t len, char *output);
struct merkle_tree_node* insert_node(struct merkle_tree *tree, struct merkle_tree_node *node);
void compute_hash_not_leaf(struct merkle_tree_node *node);
void compute_hash_all_nodes(struct merkle_tree_node *node);
int check_merkle_tree(struct merkle_tree *tree);


#endif
