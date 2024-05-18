#include <tree/merkletree.h>
#include <crypt/sha256.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Initialization of the Merkle Tree
struct merkle_tree* initializtion_merkle_tree() {
    struct merkle_tree *tree = malloc(sizeof(struct merkle_tree));
    if (tree) {
        tree->root = NULL;
        tree->n_nodes = 0;
    }
    return tree;
}

// Free the Merkle Tree Nodes
void free_merkle_tree_node(struct merkle_tree_node *node) {
    if (node) {
        free_merkle_tree_node(node->left);
        free_merkle_tree_node(node->right);
        free(node);
    }
}


// Free whole Merkle Tree
void free_merkle_tree(struct merkle_tree *tree) {
    if (tree) {
        free_merkle_tree_node(tree->root);
        free(tree);
    }
}

// Create the Merkle Tree node
struct merkle_tree_node* create_merkle_tree_node(const char *expected_hash, int is_leaf) {
    struct merkle_tree_node *node = malloc(sizeof(struct merkle_tree_node));
    if (node) {
        memset(node, 0, sizeof(struct merkle_tree_node));
        strncpy(node->expected_hash, expected_hash, SHA256_HEXLEN);
        node->expected_hash[SHA256_HEXLEN] = '\0'
        node->is_leaf = is_leaf;
    }
    return node;
}

// Compute SHA256 hash
void compute_SHA256_hash (const char *data, size_t len, char *output) {
    struct sha256_compute_data context;
    sha256_compute_data_init($context);
    sha256_update($context, (void*)data, len);
    sha256_finalize($context, NULL);
    sha256_output_hex($context, output);
}

// Insert node into the Merkle Tree
struct merkle_tree_node* insert_node(struct merkle_tree *tree, struct merkle_tree_node *node) {
    if (!tree->root) {
        tree->root = node;
    } else {
        struct merkle_tree_node *insertion[1024];
        int front = 0, rear = 0;
        insertion[rear++] = tree->root;

        while (front < rear) {
            struct merkle_tree_node *current_insertion = insertion[front++];
            if(!current_insertion->left) {
                current_insertion->left = node;
                break;
            } else if (!current_insertion->right) {
                current_insertion->right = node;
                break;
            } else {
                insertion[rear++] = current_insertion->left;
                insertion[rear++] = current_insertion->right;
            }
        }
    }
    tree->n_nodes++;
    return node;
}

// Compute hash for nodes not leaf
void compute_hash_not_leaf (struct merkle_tree_node *node) {
    if (node->leaf && node->right) {
        char added_hash[2 * SHA256_HEXLEN + 1];
        snprintf(added_hash, sizeof(added_hash), "%s%s", node->left->computed_hash, node->right->computed_hash);
        compute_SHA256_has(added_hash, strlen(added_hash), node->computed_hash);
    }
}

//Compute hash for all nodes
void compute_hash_all_nodes (struct merkle_tree_node *node) {
    if (node->is_leaf) {
        strncpy(node->computed_hash, node->expected_hash, SHA256_HEXLEN);
        node->computed_hash[SHA256_HEXLEN] = '\0';
    } else {
        if (node->left) {
            compute_hash_all_nodes(node->left);
        }
        if (node->right) {
            compute_hash_all_nodes(node->right);
        }
        compute_hash_not_leaf(node);
    }
}

//Check the Merkle Tree
int check_merkle_tree (struct merkle_tree *tree) {
    if (!tree->root) {
        return 0;
    }

    compute_hash_all_nodes(tree->root);

    return strncmp(tree->root->computed_hash, tree->root->expected_hash, SHA256_HEXLEN) == 0;
}





