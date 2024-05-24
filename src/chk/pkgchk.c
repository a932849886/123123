#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <chk/pkgchk.h>
#include <crypt/sha256.h>
#include <tree/merkletree.h>

// PART 1

struct node_level {
    struct merkle_tree_node* node;
    int level;
};

void connect_nodes(struct node_level* nodes, size_t index, struct merkle_tree_node* node, int level) {
    nodes[index].node = node;
    nodes[index].level = level;

    if (index > 0) {
        size_t parent_index = (index - 1) / 2;
        if (nodes[parent_index].level == level - 1) {
            if ((index - 1) % 2 == 0) {
                nodes[parent_index].node->left = node;
            } else {
                nodes[parent_index].node->right = node;
            }
        }
    }
}

/**
 * Loads the package for when a valid path is given
 */
struct bpkg_obj* bpkg_load(const char* path) {
    FILE* file = fopen(path, "r");
    if (!file) {
        return NULL;
    }

    struct bpkg_obj* obj = (struct bpkg_obj*)malloc(sizeof(struct bpkg_obj));
    if (!obj) {
        fclose(file);
        return NULL;
    }
    memset(obj, 0, sizeof(struct bpkg_obj));

    struct merkle_tree* tree = initializtion_merkle_tree();
    if (!tree) {
        free(obj);
        fclose(file);
        return NULL;
    }

    obj->tree = tree;

    char buffer[1024];
    char* pos;
    size_t hash_index = 0, chunk_index = 0;
    struct node_level* nodes = NULL;
    int level = 0;
    int nodes_current_level = 1;
    int nodes_proccessed_level = 0;

    while (fgets(buffer, sizeof(buffer), file)) {
        if ((pos = strchr(buffer, '\n')) != NULL) {
            *pos = '\0';
        }

        while (*buffer == ' ') {
            memmove(buffer, buffer + 1, strlen(buffer));
        }

        if (strncmp(buffer, "ident:", 6) == 0) {
            obj->ident = strdup(buffer + 6);
            if (!obj->ident) {
                free_merkle_tree(tree);
                free(obj);
                fclose(file);
                return NULL;
            }
        } else if (strncmp(buffer, "filename:", 9) == 0) {
            obj->filename = strdup(buffer + 9);
            if (!obj->filename) {
                free(obj->ident);
                free_merkle_tree(tree);
                free(obj);
                fclose(file);
                return NULL;
            }
        } else if (strncmp(buffer, "size:", 5) == 0){
            obj->size = strtoul(buffer + 5, NULL, 10);
        } else if (strncmp(buffer, "nhashes:", 8) == 0) {
            obj->nhashes = strtoul(buffer + 8, NULL, 10);
            obj->hashes = malloc(obj->nhashes * sizeof(char*));
            if (!obj->hashes) {
                free(obj->ident);
                free(obj->filename);
                free_merkle_tree(tree);
                free(obj);
                fclose(file);
                return NULL;
            }
            fgets(buffer, sizeof(buffer), file);
            nodes = malloc(obj->nhashes * sizeof(struct node_level));
            if (!nodes) {
                free(obj->hashes);
                free(obj->ident);
                free(obj->filename);
                free_merkle_tree(tree);
                free(obj);
                fclose(file);
                return NULL;
            }
            level = 0;
            for (size_t i = 0; i < obj->nhashes; i++) {
                if (fgets(buffer, sizeof(buffer), file)) {
                    if ((pos = strchr(buffer, '\n')) != NULL) {
                        *pos = '\0';
                    }
                    while (*buffer == '\t') {
                        memmove(buffer, buffer + 1, strlen(buffer));
                    }
                    char *hash = strtok(buffer, " ");
                    obj->hashes[hash_index++] = strdup(hash);

                    struct merkle_tree_node* node = create_merkle_tree_node(obj->hashes[i], 0);
                    insert_node(tree, node);
                    connect_nodes(nodes, i, node, level);
                    
                    nodes_proccessed_level++;
                    if (nodes_proccessed_level == nodes_current_level) {
                        level++;
                        nodes_current_level *= 2;
                        nodes_proccessed_level = 0;
                    }
                }
            }
        } else if (strncmp(buffer, "nchunks:", 8) == 0) {
            obj->nchunks = strtoul(buffer + 8, NULL, 10);
            struct node_level* new_nodes = realloc(nodes, (obj->nhashes + obj->nchunks) * sizeof(struct node_level));
            if (!new_nodes) {
                for (size_t i = 0; i < obj->nhashes; i++) {
                    free(obj->hashes[i]);
                }
                free(obj->hashes);
                free(obj->ident);
                free(obj->filename);
                free_merkle_tree(tree);
                free(nodes);
                free(obj);
                fclose(file);
                return NULL;
            }
            nodes = new_nodes;
            obj->chunks = malloc(obj->nchunks * sizeof(struct chunk));
            if (!obj->chunks) {
                for (size_t i = 0; i < obj->nhashes; i++) {
                    free(obj->hashes[i]);
                }
                free(obj->hashes);
                free(obj->ident);
                free(obj->filename);
                free_merkle_tree(tree);
                free(nodes);
                free(obj);
                fclose(file);
                return NULL;
            }
            fgets(buffer, sizeof(buffer), file);
            for (size_t i = 0; i < obj->nchunks; i++) {
                if (fgets(buffer, sizeof(buffer), file)) {
                    if ((pos = strchr(buffer, '\n')) != NULL) {
                        *pos = '\0';
                    }
                    while (*buffer == '\t') {
                        memmove(buffer, buffer + 1, strlen(buffer));
                    }
                    size_t offset, size;
                    char hash[SHA256_HEXLEN + 1];
                    sscanf(buffer, "%64[^,],%zu,%zu", hash, &offset, &size);

                    obj->chunks[chunk_index].offset = offset;
                    obj->chunks[chunk_index].size = size;
                    strncpy(obj->chunks[chunk_index].hash, hash, SHA256_HEXLEN);

                    struct merkle_tree_node* node = create_merkle_tree_node(obj->chunks[chunk_index].hash, 1);
                    insert_node(tree, node);
                    connect_nodes(nodes, hash_index + chunk_index, node, level + 1);
                    chunk_index++;
                }
            }
        }


    }

    size_t last_level_start = obj->nhashes - (1 << (level -1));
    for (size_t i = 0; i < obj->nchunks / 2; i++) {
        size_t hash_idx = last_level_start + (i / 2);
        if (i % 2 == 0) {
            nodes[hash_idx].node->left = nodes[obj->nhashes + i].node;
        } else {
            nodes[hash_idx].node->right = nodes[obj->nhashes + i].node;
        }
    }
    
    free(nodes);
    fclose(file);
    return obj;
}

/**
 * Checks to see if the referenced filename in the bpkg file
 * exists or not.
 * @param bpkg, constructed bpkg object
 * @return query_result, a single string should be
 *      printable in hashes with len sized to 1.
 * 		If the file exists, hashes[0] should contain "File Exists"
 *		If the file does not exist, hashes[0] should contain "File Created"
 */
struct bpkg_query bpkg_file_check(struct bpkg_obj* bpkg) {
    struct bpkg_query result;
    result.len = 1;
    result.hashes = malloc(sizeof(char*));
    result.hashes[0] = malloc(64);

    FILE* file = fopen(bpkg->filename, "r");
    if (file) {
        fclose(file);
        strcpy(result.hashes[0], "File Exists");
    } else {
        file = fopen(bpkg->filename, "w");
        if (file) {
            fclose(file);
            strcpy(result.hashes[0], "File Created");
        }
    }

    return result;
};

/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_hashes(struct bpkg_obj* bpkg) {
    struct bpkg_query qry = { 0 };
    qry.len = bpkg->nhashes + bpkg->nchunks;
    qry.hashes = malloc(qry.len * sizeof(char*));
    if (!qry.hashes) {
        return qry;
    }

    size_t index = 0;

    for (size_t i = 0; i < bpkg->nhashes; i++) {
        qry.hashes[index++] = strdup(bpkg->hashes[i]);
    }

    for (size_t i = 0; i < bpkg->nchunks; i++) {
        qry.hashes[index++] = strdup(bpkg->chunks[i].hash);
    }
    
    return qry;
}


int validate_chunk(struct chunk* chunk, const char* data, size_t data_len) {
    char computed_hash[SHA256_HEXLEN + 1];
    compute_SHA256_hash(data, data_len, computed_hash);
    return strncmp(chunk->hash, computed_hash, SHA256_HEXLEN) == 0;

};

char* load_data_from_chunk(struct chunk* chunk, const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }

    char* data = (char*)malloc(chunk->size);
    if (!data) {
        fclose(file);
        return NULL;
    }

    fseek(file, chunk->offset, SEEK_SET);
    fread(data, 1, chunk->size, file);
    fclose(file);

    return data;

};

/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(struct bpkg_obj* bpkg) { 
    struct bpkg_query qry = { 0 };
    qry.len = 0;
    qry.hashes = malloc(bpkg->nchunks * sizeof(char*));

    for (size_t i = 0; i < bpkg->nchunks; i++) {
        struct chunk* chunk= &bpkg->chunks[i];
        char* data = load_data_from_chunk(chunk, bpkg->filename);
        if (data && validate_chunk(chunk, data, chunk->size)) {
            qry.hashes[qry.len++] = strdup(chunk->hash);
        }
        free(data);

    }

    if (qry.len > 0) {
        qry.hashes = realloc(qry.hashes, qry.len * sizeof(char*));
    } else {
        free(qry.hashes);
        qry.hashes = NULL;
    }
    return qry;

}

void compute_non_leaf_hash(const char* left, const char* right, char* output) {
    char combined[2 * SHA256_HEXLEN + 1];
    snprintf(combined, sizeof(combined), "%s%s", left, right);
    compute_SHA256_hash(combined, strlen(combined), output);
}

/**
 * Gets only the required/min hashes to represent the current completion state
 * Return the smallest set of hashes of completed branches to represent
 * the completion state of the file.
 *
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_min_completed_hashes(struct bpkg_obj* bpkg) {
    struct bpkg_query qry = { 0 };
    size_t numOfnodes = bpkg->nchunks + bpkg->nhashes;
    qry.hashes = malloc(numOfnodes * sizeof(char*));
    size_t min_hashes_count = 0;

    int* completed_chunks = calloc(bpkg->nchunks, sizeof(int));
    for (size_t i = 0; i < bpkg->nchunks; i++) {
        struct chunk* chunk = &bpkg->chunks[i];
        char* data = load_data_from_chunk(chunk, bpkg->filename);
        if (data && validate_chunk(chunk, data, chunk->size)) {
            completed_chunks[i] = 1;
        }
        free(data);
    }

    for (size_t i = 0; i < bpkg->nhashes; i++) {
        char left_hash[SHA256_HEXLEN + 1];
        char right_hash[SHA256_HEXLEN + 1];
        char computed_hash[SHA256_HEXLEN + 1];

        size_t left_index = 2 * i + 1;
        size_t right_index = 2 * i + 2;

        if (left_index < bpkg->nchunks && right_index < bpkg->nchunks &&
            completed_chunks[left_index] && completed_chunks[right_index]) {
            strncpy(left_hash, bpkg->chunks[left_index].hash, SHA256_HEXLEN);
            strncpy(right_hash, bpkg->chunks[right_index].hash, SHA256_HEXLEN);
            compute_non_leaf_hash(left_hash, right_hash, computed_hash);

            if (strncmp(bpkg->hashes[i], computed_hash, SHA256_HEXLEN) == 0) {
                qry.hashes[min_hashes_count++] = strdup(bpkg->hashes[i]);
            }
        }

    }

    for (size_t i = 0; i < bpkg->nchunks; i++) {
        if (completed_chunks[i]) {
            qry.hashes[min_hashes_count++] = strdup(bpkg->chunks[i].hash);
        }
    }

    qry.len = min_hashes_count;
    qry.hashes = realloc(qry.hashes, qry.len * sizeof(char*));
    free(completed_chunks);

    return qry;
}


/**
 * Retrieves all chunk hashes given a certain an ancestor hash (or itself)
 * Example: If the root hash was given, all chunk hashes will be outputted
 * 	If the root's left child hash was given, all chunks corresponding to
 * 	the first half of the file will be outputted
 * 	If the root's right child hash was given, all chunks corresponding to
 * 	the second half of the file will be outputted
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(struct bpkg_obj* bpkg, 
    char* hash) {
    
    struct bpkg_query qry = { 0 };
    qry.len = 0;
    qry.hashes = NULL;

    for (size_t i = 0; i < bpkg->nchunks; i++) {
        if (strcmp(bpkg->chunks[i].hash, hash) == 0) {
            qry.len++;
            qry.hashes = malloc(sizeof(char*));
            qry.hashes[0] = strdup(bpkg->chunks[i].hash);
            break;
        }
    }

    return qry;
}


/**
 * Deallocates the query result after it has been constructed from
 * the relevant queries above.
 */
void bpkg_query_destroy(struct bpkg_query* qry) {
    for (size_t i = 0; i < qry->len; i++) {
        free(qry->hashes[i]);
    }
    free(qry->hashes);
    qry->hashes = NULL;
    qry->len = 0;

}

/**
 * Deallocates memory at the end of the program,
 * make sure it has been completely deallocated
 */
void bpkg_obj_destroy(struct bpkg_obj* obj) {
    if (obj) {
        free(obj->ident);
        free(obj->filename);
        for (size_t i = 0; i < obj->nhashes; i++) {
            free(obj->hashes[i]);
        }
        free(obj->hashes);
        free(obj->chunks);
        free_merkle_tree(obj->tree);
        free(obj);
    }

}


