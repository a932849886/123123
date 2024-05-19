#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <chk/pkgchk.h>
#include <crypt/sha256.h>
#include <tree/merkletree.h>

// PART 1


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

    char buffer[1024];
    char* pos;
    while (fgets(buffer, sizeof(buffer), file)) {
        if ((pos = strchr(buffer, '\n')) != NULL) {
            *pos = '\0';
        }

        if (strncmp(buffer, "chunks:", 7) == 0 || strncmp(buffer, "hashes:", 7) == 0) {
            continue;
        }

        while (*buffer == ' ') {
            memmove(buffer, buffer + 1, strlen(buffer));
        }

        if (strncmp(buffer, "ident:", 6) == 0) {
            obj->ident = strdup(buffer + 6);
        } else if (strncmp(buffer, "filename:", 9) == 0) {
            obj->filename = strdup(buffer + 9);
        } else if (strncmp(buffer, "size:", 5) == 0){
            obj->size = strtoul(buffer + 5, NULL, 10);
        } else if (strncmp(buffer, "nhashes:", 8) == 0) {
            obj->nhashes = strtoul(buffer + 8, NULL, 10);
            obj->hashes = malloc(obj->nhashes * sizeof(char*));
            for (size_t i = 0; i < obj->nhashes; i++) {
                if (fgets(buffer, sizeof(buffer), file)) {
                    if ((pos = strchr(buffer, '\n')) != NULL) {
                        *pos = '\0';
                    }
                    while (*buffer == '\t') {
                        memmove(buffer, buffer + 1, strlen(buffer));
                    }
                    obj->hashes[i] = strdup(buffer);
                }
            }
        } else if (strncmp(buffer, "nchunks:", 8) == 0) {
            obj->nchunks = strtoul(buffer + 8, NULL, 10);
            obj->chunks = malloc(obj->nchunks * sizeof(struct chunk));
            for (size_t i = 0; i < obj->nchunks; i++) {
                if (fgets(buffer, sizeof(buffer), file)) {
                    if ((pos = strchr(buffer, '\n')) != NULL) {
                        *pos = '\0';
                    }
                    while (*buffer == '\t') {
                        memmove(buffer, buffer + 1, strlen(buffer));
                    }
                    sscanf(buffer, "%64[^,],%zu,%zu", obj->chunks[i].hash, &obj->chunks[i].offset, &obj->chunks[i].size);
                }
            }
        }


    }
    
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
        strcpy(result.hashes[0], "File not Exist");
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
    qry.len = bpkg->nhashes;
    qry.hashes = malloc(qry.len * sizeof(char*));

    for (size_t i = 0; i < qry.len; i++) {
        qry.hashes[i] = strdup(bpkg->hashes[i]);
    }
    
    return qry;
}

/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(struct bpkg_obj* bpkg) { 
    struct bpkg_query qry = { 0 };
    qry.len = bpkg->nchunks;
    qry.hashes = malloc(qry.len * sizeof(char*));

    for (size_t i = 0; i < bpkg->nchunks; i++) {
        qry.hashes[i] = strdup(bpkg->chunks[i].hash);
    }

    return qry;
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
    qry.len = 0;
    qry.hashes = malloc((bpkg->nhashes + bpkg->nchunks) * sizeof(char*));

    int* completed_chunks = calloc(bpkg->nchunks, sizeof(int));
    for (size_t i = 0; i < bpkg->nchunks; i++) {
        completed_chunks[i] = 1;
    }

    size_t min_hashes_count = 0;
    for (size_t i = 0; i < bpkg->nhashes; i++) {
        int completed_or_not = 1;
        for (size_t j = 0; j < bpkg->nchunks; j++) {
            if (completed_chunks[j] == 0) {
                completed_or_not = 0;
                break;
            }
        }
        if (completed_or_not) {
            qry.hashes[min_hashes_count++] = strdup(bpkg->hashes[i]);
        }
    }

    for (size_t i = 0; i < bpkg->nchunks; i++) {
        if (completed_chunks[i]) {
            qry.hashes[min_hashes_count++] = strdup(bpkg->chunks[i].hash);
        }
    }

    qry.len = min_hashes_count;
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
        free(obj);
    }

}


