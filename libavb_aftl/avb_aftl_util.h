/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef AVB_INSIDE_LIBAVB_AFTL_H
#error "You can't include avb_aftl_util.h in the public header libavb_aftl.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_AFTL_UTIL_H_
#define AVB_AFTL_UTIL_H_

#include "avb_aftl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVB_AFTL_MAGIC 0x4c544641
#define avb_aftl_member_size(type, member) sizeof(((type*)0)->member)

/* Performs a SHA256 hash operation on data. */
bool avb_aftl_sha256(
    uint8_t* data,                     /* Data to be hashed. */
    uint64_t length,                   /* Size of data. */
    uint8_t hash[AVB_AFTL_HASH_SIZE]); /* Resulting SHA256 hash. */

/* Calculates a SHA256 hash of the TrillianLogRootDescriptor in icp_entry. */
bool avb_aftl_hash_log_root_descriptor(
    AftlIcpEntry* icp_entry, /* The icp_entry containing the descriptor. */
    uint8_t* hash);          /* The resulting hash of the descriptor data. */

/* RFC 6962 Hashing function for leaves of a Merkle tree. */
bool avb_aftl_rfc6962_hash_leaf(
    uint8_t* leaf,      /* The Merkle tree leaf data to be hashed. */
    uint64_t leaf_size, /* Size of the leaf data. */
    uint8_t* hash);     /* Resulting RFC 6962 hash of the leaf data. */

/* Computes an inner hash as detailed by https://tools.ietf.org/html/rfc6962. */
bool avb_aftl_rfc6962_hash_children(
    uint8_t* left_child,       /* The left child node data. */
    uint64_t left_child_size,  /* Size of the left child node data. */
    uint8_t* right_child,      /* The right child node data. */
    uint64_t right_child_size, /* Size of the right child node data. */
    uint8_t
        hash[AVB_AFTL_HASH_SIZE]); /* Resulting RFC 6962 hash of the children.*/

/* Computes a subtree hash along the left-side tree border. */
bool avb_aftl_chain_border_right(
    uint8_t* seed,              /* Data containing the starting hash. */
    uint64_t seed_size,         /* Size of the starting hash data. */
    uint8_t* proof,             /* The hashes in the inclusion proof. */
    uint32_t proof_entry_count, /* Number of inclusion proof entries. */
    uint8_t* hash);             /* Resulting subtree hash. */

/* Computes a subtree hash on or below the tree's right border. */
bool avb_aftl_chain_inner(
    uint8_t* seed,              /* Data containing the starting hash. */
    uint64_t seed_size,         /* Size of the starting hash data. */
    uint8_t* proof,             /* The hashes in the inclusion proof. */
    uint32_t proof_entry_count, /* Number of inclusion proof entries. */
    uint64_t leaf_index,        /* The current Merkle tree leaf index. */
    uint8_t* hash);             /* Resulting subtree hash. */

/* Counts leading zeros. Used in Merkle tree hash validation .*/
unsigned int avb_aftl_count_leading_zeros(
    uint64_t val); /* Value to count leading zeros of. */

/* Calculates the expected Merkle tree hash. */
bool avb_aftl_root_from_icp(
    uint64_t leaf_index,                 /* The leaf index in the Merkle tree.*/
    uint64_t tree_size,                  /* The size of the Merkle tree. */
    uint8_t proof[][AVB_AFTL_HASH_SIZE], /* Inclusion proof hash data. */
    uint32_t proof_entry_count,          /* Number of inclusion proof hashes. */
    uint8_t* leaf_hash,      /* The leaf hash to prove inclusion of. */
    uint64_t leaf_hash_size, /* Size of the leaf hash. */
    uint8_t* root_hash);     /* The resulting tree root hash. */

/* Allocates and populates an AftlDescriptor from a binary blob. */
AftlDescriptor* parse_aftl_descriptor(uint8_t* aftl_blob,
                                      size_t aftl_blob_size);

/* Allocates and populates an AftlIcpEntry and all sub-fields from
   a binary blob. It is assumed that the blob points to an AftlIcpEntry. */
AftlIcpEntry* parse_icp_entry(uint8_t** aftl_blob, size_t* remaining_size);

/* Frees an AftlIcpEntry and all sub-fields that were previously
   allocated by a call to allocate_icp_entry. */
void free_aftl_icp_entry(AftlIcpEntry* aftl_icp_entry);

/* Frees an AftlDescriptor and all sub-fields that were previously
   allocated by a call to allocate_aftl_descriptor. */
void free_aftl_descriptor(AftlDescriptor* aftl_descriptor);

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_UTIL_H_ */
