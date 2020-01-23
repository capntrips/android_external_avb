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

#include <libavb/avb_crypto.h>
#include <libavb/avb_rsa.h>
#include <libavb/avb_sha.h>
#include <libavb/avb_util.h>

#include "avb_aftl_types.h"
#include "avb_aftl_util.h"
#include "avb_aftl_validate.h"

/* Performs a SHA256 hash operation on data. */
bool avb_aftl_sha256(uint8_t* data,
                     uint64_t length,
                     uint8_t hash[AFTL_HASH_SIZE]) {
  AvbSHA256Ctx context;
  uint8_t* tmp;

  if ((data == NULL) && (length != 0)) return false;

  avb_sha256_init(&context);
  avb_sha256_update(&context, data, length);
  tmp = avb_sha256_final(&context);
  avb_memcpy(hash, tmp, AFTL_HASH_SIZE);
  return true;
}

/* Calculates a SHA256 hash of the TrillianLogRootDescriptor in icp_entry.

   The hash is calculated over the entire TrillianLogRootDescriptor
   structure. Some of the fields in this implementation are dynamically
   allocated, and so the data needs to be reconstructed so that the hash
   can be properly calculated. The TrillianLogRootDescriptor is defined
   here: https://github.com/google/trillian/blob/master/trillian.proto#L255 */
bool avb_aftl_hash_log_root_descriptor(AftlIcpEntry* icp_entry, uint8_t* hash) {
  uint8_t* buffer;
  uint8_t* lrd_offset; /* Byte offset into the descriptor. */
  uint32_t tlrd_size;
  bool retval;

  avb_assert(icp_entry != NULL && hash != NULL);

  /* Size of the non-pointer elements of the TrillianLogRootDescriptor. */
  tlrd_size = sizeof(uint16_t) * 2 + sizeof(uint64_t) * 3 + sizeof(uint8_t);
  /* Ensure the log_root_descriptor size is correct. */
  if (icp_entry->log_root_descriptor_size > AFTL_MAX_LOG_ROOT_DESCRIPTOR_SIZE) {
    avb_error("Invalid log root descriptor size.\n");
    return false;
  }
  if (icp_entry->log_root_descriptor_size !=
      (tlrd_size + icp_entry->log_root_descriptor.root_hash_size +
       icp_entry->log_root_descriptor.metadata_size)) {
    avb_error("Log root descriptor size doesn't match fields.\n");
    return false;
  }
  /* Check that the root_hash exists, and if not, it's size is sane. */
  if (!icp_entry->log_root_descriptor.root_hash &&
      (icp_entry->log_root_descriptor.root_hash_size != 0)) {
    avb_error("Invalid tree root hash values.\n");
    return false;
  }

  /* Check that the metadata exists, and if not, it's size is sane. */
  if (!icp_entry->log_root_descriptor.metadata &&
      (icp_entry->log_root_descriptor.metadata_size != 0)) {
    avb_error("Invalid log root descriptor metadata values.\n");
    return false;
  }
  buffer = (uint8_t*)avb_malloc(icp_entry->log_root_descriptor_size);
  if (buffer == NULL) {
    avb_error("Allocation failure in avb_aftl_hash_log_root_descriptor.\n");
    return false;
  }
  lrd_offset = buffer;
  /* Copy in the version, tree_size and root hash length. */
  avb_memcpy(
      lrd_offset, &(icp_entry->log_root_descriptor.version), sizeof(uint16_t));
  lrd_offset += sizeof(uint16_t);
  avb_memcpy(lrd_offset,
             &(icp_entry->log_root_descriptor.tree_size),
             sizeof(uint64_t));
  lrd_offset += sizeof(uint64_t);
  avb_memcpy(lrd_offset,
             &(icp_entry->log_root_descriptor.root_hash_size),
             sizeof(uint8_t));
  lrd_offset += sizeof(uint8_t);
  /* Copy the root hash. */
  if (icp_entry->log_root_descriptor.root_hash_size > 0) {
    avb_memcpy(lrd_offset,
               icp_entry->log_root_descriptor.root_hash,
               icp_entry->log_root_descriptor.root_hash_size);
  }
  lrd_offset += icp_entry->log_root_descriptor.root_hash_size;
  /* Copy in the timestamp, revision, and the metadata length. */
  avb_memcpy(lrd_offset,
             &(icp_entry->log_root_descriptor.timestamp),
             sizeof(uint64_t));
  lrd_offset += sizeof(uint64_t);

  avb_memcpy(
      lrd_offset, &(icp_entry->log_root_descriptor.revision), sizeof(uint64_t));
  lrd_offset += sizeof(uint64_t);

  avb_memcpy(lrd_offset,
             &(icp_entry->log_root_descriptor.metadata_size),
             sizeof(uint16_t));
  lrd_offset += sizeof(uint16_t);

  /* Copy the metadata if it exists. */
  if (icp_entry->log_root_descriptor.metadata_size > 0) {
    avb_memcpy(lrd_offset,
               icp_entry->log_root_descriptor.metadata,
               icp_entry->log_root_descriptor.metadata_size);
  }
  /* Hash the result & clean up. */

  retval = avb_aftl_sha256(buffer, icp_entry->log_root_descriptor_size, hash);
  avb_free(buffer);
  return retval;
}

/* Computes a leaf hash as detailed by https://tools.ietf.org/html/rfc6962. */
bool avb_aftl_rfc6962_hash_leaf(uint8_t* leaf,
                                uint64_t leaf_size,
                                uint8_t* hash) {
  uint8_t* buffer;
  bool retval;

  avb_assert(leaf != NULL && hash != NULL);
  avb_assert(leaf_size != AFTL_ULONG_MAX);

  buffer = (uint8_t*)avb_malloc(leaf_size + 1);

  if (buffer == NULL) {
    avb_error("Allocation failure in avb_aftl_rfc6962_hash_leaf.\n");
    return false;
  }
  /* Prefix the data with a '0' for 2nd preimage attack resistance. */
  buffer[0] = 0;

  if (leaf_size > 0) avb_memcpy(buffer + 1, leaf, leaf_size);

  retval = avb_aftl_sha256(buffer, leaf_size + 1, hash);
  avb_free(buffer);
  return retval;
}

/* Computes an inner hash as detailed by https://tools.ietf.org/html/rfc6962. */
bool avb_aftl_rfc6962_hash_children(uint8_t* left_child,
                                    uint64_t left_child_size,
                                    uint8_t* right_child,
                                    uint64_t right_child_size,
                                    uint8_t* hash) {
  uint8_t* buffer;
  uint64_t data_size;
  bool retval;

  avb_assert(left_child != NULL && right_child != NULL && hash != NULL);

  /* Check for integer overflow. */
  avb_assert(left_child_size < AFTL_ULONG_MAX - right_child_size);

  data_size = left_child_size + right_child_size + 1;
  buffer = (uint8_t*)avb_malloc(data_size);
  if (buffer == NULL) {
    avb_error("Allocation failure in avb_aftl_rfc6962_hash_children.\n");
    return false;
  }

  /* Prefix the data with '1' for 2nd preimage attack resistance. */
  buffer[0] = 1;

  /* Copy the left child data, if it exists. */
  if (left_child_size > 0) avb_memcpy(buffer + 1, left_child, left_child_size);
  /* Copy the right child data, if it exists. */
  if (right_child_size > 0)
    avb_memcpy(buffer + 1 + left_child_size, right_child, right_child_size);

  /* Hash the concatenated data and clean up. */
  retval = avb_aftl_sha256(buffer, data_size, hash);
  avb_free(buffer);
  return retval;
}

/* Computes a subtree hash along tree's right border. */
bool avb_aftl_chain_border_right(uint8_t* seed,
                                 uint64_t seed_size,
                                 uint8_t* proof,
                                 uint32_t proof_entry_count,
                                 uint8_t* hash) {
  size_t i;
  uint8_t* tmp;
  uint8_t* tmp_hash;
  bool retval;

  avb_assert(seed_size == AFTL_HASH_SIZE);
  avb_assert(seed != NULL && proof != NULL && hash != NULL);

  tmp = seed;
  tmp_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  if (tmp_hash == NULL) {
    avb_error("Allocation failure in avb_aftl_chain_border_right.\n");
    return false;
  }
  for (i = 0; i < proof_entry_count; i++) {
    retval = avb_aftl_rfc6962_hash_children(proof + (i * AFTL_HASH_SIZE),
                                            AFTL_HASH_SIZE,
                                            tmp,
                                            AFTL_HASH_SIZE,
                                            tmp_hash);
    if (!retval) {
      avb_error("Failed to hash Merkle tree children.\n");
    }
    tmp = tmp_hash;
  }

  if (retval) avb_memcpy(hash, tmp, AFTL_HASH_SIZE);

  avb_free(tmp_hash);
  return retval;
}

/* Computes a subtree hash on or below the tree's right border. */
bool avb_aftl_chain_inner(uint8_t* seed,
                          uint64_t seed_size,
                          uint8_t* proof,
                          uint32_t proof_entry_count,
                          uint64_t leaf_index,
                          uint8_t* hash) {
  size_t i;
  uint8_t* tmp = seed;
  uint8_t* tmp_hash;
  bool retval;

  avb_assert(seed_size == AFTL_HASH_SIZE);
  avb_assert(seed != NULL && proof != NULL && hash != NULL);

  tmp = seed;
  tmp_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  if (tmp_hash == NULL) {
    avb_error("Allocation failure in avb_aftl_chain_inner.\n");
    return false;
  }
  for (i = 0; i < proof_entry_count; i++) {
    if ((leaf_index >> i & 1) == 0) {
      retval = avb_aftl_rfc6962_hash_children(tmp,
                                              seed_size,
                                              proof + (i * AFTL_HASH_SIZE),
                                              AFTL_HASH_SIZE,
                                              tmp_hash);
    } else {
      retval = avb_aftl_rfc6962_hash_children(proof + (i * AFTL_HASH_SIZE),
                                              AFTL_HASH_SIZE,
                                              tmp,
                                              seed_size,
                                              tmp_hash);
    }
    if (!retval) {
      avb_error("Failed to hash Merkle tree children.\n");
      break;
    }
    tmp = tmp_hash;
  }
  if (retval) avb_memcpy(hash, tmp, AFTL_HASH_SIZE);
  avb_free(tmp_hash);
  return retval;
}

/* Counts leading zeros. Used in Merkle tree hash validation .*/
unsigned int avb_aftl_count_leading_zeros(uint64_t val) {
  int r = 0;
  if (val == 0) return 64;
  if (!(val & 0xffffffff00000000u)) {
    val <<= 32;
    r += 32;
  }
  if (!(val & 0xffff000000000000u)) {
    val <<= 16;
    r += 16;
  }
  if (!(val & 0xff00000000000000u)) {
    val <<= 8;
    r += 8;
  }
  if (!(val & 0xf000000000000000u)) {
    val <<= 4;
    r += 4;
  }
  if (!(val & 0xc000000000000000u)) {
    val <<= 2;
    r += 2;
  }
  if (!(val & 0x8000000000000000u)) {
    val <<= 1;
    r += 1;
  }

  return r;
}

/* Calculates the expected Merkle tree hash. */
bool avb_aftl_root_from_icp(uint64_t leaf_index,
                            uint64_t tree_size,
                            uint8_t proof[][AFTL_HASH_SIZE],
                            uint32_t proof_entry_count,
                            uint8_t* leaf_hash,
                            uint64_t leaf_hash_size,
                            uint8_t* root_hash) {
  uint64_t inner_proof_size;
  uint64_t border_proof_size;
  size_t i;
  uint8_t hash[AFTL_HASH_SIZE];
  uint8_t* inner_proof;
  uint8_t* border_proof;
  bool retval;

  avb_assert(proof_entry_count != 0);
  avb_assert(leaf_hash_size != 0);
  avb_assert(proof != NULL && leaf_hash != NULL && root_hash != NULL);

  /* This cannot overflow. */
  inner_proof_size =
      64 - avb_aftl_count_leading_zeros(leaf_index ^ (tree_size - 1));

  /* Check for integer underflow.*/
  if ((proof_entry_count - inner_proof_size) > proof_entry_count) {
    avb_error("Invalid proof entry count value.\n");
    return false;
  }
  border_proof_size = proof_entry_count - inner_proof_size;
  /* Split the proof into two parts based on the calculated pivot point. */
  inner_proof = (uint8_t*)avb_malloc(inner_proof_size * AFTL_HASH_SIZE);
  if (inner_proof == NULL) {
    avb_error("Allocation failure in avb_aftl_root_from_icp.\n");
    return false;
  }
  border_proof = (uint8_t*)avb_malloc(border_proof_size * AFTL_HASH_SIZE);
  if (border_proof == NULL) {
    avb_free(inner_proof);
    avb_error("Allocation failure in avb_aftl_root_from_icp.\n");
    return false;
  }

  for (i = 0; i < inner_proof_size; i++) {
    avb_memcpy(inner_proof + (AFTL_HASH_SIZE * i), proof[i], AFTL_HASH_SIZE);
  }
  for (i = 0; i < border_proof_size; i++) {
    avb_memcpy(border_proof + (AFTL_HASH_SIZE * i),
               proof[inner_proof_size + i],
               AFTL_HASH_SIZE);
  }

  /* Calculate the root hash and store it in root_hash. */
  retval = avb_aftl_chain_inner(leaf_hash,
                                leaf_hash_size,
                                inner_proof,
                                inner_proof_size,
                                leaf_index,
                                hash);
  if (retval)
    retval = avb_aftl_chain_border_right(
        hash, AFTL_HASH_SIZE, border_proof, border_proof_size, root_hash);

  if (inner_proof != NULL) avb_free(inner_proof);
  if (border_proof != NULL) avb_free(border_proof);
  return retval;
}
