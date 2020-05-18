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
                     uint8_t hash[AVB_AFTL_HASH_SIZE]) {
  AvbSHA256Ctx context;
  uint8_t* tmp;

  if ((data == NULL) && (length != 0)) return false;

  avb_sha256_init(&context);
  avb_sha256_update(&context, data, length);
  tmp = avb_sha256_final(&context);
  avb_memcpy(hash, tmp, AVB_AFTL_HASH_SIZE);
  return true;
}

/* Computes a leaf hash as detailed by https://tools.ietf.org/html/rfc6962. */
bool avb_aftl_rfc6962_hash_leaf(uint8_t* leaf,
                                uint64_t leaf_size,
                                uint8_t* hash) {
  uint8_t* buffer;
  bool retval;

  avb_assert(leaf != NULL && hash != NULL);
  avb_assert(leaf_size != AVB_AFTL_UINT64_MAX);

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
  avb_assert(left_child_size < AVB_AFTL_UINT64_MAX - right_child_size);

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
  uint8_t* tmp_hash;
  uint8_t* tmp = seed;
  bool retval = true;

  avb_assert(seed_size == AVB_AFTL_HASH_SIZE);
  avb_assert(seed != NULL && proof != NULL && hash != NULL);

  tmp_hash = (uint8_t*)avb_malloc(AVB_AFTL_HASH_SIZE);
  if (tmp_hash == NULL) {
    avb_error("Allocation failure in avb_aftl_chain_border_right.\n");
    return false;
  }
  for (i = 0; i < proof_entry_count; i++) {
    retval = avb_aftl_rfc6962_hash_children(proof + (i * AVB_AFTL_HASH_SIZE),
                                            AVB_AFTL_HASH_SIZE,
                                            tmp,
                                            AVB_AFTL_HASH_SIZE,
                                            tmp_hash);
    if (!retval) {
      avb_error("Failed to hash Merkle tree children.\n");
      break;
    }
    tmp = tmp_hash;
  }

  if (retval) avb_memcpy(hash, tmp, AVB_AFTL_HASH_SIZE);

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
  uint8_t* tmp_hash;
  uint8_t* tmp = seed;
  bool retval = true;

  avb_assert(seed_size == AVB_AFTL_HASH_SIZE);
  avb_assert(seed != NULL && proof != NULL && hash != NULL);

  tmp_hash = (uint8_t*)avb_malloc(AVB_AFTL_HASH_SIZE);
  if (tmp_hash == NULL) {
    avb_error("Allocation failure in avb_aftl_chain_inner.\n");
    return false;
  }
  for (i = 0; i < proof_entry_count; i++) {
    if ((leaf_index >> i & 1) == 0) {
      retval = avb_aftl_rfc6962_hash_children(tmp,
                                              seed_size,
                                              proof + (i * AVB_AFTL_HASH_SIZE),
                                              AVB_AFTL_HASH_SIZE,
                                              tmp_hash);
    } else {
      retval = avb_aftl_rfc6962_hash_children(proof + (i * AVB_AFTL_HASH_SIZE),
                                              AVB_AFTL_HASH_SIZE,
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
  if (retval) avb_memcpy(hash, tmp, AVB_AFTL_HASH_SIZE);
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
                            uint8_t proof[][AVB_AFTL_HASH_SIZE],
                            uint32_t proof_entry_count,
                            uint8_t* leaf_hash,
                            uint64_t leaf_hash_size,
                            uint8_t* root_hash) {
  uint64_t inner_proof_size;
  uint64_t border_proof_size;
  size_t i;
  uint8_t hash[AVB_AFTL_HASH_SIZE];
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
  inner_proof = (uint8_t*)avb_malloc(inner_proof_size * AVB_AFTL_HASH_SIZE);
  if (inner_proof == NULL) {
    avb_error("Allocation failure in avb_aftl_root_from_icp.\n");
    return false;
  }
  border_proof = (uint8_t*)avb_malloc(border_proof_size * AVB_AFTL_HASH_SIZE);
  if (border_proof == NULL) {
    avb_free(inner_proof);
    avb_error("Allocation failure in avb_aftl_root_from_icp.\n");
    return false;
  }

  for (i = 0; i < inner_proof_size; i++) {
    avb_memcpy(
        inner_proof + (AVB_AFTL_HASH_SIZE * i), proof[i], AVB_AFTL_HASH_SIZE);
  }
  for (i = 0; i < border_proof_size; i++) {
    avb_memcpy(border_proof + (AVB_AFTL_HASH_SIZE * i),
               proof[inner_proof_size + i],
               AVB_AFTL_HASH_SIZE);
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
        hash, AVB_AFTL_HASH_SIZE, border_proof, border_proof_size, root_hash);

  if (inner_proof != NULL) avb_free(inner_proof);
  if (border_proof != NULL) avb_free(border_proof);
  return retval;
}

/* Defines helper functions read_u8, read_u16, read_u32 and read_u64. These
 * functions can be used to read from a |data| stream a |value| of a specific
 * size. The value endianness is converted from big-endian to host.  We ensure
 * that the read do not overflow beyond |data_end|. If successful, |data| is
 * brought forward by the size of the value read.
 */
#define _read_u(fct)                                   \
  {                                                    \
    size_t value_size = sizeof(*value);                \
    if ((*data + value_size) < *data) return false;    \
    if ((*data + value_size) > data_end) return false; \
    avb_memcpy(value, *data, value_size);              \
    *value = fct(*value);                              \
    *data += value_size;                               \
    return true;                                       \
  }
static bool read_u8(uint8_t* value, uint8_t** data, uint8_t* data_end) {
  _read_u();
}
AVB_ATTR_WARN_UNUSED_RESULT
static bool read_u16(uint16_t* value, uint8_t** data, uint8_t* data_end) {
  _read_u(avb_be16toh);
}
AVB_ATTR_WARN_UNUSED_RESULT
static bool read_u32(uint32_t* value, uint8_t** data, uint8_t* data_end) {
  _read_u(avb_be32toh);
}
AVB_ATTR_WARN_UNUSED_RESULT
static bool read_u64(uint64_t* value, uint8_t** data, uint8_t* data_end) {
  _read_u(avb_be64toh);
}
AVB_ATTR_WARN_UNUSED_RESULT

/* Allocates |value_size| bytes into |value| and copy |value_size| bytes from
 * |data|.  Ensure that we don't overflow beyond |data_end|. It is the caller
 * responsibility to avb_free |value|. Advances the |data| pointer pass the
 * value that has been read. Returns false if an overflow would have occurred or
 * if the allocation failed.
 */
static bool read_mem(uint8_t** value,
                     size_t value_size,
                     uint8_t** data,
                     uint8_t* data_end) {
  if (*data + value_size < *data || *data + value_size > data_end) {
    return false;
  }
  *value = (uint8_t*)avb_calloc(value_size);
  if (!value) {
    return false;
  }
  avb_memcpy(*value, *data, value_size);
  *data += value_size;
  return true;
}

/* Allocates and populates a TrillianLogRootDescriptor element in an
   AftlIcpEntry from a binary blob.
   The blob is expected to be pointing to the beginning of a
   serialized TrillianLogRootDescriptor element of an AftlIcpEntry.
   The aftl_blob argument is updated to point to the area after the
   TrillianLogRootDescriptor. aftl_blob_remaining gives the amount of the
   aftl_blob that is left to parse. */
static bool parse_trillian_log_root_descriptor(AftlIcpEntry* icp_entry,
                                               uint8_t** aftl_blob,
                                               size_t aftl_blob_remaining) {
  avb_assert(icp_entry);
  avb_assert(aftl_blob);
  uint8_t* blob_end = *aftl_blob + aftl_blob_remaining;
  if (*aftl_blob > blob_end) {
    return false;
  }

  /* Copy in the version field from the blob. */
  if (!read_u16(
          &(icp_entry->log_root_descriptor.version), aftl_blob, blob_end)) {
    avb_error("Unable to parse version.\n");
    return false;
  }

  /* Copy in the tree size field from the blob. */
  if (!read_u64(
          &(icp_entry->log_root_descriptor.tree_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse tree size.\n");
    return false;
  }

  /* Copy in the root hash size field from the blob. */
  if (!read_u8(&(icp_entry->log_root_descriptor.root_hash_size),
               aftl_blob,
               blob_end)) {
    avb_error("Unable to parse root hash size.\n");
    return false;
  }
  if (icp_entry->log_root_descriptor.root_hash_size != AVB_AFTL_HASH_SIZE) {
    avb_error("Invalid root hash size.\n");
    return false;
  }

  /* Copy in the root hash from the blob. */
  if (!read_mem(&(icp_entry->log_root_descriptor.root_hash),
                icp_entry->log_root_descriptor.root_hash_size,
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse root hash.\n");
    return false;
  }

  /* Copy in the timestamp field from the blob. */
  if (!read_u64(
          &(icp_entry->log_root_descriptor.timestamp), aftl_blob, blob_end)) {
    avb_error("Unable to parse timestamp.\n");
    return false;
  }

  /* Copy in the revision field from the blob. */
  if (!read_u64(
          &(icp_entry->log_root_descriptor.revision), aftl_blob, blob_end)) {
    avb_error("Unable to parse revision.\n");
    return false;
  }

  /* Copy in the metadata size field from the blob. */
  if (!read_u16(&(icp_entry->log_root_descriptor.metadata_size),
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse metadata size.\n");
    return false;
  }

  if (icp_entry->log_root_descriptor.metadata_size >
      AVB_AFTL_MAX_METADATA_SIZE) {
    avb_error("Invalid metadata size.\n");
    return false;
  }

  /* If it exists, copy in the metadata field from the blob. */
  if (icp_entry->log_root_descriptor.metadata_size > 0) {
    if (!read_mem(&(icp_entry->log_root_descriptor.metadata),
                  icp_entry->log_root_descriptor.metadata_size,
                  aftl_blob,
                  blob_end)) {
      avb_error("Unable to parse metadata.\n");
      return false;
    }
  } else {
    icp_entry->log_root_descriptor.metadata = NULL;
  }
  return true;
}

/* Parses a Signature from |aftl_blob| into leaf->signature.
 * Returns false if an error occurred during the parsing */
static bool parse_signature(SignedVBMetaPrimaryAnnotationLeaf* leaf,
                            uint8_t** aftl_blob,
                            uint8_t* blob_end) {
  Signature* signature = (Signature*)avb_calloc(sizeof(Signature));
  if (!signature) {
    avb_error("Failed to allocate signature.\n");
    return false;
  }
  leaf->signature = signature;

  if (!read_u8(&(signature->hash_algorithm), aftl_blob, blob_end)) {
    avb_error("Unable to parse the hash algorithm.\n");
    return false;
  }
  if (signature->hash_algorithm >= _AVB_AFTL_HASH_ALGORITHM_NUM) {
    avb_error("Unexpect hash algorithm in leaf signature.\n");
    return false;
  }

  if (!read_u8(&(signature->signature_algorithm), aftl_blob, blob_end)) {
    avb_error("Unable to parse the signature algorithm.\n");
    return false;
  }
  if (signature->signature_algorithm >= _AVB_AFTL_SIGNATURE_ALGORITHM_NUM) {
    avb_error("Unexpect signature algorithm in leaf signature.\n");
    return false;
  }

  if (!read_u16(&(signature->signature_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse the signature size.\n");
    return false;
  }
  if (!read_mem(&(signature->signature),
                signature->signature_size,
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse signature.\n");
    return false;
  }
  return true;
}

/* Parses an VBMetaPrimaryAnnotation from |aftl_blob| into leaf->annotation.
 * Returns false if an error occurred during the parsing */
static bool parse_annotation(SignedVBMetaPrimaryAnnotationLeaf* leaf,
                             uint8_t** aftl_blob,
                             uint8_t* blob_end) {
  VBMetaPrimaryAnnotation* annotation =
      (VBMetaPrimaryAnnotation*)avb_calloc(sizeof(VBMetaPrimaryAnnotation));
  if (!annotation) {
    avb_error("Failed to allocate annotation.\n");
    return false;
  }
  leaf->annotation = annotation;

  if (!read_u8(&(annotation->vbmeta_hash_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse VBMeta hash size.\n");
    return false;
  }
  if (annotation->vbmeta_hash_size != AVB_AFTL_HASH_SIZE) {
    avb_error("Unexpected VBMeta hash size.\n");
    return false;
  }
  if (!read_mem(&(annotation->vbmeta_hash),
                annotation->vbmeta_hash_size,
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse VBMeta hash.\n");
    return false;
  }

  if (!read_u8(&(annotation->version_incremental_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse version incremental size.\n");
    return false;
  }
  if (!read_mem(&(annotation->version_incremental),
                annotation->version_incremental_size,
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse version incremental.\n");
    return false;
  }

  if (!read_u8(
          &(annotation->manufacturer_key_hash_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse manufacturer key hash size.\n");
    return false;
  }
  if (!read_mem(&(annotation->manufacturer_key_hash),
                annotation->manufacturer_key_hash_size,
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse manufacturer key hash.\n");
    return false;
  }

  if (!read_u16(&(annotation->description_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse description size.\n");
    return false;
  }
  if (!read_mem(&(annotation->description),
                annotation->description_size,
                aftl_blob,
                blob_end)) {
    avb_error("Unable to parse description.\n");
    return false;
  }
  return true;
}

/* Allocates and populates a SignedVBMetaPrimaryAnnotationLeaf element in an
   AftlIcpEntry from a binary blob.
   The blob is expected to be pointing to the beginning of a
   serialized SignedVBMetaPrimaryAnnotationLeaf element of an AftlIcpEntry.
   The aftl_blob argument is updated to point to the area after the leaf. */
static bool parse_annotation_leaf(AftlIcpEntry* icp_entry,
                                  uint8_t** aftl_blob) {
  SignedVBMetaPrimaryAnnotationLeaf* leaf;
  uint8_t* blob_end = *aftl_blob + icp_entry->annotation_leaf_size;
  if (*aftl_blob > blob_end) {
    return false;
  }

  leaf = (SignedVBMetaPrimaryAnnotationLeaf*)avb_calloc(
      sizeof(SignedVBMetaPrimaryAnnotationLeaf));
  if (!leaf) {
    avb_error("Failed to allocate for annotation leaf.\n");
    return false;
  }
  /* The leaf will be free'd within the free_aftl_icp_entry() */
  icp_entry->annotation_leaf = leaf;
  if (!read_u8(&(leaf->version), aftl_blob, blob_end)) {
    avb_error("Unable to parse version.\n");
    return false;
  }
  if (leaf->version != 1) {
    avb_error("Unexpected leaf version.\n");
    return false;
  }
  if (!read_u64(&(leaf->timestamp), aftl_blob, blob_end)) {
    avb_error("Unable to parse timestamp.\n");
    return false;
  }
  if (!read_u8(&(leaf->leaf_type), aftl_blob, blob_end)) {
    avb_error("Unable to parse version.\n");
    return false;
  }
  if (leaf->leaf_type != AVB_AFTL_SIGNED_VBMETA_PRIMARY_ANNOTATION_LEAF) {
    avb_error("Unexpected leaf type.\n");
    return false;
  }
  if (!parse_signature(leaf, aftl_blob, blob_end)) {
    avb_error("Unable to parse signature.\n");
    return false;
  }
  if (!parse_annotation(leaf, aftl_blob, blob_end)) {
    avb_error("Unable to parse annotation.\n");
    return false;
  }
  return true;
}

/* Allocates and populates an AftlIcpEntry from a binary blob.
   The blob is expected to be pointing to the beginning of a
   serialized AftlIcpEntry structure. */
AftlIcpEntry* parse_icp_entry(uint8_t** aftl_blob, size_t* remaining_size) {
  AftlIcpEntry* icp_entry;
  uint8_t* blob_start = *aftl_blob;
  uint8_t* blob_end = *aftl_blob + *remaining_size;
  if (*aftl_blob > blob_end) {
    return NULL;
  }

  if (*remaining_size < AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE) {
    avb_error("Invalid AftlImage\n");
    return NULL;
  }

  icp_entry = (AftlIcpEntry*)avb_calloc(sizeof(AftlIcpEntry));
  if (!icp_entry) {
    avb_error("Failure allocating AftlIcpEntry\n");
    return NULL;
  }

  /* Copy in the log server URL size field. */
  if (!read_u32(&(icp_entry->log_url_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse log url size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  if (icp_entry->log_url_size > AVB_AFTL_MAX_URL_SIZE) {
    avb_error("Invalid log URL size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  /* Copy in the leaf index field. */
  if (!read_u64(&(icp_entry->leaf_index), aftl_blob, blob_end)) {
    avb_error("Unable to parse leaf_index.\n");
    avb_free(icp_entry);
    return NULL;
  }
  /* Copy in the TrillianLogRootDescriptor size field. */
  if (!read_u32(&(icp_entry->log_root_descriptor_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse log root descriptor size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  if (icp_entry->log_root_descriptor_size < AVB_AFTL_MIN_TLRD_SIZE ||
      icp_entry->log_root_descriptor_size > AVB_AFTL_MAX_TLRD_SIZE) {
    avb_error("Invalid TrillianLogRootDescriptor size.\n");
    avb_free(icp_entry);
    return NULL;
  }

  /* Copy in the annotation leaf size field. */
  if (!read_u32(&(icp_entry->annotation_leaf_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse annotation leaf size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  if (icp_entry->annotation_leaf_size == 0 ||
      icp_entry->annotation_leaf_size > AVB_AFTL_MAX_ANNOTATION_SIZE) {
    avb_error("Invalid annotation leaf size.\n");
    avb_free(icp_entry);
    return NULL;
  }

  /* Copy the log root signature size field. */
  if (!read_u16(&(icp_entry->log_root_sig_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse log root signature size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  if (icp_entry->log_root_sig_size != AVB_AFTL_SIGNATURE_SIZE) {
    avb_error("Invalid log root signature size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  /* Copy the inclusion proof hash count field. */
  if (!read_u8(&(icp_entry->proof_hash_count), aftl_blob, blob_end)) {
    avb_error("Unable to parse proof hash count.\n");
    avb_free(icp_entry);
    return NULL;
  }
  /* Copy the inclusion proof size field. */
  if (!read_u32(&(icp_entry->inc_proof_size), aftl_blob, blob_end)) {
    avb_error("Unable to parse inclusion proof size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  if ((icp_entry->inc_proof_size !=
       icp_entry->proof_hash_count * AVB_AFTL_HASH_SIZE) ||
      (icp_entry->inc_proof_size > AVB_AFTL_MAX_PROOF_SIZE)) {
    avb_error("Invalid inclusion proof size.\n");
    avb_free(icp_entry);
    return NULL;
  }
  /* Copy in the log server URL from the blob. */
  if (*aftl_blob + icp_entry->log_url_size < *aftl_blob ||
      *aftl_blob + icp_entry->log_url_size > blob_end) {
    avb_error("Invalid AftlImage.\n");
    avb_free(icp_entry);
    return NULL;
  }
  icp_entry->log_url = (uint8_t*)avb_calloc(icp_entry->log_url_size);
  if (!icp_entry->log_url) {
    avb_error("Failure to allocate URL.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  avb_memcpy(icp_entry->log_url, *aftl_blob, icp_entry->log_url_size);
  *aftl_blob += icp_entry->log_url_size;

  /* Populate the TrillianLogRootDescriptor elements. */
  if (*aftl_blob + icp_entry->log_root_descriptor_size < *aftl_blob ||
      *aftl_blob + icp_entry->log_root_descriptor_size > blob_end) {
    avb_error("Invalid AftlImage.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  icp_entry->log_root_descriptor_raw =
      (uint8_t*)avb_calloc(icp_entry->log_root_descriptor_size);
  if (!icp_entry->log_root_descriptor_raw) {
    avb_error("Failure to allocate log root descriptor.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  avb_memcpy(icp_entry->log_root_descriptor_raw,
             *aftl_blob,
             icp_entry->log_root_descriptor_size);
  if (!parse_trillian_log_root_descriptor(
          icp_entry, aftl_blob, icp_entry->log_root_descriptor_size)) {
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }

  /* Populate the annotation leaf. */
  if (*aftl_blob + icp_entry->annotation_leaf_size < *aftl_blob ||
      *aftl_blob + icp_entry->annotation_leaf_size > blob_end) {
    avb_error("Invalid AftlImage.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  icp_entry->annotation_leaf_raw =
      (uint8_t*)avb_calloc(icp_entry->annotation_leaf_size);
  if (!icp_entry->annotation_leaf_raw) {
    avb_error("Failure to allocate annotation leaf.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  avb_memcpy(icp_entry->annotation_leaf_raw,
             *aftl_blob,
             icp_entry->annotation_leaf_size);
  if (!parse_annotation_leaf(icp_entry, aftl_blob)) {
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }

  /* Allocate and copy the log root signature from the blob. */
  if (*aftl_blob + icp_entry->log_root_sig_size < *aftl_blob ||
      *aftl_blob + icp_entry->log_root_sig_size > blob_end) {
    avb_error("Invalid AftlImage.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  icp_entry->log_root_signature =
      (uint8_t*)avb_calloc(icp_entry->log_root_sig_size);
  if (!icp_entry->log_root_signature) {
    avb_error("Failure to allocate log root signature.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  avb_memcpy(
      icp_entry->log_root_signature, *aftl_blob, icp_entry->log_root_sig_size);
  *aftl_blob += icp_entry->log_root_sig_size;

  /* Finally, copy the proof hash data from the blob to the AftlImage. */
  if (*aftl_blob + icp_entry->inc_proof_size < *aftl_blob ||
      *aftl_blob + icp_entry->inc_proof_size > blob_end) {
    avb_error("Invalid AftlImage.\n");
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  icp_entry->proofs = avb_calloc(icp_entry->inc_proof_size);
  if (!icp_entry->proofs) {
    free_aftl_icp_entry(icp_entry);
    return NULL;
  }
  avb_memcpy(icp_entry->proofs, *aftl_blob, icp_entry->inc_proof_size);
  *aftl_blob += icp_entry->inc_proof_size;

  *remaining_size -= *aftl_blob - blob_start;
  return icp_entry;
}

/* Allocate and parse an AftlImage object out of binary data. */
AftlImage* parse_aftl_image(uint8_t* aftl_blob, size_t aftl_blob_size) {
  AftlImage* image;
  AftlImageHeader* image_header;
  AftlIcpEntry* entry;
  size_t image_size;
  size_t i;
  size_t remaining_size;

  /* Ensure the blob is at least large enough for an AftlImageHeader */
  if (aftl_blob_size < sizeof(AftlImageHeader)) {
    avb_error("Invalid image header.\n");
    return NULL;
  }
  image_header = (AftlImageHeader*)aftl_blob;
  /* Check for the magic value for an AftlImageHeader. */
  if (image_header->magic != AVB_AFTL_MAGIC) {
    avb_error("Invalid magic number\n");
    return NULL;
  }
  /* Extract the size out of the header. */
  image_size = avb_be32toh(image_header->image_size);
  if (image_size < sizeof(AftlImageHeader) ||
      image_size > AVB_AFTL_MAX_AFTL_IMAGE_SIZE) {
    avb_error("Invalid image size.\n");
    return NULL;
  }
  image = (AftlImage*)avb_calloc(sizeof(AftlImage));
  if (!image) {
    avb_error("Failed allocation for AftlImage.\n");
    return NULL;
  }
  /* Copy the header bytes directly from the aftl_blob. */
  avb_memcpy(&(image->header), aftl_blob, sizeof(AftlImageHeader));
  /* Fix endianness. */
  image->header.required_icp_version_major =
      avb_be32toh(image->header.required_icp_version_major);
  image->header.required_icp_version_minor =
      avb_be32toh(image->header.required_icp_version_minor);
  image->header.image_size = avb_be32toh(image->header.image_size);
  image->header.icp_count = avb_be16toh(image->header.icp_count);
  /* Allocate memory for the entry array */
  image->entries = (AftlIcpEntry**)avb_calloc(sizeof(AftlIcpEntry*) *
                                              image->header.icp_count);
  if (!image->entries) {
    avb_error("Failed allocation for AftlIcpEntry array.\n");
    avb_free(image);
    return NULL;
  }

  /* Jump past the header and parse out each AftlIcpEntry. */
  aftl_blob += sizeof(AftlImageHeader);
  remaining_size = aftl_blob_size - sizeof(AftlImageHeader);
  for (i = 0; i < image->header.icp_count && remaining_size > 0; i++) {
    entry = parse_icp_entry(&aftl_blob, &remaining_size);
    if (!entry) {
      free_aftl_image(image);
      return NULL;
    }
    image->entries[i] = entry;
  }

  return image;
}

/* Free an AftlIcpEntry and each allocated sub-element. */
void free_aftl_icp_entry(AftlIcpEntry* icp_entry) {
  /* Ensure the AftlIcpEntry exists before attempting to free it. */
  if (icp_entry) {
    /* Free the log_url and log_root_signature elements if they exist. */
    if (icp_entry->log_url) avb_free(icp_entry->log_url);
    if (icp_entry->log_root_signature) avb_free(icp_entry->log_root_signature);
    /* Free the annotation elements if they exist. */
    if (icp_entry->annotation_leaf) {
      if (icp_entry->annotation_leaf->signature) {
        if (icp_entry->annotation_leaf->signature->signature) {
          avb_free(icp_entry->annotation_leaf->signature->signature);
        }
        avb_free(icp_entry->annotation_leaf->signature);
      }
      if (icp_entry->annotation_leaf->annotation) {
        if (icp_entry->annotation_leaf->annotation->vbmeta_hash)
          avb_free(icp_entry->annotation_leaf->annotation->vbmeta_hash);
        if (icp_entry->annotation_leaf->annotation->version_incremental)
          avb_free(icp_entry->annotation_leaf->annotation->version_incremental);
        if (icp_entry->annotation_leaf->annotation->manufacturer_key_hash)
          avb_free(
              icp_entry->annotation_leaf->annotation->manufacturer_key_hash);
        if (icp_entry->annotation_leaf->annotation->description)
          avb_free(icp_entry->annotation_leaf->annotation->description);
        avb_free(icp_entry->annotation_leaf->annotation);
      }
      avb_free(icp_entry->annotation_leaf);
    }
    if (icp_entry->annotation_leaf_raw)
      avb_free(icp_entry->annotation_leaf_raw);
    /* Free the TrillianLogRoot elements if they exist. */
    if (icp_entry->log_root_descriptor.metadata)
      avb_free(icp_entry->log_root_descriptor.metadata);
    if (icp_entry->log_root_descriptor.root_hash)
      avb_free(icp_entry->log_root_descriptor.root_hash);
    if (icp_entry->log_root_descriptor_raw)
      avb_free(icp_entry->log_root_descriptor_raw);
    if (icp_entry->proofs) avb_free(icp_entry->proofs);
    /* Finally, free the AftlIcpEntry. */
    avb_free(icp_entry);
  }
}

/* Free the AftlImage and each allocated sub-element. */
void free_aftl_image(AftlImage* image) {
  size_t i;

  /* Ensure the descriptor exists before attempting to free it. */
  if (!image) {
    return;
  }
  /* Free the entry array. */
  if (image->entries) {
    /* Walk through each entry, freeing each one. */
    for (i = 0; i < image->header.icp_count; i++) {
      if (image->entries[i]) {
        free_aftl_icp_entry(image->entries[i]);
      }
    }
    avb_free(image->entries);
  }
  avb_free(image);
}
