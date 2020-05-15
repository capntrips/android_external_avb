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
#error "You can't include avb_aftl_types.h in the public header libavb_aftl.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_AFTL_TYPES_H_
#define AVB_AFTL_TYPES_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVB_AFTL_UINT64_MAX 0xfffffffffffffffful
#define AVB_AFTL_HASH_SIZE 32ul
#define AVB_AFTL_SIGNATURE_SIZE 512ul
/* Raw key size used for signature validation. */
#define AVB_AFTL_PUB_KEY_SIZE 1032ul
/* Limit AftlImage size to 64KB. */
#define AVB_AFTL_MAX_AFTL_IMAGE_SIZE 65536ul
/* Limit version.incremental size to 256 characters. */
#define AVB_AFTL_MAX_VERSION_INCREMENTAL_SIZE 256ul
/* AFTL trees require at most 64 hashes to reconstruct the root */
#define AVB_AFTL_MAX_PROOF_SIZE 64 * AVB_AFTL_HASH_SIZE
/* Max URL limit. */
#define AVB_AFTL_MAX_URL_SIZE 2048ul
/* Minimum valid size for an Annotation leaf. */
#define AVB_AFTL_MIN_ANNOTATION_SIZE 18ul
/* Minimum valid size for a TrillianLogRootDescriptor. See the
   TrillianLogRootDescriptor struct for details. The values here cover:
   version: sizeof(uint16_t)
   tree_size: sizeof(uint64_t)
   root_hash_size: sizeof(uint8_t)
   root_hash: AVB_AFTL_HASH_SIZE
   timestamp; sizeof(uint64_t)
   revision; sizeof(uint64_t)
   metadata_size: sizeof(uint16_t)
   metadata is optional, so it's not required for the minimum size. */
#define AVB_AFTL_MIN_TLRD_SIZE                                \
  (sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint8_t) +    \
   AVB_AFTL_HASH_SIZE + sizeof(uint64_t) + sizeof(uint64_t) + \
   sizeof(uint16_t))
/* Minimum valid size for an AftlIcpEntry structure. See the
   AftlIcpEntry struct for details. The values here cover:
   log_url_size: sizeof(uint32_t)
   leaf_index: sizeof(uint64_t)
   log_root_descriptor_size: sizeof(uint32_t)
   annotation_leaf_size: sizeof(uint32_t)
   log_root_sig_size: sizeof(uint32_t)
   proof_hash_count: sizeof(uint8_t)
   inc_proof_size: sizeof(uint32_t)
   log_url: 4 (shortest practical URL)
   log_root_descriptor: AVB_AFTL_MIN_TLRD_SIZE
   annotation_leaf: AVB_AFTL_MIN_ANNOTATION_SIZE
   log_root_signature: AVB_AFTL_SIGNATURE_SIZE
   proofs: AVB_AFTL_HASH_SIZE as there must be at least one hash. */
#define AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE                                       \
  (sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + \
   sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + 4 +                 \
   AVB_AFTL_MIN_TLRD_SIZE + AVB_AFTL_MIN_ANNOTATION_SIZE +                     \
   AVB_AFTL_SIGNATURE_SIZE + AVB_AFTL_HASH_SIZE)
/* The maximum AftlIcpEntrySize is the max AftlImage size minus the size
   of the AftlImageHeader. */
#define AVB_AFTL_MAX_AFTL_ICP_ENTRY_SIZE \
  (AVB_AFTL_MAX_AFTL_IMAGE_SIZE - sizeof(AftlImageHeader))
/* The maximum Annotation size is the max AftlImage size minus the
   size of the smallest valid AftlIcpEntry. */
#define AVB_AFTL_MAX_ANNOTATION_SIZE \
  (AVB_AFTL_MAX_AFTL_IMAGE_SIZE - AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE)
/* The maximum metadata size in a TrillianLogRootDescriptor for AFTL is the
   max AftlImage size minus the smallest valid AftlIcpEntry size. */
#define AVB_AFTL_MAX_METADATA_SIZE \
  (AVB_AFTL_MAX_AFTL_IMAGE_SIZE - AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE)
/* The maximum TrillianLogRootDescriptor is the size of the smallest valid
TrillianLogRootDescriptor + the largest possible metadata size. */
#define AVB_AFTL_MAX_TLRD_SIZE \
  (AVB_AFTL_MIN_TLRD_SIZE + AVB_AFTL_MAX_METADATA_SIZE)

/* Data structure containing a Trillian LogRootDescriptor, from
   https://github.com/google/trillian/blob/master/trillian.proto#L255
   The log_root_signature is calculated over this structure. */
typedef struct TrillianLogRootDescriptor {
  uint16_t version;
  uint64_t tree_size;
  uint8_t root_hash_size;
  uint8_t* root_hash;
  uint64_t timestamp;
  uint64_t revision;
  uint16_t metadata_size;
  uint8_t* metadata;
} TrillianLogRootDescriptor;

typedef enum {
  AVB_AFTL_HASH_SHA256,
  _AVB_AFTL_HASH_ALGORITHM_NUM
} HashAlgorithm;

typedef enum {
  AVB_AFTL_SIGNATURE_RSA,    // RSA with PKCS1v15
  AVB_AFTL_SIGNATURE_ECDSA,  // ECDSA with P256 curve
  _AVB_AFTL_SIGNATURE_ALGORITHM_NUM
} SignatureAlgorithm;

/* Data structure containing the signature within a leaf of the VBMeta
 * annotation. This signature is made using the manufacturer key which is
 * generally not available at boot time. Therefore, this structure is not
 * verified by the bootloader. */
typedef struct {
  uint8_t hash_algorithm;
  uint8_t signature_algorithm;
  uint16_t signature_size;
  uint8_t* signature;
} Signature;

/* Data structure containing the VBMeta annotation. */
typedef struct {
  uint8_t vbmeta_hash_size;
  uint8_t* vbmeta_hash;
  uint8_t version_incremental_size;
  uint8_t* version_incremental;
  uint8_t manufacturer_key_hash_size;
  uint8_t* manufacturer_key_hash;
  uint16_t description_size;
  uint8_t* description;
} VBMetaPrimaryAnnotation;

#define AVB_AFTL_VBMETA_LEAF 0
#define AVB_AFTL_SIGNED_VBMETA_PRIMARY_ANNOTATION_LEAF 1

/* Data structure containing the leaf that is stored in the
   transparency log. */
typedef struct {
  uint8_t version;
  uint64_t timestamp;
  uint8_t leaf_type;
  Signature* signature;
  VBMetaPrimaryAnnotation* annotation;
} SignedVBMetaPrimaryAnnotationLeaf;

/* Data structure containing AFTL inclusion proof data from a single
   transparency log. */
typedef struct AftlIcpEntry {
  uint32_t log_url_size;
  uint64_t leaf_index;
  uint32_t log_root_descriptor_size;
  uint32_t annotation_leaf_size;
  uint16_t log_root_sig_size;
  uint8_t proof_hash_count;
  uint32_t inc_proof_size;
  uint8_t* log_url;
  TrillianLogRootDescriptor log_root_descriptor;
  uint8_t* log_root_descriptor_raw;
  SignedVBMetaPrimaryAnnotationLeaf* annotation_leaf;
  uint8_t* annotation_leaf_raw;
  uint8_t* log_root_signature;
  uint8_t (*proofs)[AVB_AFTL_HASH_SIZE];
} AftlIcpEntry;

/* Data structure containing AFTL header information. */
typedef struct AftlImageHeader {
  uint32_t magic;
  uint32_t required_icp_version_major;
  uint32_t required_icp_version_minor;
  uint32_t image_size; /* Total size of the AftlImage, including this header */
  uint16_t icp_count;
} AVB_ATTR_PACKED AftlImageHeader;

/* Main data structure for an AFTL image. */
typedef struct AftlImage {
  AftlImageHeader header;
  AftlIcpEntry** entries;
} AftlImage;

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_TYPES_H_ */
