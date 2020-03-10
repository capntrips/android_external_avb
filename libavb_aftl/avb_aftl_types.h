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
/* Limit AftlDescriptor size to 64KB. */
#define AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE 65536ul
/* Limit version.incremental size to 256 characters. */
#define AVB_AFTL_MAX_VERSION_INCREMENTAL_SIZE 256ul
/* AFTL trees require at most 64 hashes to reconstruct the root */
#define AVB_AFTL_MAX_PROOF_SIZE 64 * AVB_AFTL_HASH_SIZE
/* Max URL limit. */
#define AVB_AFTL_MAX_URL_SIZE 2048ul
/* Minimum valid size for a FirmwareInfo leaf. Derived from a minimal json
   response that contains only the vbmeta_hash. */
#define AVB_AFTL_MIN_FW_INFO_SIZE 103ul
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
   fw_info_leaf_size: sizeof(uint32_t)
   log_root_sig_size: sizeof(uint32_t)
   proof_hash_count: sizeof(uint8_t)
   inc_proof_size: sizeof(uint32_t)
   log_url: 4 (shortest practical URL)
   log_root_descriptor: AVB_AFTL_MIN_TLRD_SIZE
   fw_info_leaf: AVB_AFTL_MIN_FW_INFO_SIZE
   log_root_signature: AVB_AFTL_SIGNATURE_SIZE
   proofs: AVB_AFTL_HASH_SIZE as there must be at least one hash. */
#define AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE                                       \
  (sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + \
   sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + 4 +                 \
   AVB_AFTL_MIN_TLRD_SIZE + AVB_AFTL_MIN_FW_INFO_SIZE +                        \
   AVB_AFTL_SIGNATURE_SIZE + AVB_AFTL_HASH_SIZE)
/* The maximum AftlIcpEntrySize is the max AftlDescriptor size minus the size
   of the AftlIcpHeader. */
#define AVB_AFTL_MAX_AFTL_ICP_ENTRY_SIZE \
  (AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE - sizeof(AftlIcpHeader))
/* The maximum FirmwareInfo is the max AftlDescriptor size minus the
   size of the smallest valid AftlIcpEntry. */
#define AVB_AFTL_MAX_FW_INFO_SIZE \
  (AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE - AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE)
/* The maximum metadata size in a TrillianLogRootDescriptor for AFTL is the
   max AftlDescriptor size minus the smallest valid AftlIcpEntry size. */
#define AVB_AFTL_MAX_METADATA_SIZE \
  (AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE - AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE)
/* The maximum TrillianLogRootDescriptor is the size of the smallest valid
TrillianLogRootDescriptor + the largest possible metadata size. */
#define AVB_AFTL_MAX_TLRD_SIZE \
  (AVB_AFTL_MIN_TLRD_SIZE + AVB_AFTL_MAX_METADATA_SIZE)

/* Data structure containing AFTL header information. */
typedef struct AftlIcpHeader {
  uint32_t magic;
  uint32_t required_icp_version_major;
  uint32_t required_icp_version_minor;
  uint32_t aftl_descriptor_size; /* Total size of the AftlDescriptor. */
  uint16_t icp_count;
} AVB_ATTR_PACKED AftlIcpHeader;

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

/* Data structure containing the firmware image info stored in the
   transparency log. This is defined in
   https://android.googlesource.com/platform/external/avb/+/master/proto/aftl.proto
 */
typedef struct FirmwareInfo {
  uint32_t vbmeta_hash_size;
  uint8_t* vbmeta_hash;
  uint8_t* json_data;
} FirmwareInfo;

/* Data structure containing AFTL inclusion proof data from a single
   transparency log. */
typedef struct AftlIcpEntry {
  uint32_t log_url_size;
  uint64_t leaf_index;
  uint32_t log_root_descriptor_size;
  uint32_t fw_info_leaf_size;
  uint16_t log_root_sig_size;
  uint8_t proof_hash_count;
  uint32_t inc_proof_size;
  uint8_t* log_url;
  TrillianLogRootDescriptor log_root_descriptor;
  FirmwareInfo fw_info_leaf;
  uint8_t* log_root_signature;
  uint8_t proofs[/*proof_hash_count*/][AVB_AFTL_HASH_SIZE];
} AVB_ATTR_PACKED AftlIcpEntry;

/* Main data structure for an AFTL descriptor. */
typedef struct AftlDescriptor {
  AftlIcpHeader header;
  AftlIcpEntry** entries;
} AVB_ATTR_PACKED AftlDescriptor;

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_TYPES_H_ */
