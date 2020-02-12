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

/* Verifies that the logged VBMeta hash matches the one on device. */
bool avb_aftl_verify_vbmeta_hash(uint8_t* vbmeta,
                                 size_t vbmeta_size,
                                 AftlIcpEntry* icp_entry) {
  uint8_t vbmeta_hash[AFTL_HASH_SIZE];

  avb_assert(vbmeta != NULL && icp_entry != NULL);

  if (!avb_aftl_sha256(vbmeta, vbmeta_size, vbmeta_hash)) return false;

  /* Only SHA256 hashes are currently supported. If the vbmeta hash
     size is not AFTL_HASH_SIZE, return false. */
  if (icp_entry->fw_info_leaf.vbmeta_hash_size != AFTL_HASH_SIZE) {
    avb_error("Invalid VBMeta hash size.\n");
    return false;
  }
  /* Return whether the calculated VBMeta hash matches the stored one. */
  return avb_safe_memcmp(vbmeta_hash,
                         icp_entry->fw_info_leaf.vbmeta_hash,
                         AFTL_HASH_SIZE) == 0;
}

/* Extracts the raw data from the FirmwareInfo structure. */
static bool get_raw_fw_image_info(AftlIcpEntry* icp_entry,
                                  uint8_t* buffer,
                                  size_t buffer_size) {
  uint64_t offset;
  uint64_t calc_fw_image_size;

  avb_assert(icp_entry != NULL && buffer != NULL);

  if (icp_entry->fw_info_leaf_size != buffer_size) {
    avb_error("Invalid size passed to get_raw_fw_image_info.\n");
    return false;
  }
  calc_fw_image_size = icp_entry->fw_info_leaf.vbmeta_hash_size;
  if (calc_fw_image_size != AFTL_HASH_SIZE) {
    avb_error("Invalid vbmeta hash size.\n");
    return false;
  }
  if (!avb_safe_add_to(&calc_fw_image_size,
                       icp_entry->fw_info_leaf.version_incremental_size)) {
    avb_error("Invalid version incremental size.\n");
    return false;
  }
  if (!avb_safe_add_to(&calc_fw_image_size,
                       icp_entry->fw_info_leaf.platform_key_size)) {
    avb_error("Invalid platform key size.\n");
    return false;
  }
  if (!avb_safe_add_to(&calc_fw_image_size,
                       icp_entry->fw_info_leaf.manufacturer_key_hash_size)) {
    avb_error("Invalid manufacturer key hash size.\n");
    return false;
  }
  if (!avb_safe_add_to(&calc_fw_image_size,
                       icp_entry->fw_info_leaf.description_size)) {
    avb_error("Invalid description size.\n");
    return false;
  }

  offset = 0;

  if (icp_entry->fw_info_leaf_size != calc_fw_image_size) {
    avb_error("Invalid FirmwareInfo leaf size.\n");
    return false;
  }
  if (icp_entry->fw_info_leaf.vbmeta_hash != NULL) {
    avb_memcpy(buffer,
               icp_entry->fw_info_leaf.vbmeta_hash,
               icp_entry->fw_info_leaf.vbmeta_hash_size);
    offset = icp_entry->fw_info_leaf.vbmeta_hash_size;
  }

  if (icp_entry->fw_info_leaf.version_incremental != NULL) {
    avb_memcpy(buffer + offset,
               icp_entry->fw_info_leaf.version_incremental,
               icp_entry->fw_info_leaf.version_incremental_size);
    offset += icp_entry->fw_info_leaf.version_incremental_size;
  }

  if (icp_entry->fw_info_leaf.platform_key != NULL) {
    avb_memcpy(buffer + offset,
               icp_entry->fw_info_leaf.platform_key,
               icp_entry->fw_info_leaf.platform_key_size);
    offset += icp_entry->fw_info_leaf.platform_key_size;
  }

  if (icp_entry->fw_info_leaf.manufacturer_key_hash != NULL) {
    avb_memcpy(buffer + offset,
               icp_entry->fw_info_leaf.manufacturer_key_hash,
               icp_entry->fw_info_leaf.manufacturer_key_hash_size);
    offset += icp_entry->fw_info_leaf.manufacturer_key_hash_size;
  }

  if (icp_entry->fw_info_leaf.description != NULL) {
    avb_memcpy(buffer + offset,
               icp_entry->fw_info_leaf.description,
               icp_entry->fw_info_leaf.description_size);
    offset += icp_entry->fw_info_leaf.description_size;
  }
  return true;
}

/* Verifies the Merkle tree root hash. */
bool avb_aftl_verify_icp_root_hash(AftlIcpEntry* icp_entry) {
  uint8_t leaf_hash[AFTL_HASH_SIZE];
  uint8_t result_hash[AFTL_HASH_SIZE];
  uint8_t* buffer;

  avb_assert(icp_entry != NULL);
  if (icp_entry->fw_info_leaf_size > AFTL_MAX_FW_INFO_LEAF_SIZE) {
    avb_error("Invalid FirmwareInfo leaf size\n");
    return false;
  }
  buffer = (uint8_t*)avb_malloc(icp_entry->fw_info_leaf_size);
  if (buffer == NULL) {
    avb_error("Allocation failure in avb_aftl_verify_icp_root_hash\n");
    return false;
  }
  /* Extract the raw data from the FirmwareInfo leaf */
  if (!get_raw_fw_image_info(icp_entry, buffer, icp_entry->fw_info_leaf_size)) {
    avb_free(buffer);
    return false;
  }
  /* Calculate the RFC 6962 hash of the seed entry. */
  if (!avb_aftl_rfc6962_hash_leaf(
          buffer, icp_entry->fw_info_leaf_size, leaf_hash)) {
    avb_free(buffer);
    return false;
  }
  avb_free(buffer);
  /* Calculate the Merkle tree's root hash. */
  if (!avb_aftl_root_from_icp(icp_entry->leaf_index,
                              icp_entry->log_root_descriptor.tree_size,
                              icp_entry->proofs,
                              icp_entry->proof_hash_count,
                              leaf_hash,
                              AFTL_HASH_SIZE,
                              result_hash))
    return false;
  /* Return whether the calculated root hash matches the stored one. */
  return (avb_safe_memcmp(result_hash,
                          icp_entry->log_root_descriptor.root_hash,
                          AFTL_HASH_SIZE) == 0);
}

/* Verifies the log root signature for the transparency log submission. */
bool avb_aftl_verify_entry_signature(const uint8_t* key,
                                     size_t key_num_bytes,
                                     AftlIcpEntry* icp_entry) {
  uint8_t* sig;
  size_t sig_num_bytes;
  uint8_t log_root_hash[AFTL_HASH_SIZE];
  size_t log_root_hash_num_bytes;
  const AvbAlgorithmData* algorithm_data;

  avb_assert(key != NULL && icp_entry != NULL);

  /* Extract the log root signature from the AftlIcpEntry. */
  sig = icp_entry->log_root_signature;
  if (sig == NULL) {
    avb_error("Invalid log root signature.\n");
    return false;
  }
  sig_num_bytes = icp_entry->log_root_sig_size;
  log_root_hash_num_bytes = AFTL_HASH_SIZE;

  /* Calculate the SHA256 of the TrillianLogRootDescriptor. */
  if (!avb_aftl_hash_log_root_descriptor(icp_entry, log_root_hash))
    return false;

  /* algorithm_data is used to calculate the padding for signature verification.
   */
  algorithm_data = avb_get_algorithm_data(AVB_ALGORITHM_TYPE_SHA256_RSA4096);
  if (algorithm_data == NULL) {
    avb_error("Failed to get algorithm data.\n");
    return false;
  }
  return avb_rsa_verify(key,
                        key_num_bytes,
                        sig,
                        sig_num_bytes,
                        log_root_hash,
                        log_root_hash_num_bytes,
                        algorithm_data->padding,
                        algorithm_data->padding_len);
}
