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

#include "libavb_aftl/avb_aftl_verify.h"

#include <libavb/avb_cmdline.h>
#include <libavb/avb_slot_verify.h>
#include <libavb/avb_util.h>

#include "libavb_aftl/avb_aftl_types.h"
#include "libavb_aftl/avb_aftl_util.h"
#include "libavb_aftl/avb_aftl_validate.h"

/* Read the vbmeta partition, after the AvbVBMetaImageHeader structure, to find
 * the AftlDescriptor.
 */
static AvbSlotVerifyResult avb_aftl_find_aftl_descriptor(
    AvbOps* ops,
    const char* part_name,
    size_t vbmeta_size,
    uint8_t* out_image_buf,
    size_t* out_image_size) {
  AvbIOResult io_ret;

  avb_assert(vbmeta_size <= AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE);
  io_ret =
      ops->read_from_partition(ops,
                               part_name,
                               vbmeta_size /* offset */,
                               AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE - vbmeta_size,
                               out_image_buf,
                               out_image_size);

  if (io_ret == AVB_IO_RESULT_ERROR_OOM) {
    return AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
  } else if (io_ret != AVB_IO_RESULT_OK) {
    avb_errorv(
        part_name, ": Error loading AftlDescriptor from partition.\n", NULL);
    return AVB_SLOT_VERIFY_RESULT_ERROR_IO;
  }

  if (*out_image_size < 4 || (out_image_buf[0] != 'A') ||
      (out_image_buf[1] != 'F') || (out_image_buf[2] != 'T') ||
      (out_image_buf[3] != 'L')) {
    avb_errorv(part_name, ": Unexpected AftlDescriptor magic.\n", NULL);
    return AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
  }

  return AVB_SLOT_VERIFY_RESULT_OK;
}

/* Performs the three validation steps for an AFTL descriptor:
   1. Ensure the vbmeta image hash matches that in the descriptor.
   2. Ensure the root hash of the Merkle tree matches that in the descriptor.
   3. Verify the signature using the transparency log public key.
*/
static AvbSlotVerifyResult avb_aftl_verify_descriptor(uint8_t* cur_vbmeta_data,
                                                      size_t cur_vbmeta_size,
                                                      uint8_t* aftl_blob,
                                                      size_t aftl_size,
                                                      uint8_t* key_bytes,
                                                      size_t key_num_bytes) {
  size_t i;
  AftlDescriptor* aftl_descriptor;
  AvbSlotVerifyResult result = AVB_SLOT_VERIFY_RESULT_OK;

  /* Attempt to parse the AftlDescriptor pointed to by aftl_blob. */
  aftl_descriptor = parse_aftl_descriptor(aftl_blob, aftl_size);
  if (!aftl_descriptor) {
    return AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
  }

  /* Now that a valid AftlDescriptor has been parsed, attempt to verify
     the inclusion proof(s) in three steps. */
  for (i = 0; i < aftl_descriptor->header.icp_count; i++) {
    /* 1. Ensure that the vbmeta hash stored in the AftlIcpEntry matches
       the one that represents the partition. */
    if (!avb_aftl_verify_vbmeta_hash(
            cur_vbmeta_data, cur_vbmeta_size, aftl_descriptor->entries[i])) {
      avb_error("AFTL vbmeta hash verification failed.\n");
      result = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
      break;
    }
    /* 2. Ensure that the root hash of the Merkle tree representing
       the transparency log entry matches the one stored in the
       AftlIcpEntry. */
    if (!avb_aftl_verify_icp_root_hash(aftl_descriptor->entries[i])) {
      avb_error("AFTL root hash verification failed.\n");
      result = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
      break;
    }
    /* 3. Verify the signature using the transparency log public
       key stored on device. */
    if (!avb_aftl_verify_entry_signature(
            key_bytes, key_num_bytes, aftl_descriptor->entries[i])) {
      avb_error("AFTL signature verification failed on entry.\n");
      result = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
      break;
    }
  }
  free_aftl_descriptor(aftl_descriptor);
  return result;
}

AvbSlotVerifyResult aftl_slot_verify(AvbOps* ops,
                                     AvbSlotVerifyData* asv_data,
                                     uint8_t* key_bytes,
                                     size_t key_size) {
  size_t i;
  size_t aftl_descriptor_size;
  size_t vbmeta_size;
  uint8_t* current_aftl_blob;
  char part_name[AVB_PART_NAME_MAX_SIZE];
  char* pname;
  AvbSlotVerifyResult ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;

  avb_assert(asv_data != NULL);
  avb_assert(key_bytes != NULL);
  avb_assert(key_size == AVB_AFTL_PUB_KEY_SIZE);
  if (asv_data->vbmeta_images == NULL) {
    return AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
  }

  current_aftl_blob = avb_malloc(AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE);
  if (current_aftl_blob == NULL) {
    return AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
  }

  /* Walk through each vbmeta blob in the AvbSlotVerifyData struct. */
  for (i = 0; i < asv_data->num_vbmeta_images; i++) {
    /* Rebuild partition name, appending the suffix */
    pname = asv_data->vbmeta_images[i].partition_name;
    if (!avb_str_concat(part_name,
                        sizeof part_name,
                        (const char*)pname,
                        avb_strlen(pname),
                        asv_data->ab_suffix,
                        avb_strlen(asv_data->ab_suffix))) {
      avb_error("Partition name and suffix does not fit.\n");
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
      break;
    }

    /* Use the partition info to find the AftlDescriptor */
    vbmeta_size = asv_data->vbmeta_images[i].vbmeta_size;
    ret = avb_aftl_find_aftl_descriptor(
        ops, part_name, vbmeta_size, current_aftl_blob, &aftl_descriptor_size);
    if (ret != AVB_SLOT_VERIFY_RESULT_OK) {
      avb_error("Unable to find the AftlDescriptor.\n");
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA;
      break;
    }

    /* Validate the AFTL descriptor in the vbmeta image. */
    ret = avb_aftl_verify_descriptor(asv_data->vbmeta_images[i].vbmeta_data,
                                     vbmeta_size,
                                     current_aftl_blob,
                                     aftl_descriptor_size,
                                     key_bytes,
                                     key_size);
    if (ret != AVB_SLOT_VERIFY_RESULT_OK) break;
  }

  avb_free(current_aftl_blob);
  return ret;
}
