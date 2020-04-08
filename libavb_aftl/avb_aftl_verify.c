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
 * the AftlImage.
 */
static AftlSlotVerifyResult avb_aftl_find_aftl_image(AvbOps* ops,
                                                     const char* part_name,
                                                     size_t vbmeta_size,
                                                     uint8_t* out_image_buf,
                                                     size_t* out_image_size) {
  AvbIOResult io_ret;

  avb_assert(vbmeta_size <= AVB_AFTL_MAX_AFTL_IMAGE_SIZE);
  io_ret = ops->read_from_partition(ops,
                                    part_name,
                                    vbmeta_size /* offset */,
                                    AVB_AFTL_MAX_AFTL_IMAGE_SIZE - vbmeta_size,
                                    out_image_buf,
                                    out_image_size);
  switch (io_ret) {
    case AVB_IO_RESULT_OK:
      break;
    case AVB_IO_RESULT_ERROR_OOM:
      return AFTL_SLOT_VERIFY_RESULT_ERROR_OOM;
    case AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION:
    case AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION:
      return AFTL_SLOT_VERIFY_RESULT_ERROR_IMAGE_NOT_FOUND;
    default:
      avb_errorv(
          part_name, ": Error loading AftlImage from partition.\n", NULL);
      return AFTL_SLOT_VERIFY_RESULT_ERROR_IO;
  }

  if (*out_image_size < 4 || (out_image_buf[0] != 'A') ||
      (out_image_buf[1] != 'F') || (out_image_buf[2] != 'T') ||
      (out_image_buf[3] != 'L')) {
    avb_errorv(part_name, ": Unexpected AftlImage magic.\n", NULL);
    return AFTL_SLOT_VERIFY_RESULT_ERROR_IMAGE_NOT_FOUND;
  }

  return AFTL_SLOT_VERIFY_RESULT_OK;
}

/* Performs the three validation steps for an AFTL image:
   1. Ensure the vbmeta image hash matches that in the image.
   2. Ensure the root hash of the Merkle tree matches that in the image.
   3. Verify the signature using the transparency log public key.
*/
static AftlSlotVerifyResult avb_aftl_verify_image(uint8_t* cur_vbmeta_data,
                                                  size_t cur_vbmeta_size,
                                                  uint8_t* aftl_blob,
                                                  size_t aftl_size,
                                                  uint8_t* key_bytes,
                                                  size_t key_num_bytes) {
  size_t i;
  AftlImage* image;
  AftlSlotVerifyResult result = AFTL_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;

  /* Attempt to parse the AftlImage pointed to by aftl_blob. */
  image = parse_aftl_image(aftl_blob, aftl_size);
  if (!image) {
    return AFTL_SLOT_VERIFY_RESULT_ERROR_INVALID_IMAGE;
  }

  /* Now that a valid AftlImage has been parsed, attempt to verify
     the inclusion proof(s) in three steps. */
  for (i = 0; i < image->header.icp_count; i++) {
    /* 1. Ensure that the vbmeta hash stored in the AftlIcpEntry matches
       the one that represents the partition. */
    if (!avb_aftl_verify_vbmeta_hash(
            cur_vbmeta_data, cur_vbmeta_size, image->entries[i])) {
      avb_error("AFTL vbmeta hash verification failed.\n");
      result = AFTL_SLOT_VERIFY_RESULT_ERROR_VBMETA_HASH_MISMATCH;
      break;
    }
    /* 2. Ensure that the root hash of the Merkle tree representing
       the transparency log entry matches the one stored in the
       AftlIcpEntry. */
    if (!avb_aftl_verify_icp_root_hash(image->entries[i])) {
      avb_error("AFTL root hash verification failed.\n");
      result = AFTL_SLOT_VERIFY_RESULT_ERROR_TREE_HASH_MISMATCH;
      break;
    }
    /* 3. Verify the signature using the transparency log public
       key stored on device. */
    if (!avb_aftl_verify_entry_signature(
            key_bytes, key_num_bytes, image->entries[i])) {
      avb_error("AFTL signature verification failed on entry.\n");
      result = AFTL_SLOT_VERIFY_RESULT_ERROR_INVALID_PROOF_SIGNATURE;
      break;
    }
    result = AFTL_SLOT_VERIFY_RESULT_OK;
  }
  free_aftl_image(image);
  return result;
}

AftlSlotVerifyResult aftl_slot_verify(AvbOps* ops,
                                      AvbSlotVerifyData* slot_verify_data,
                                      uint8_t* key_bytes,
                                      size_t key_size) {
  size_t i;
  size_t aftl_image_size;
  size_t vbmeta_size;
  uint8_t* current_aftl_blob;
  char part_name[AVB_PART_NAME_MAX_SIZE];
  char* pname;
  AftlSlotVerifyResult ret = AFTL_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;

  avb_assert(slot_verify_data != NULL);
  avb_assert(key_bytes != NULL);
  avb_assert(key_size == AVB_AFTL_PUB_KEY_SIZE);
  if (slot_verify_data->vbmeta_images == NULL) {
    return AFTL_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT;
  }

  current_aftl_blob = avb_malloc(AVB_AFTL_MAX_AFTL_IMAGE_SIZE);
  if (current_aftl_blob == NULL) {
    return AFTL_SLOT_VERIFY_RESULT_ERROR_OOM;
  }

  /* Walk through each vbmeta blob in the AvbSlotVerifyData struct. */
  for (i = 0; i < slot_verify_data->num_vbmeta_images; i++) {
    /* Rebuild partition name, appending the suffix */
    pname = slot_verify_data->vbmeta_images[i].partition_name;
    if (!avb_str_concat(part_name,
                        sizeof part_name,
                        (const char*)pname,
                        avb_strlen(pname),
                        slot_verify_data->ab_suffix,
                        avb_strlen(slot_verify_data->ab_suffix))) {
      avb_error("Partition name and suffix does not fit.\n");
      ret = AFTL_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
      break;
    }

    /* Use the partition info to find the AftlImage */
    vbmeta_size = slot_verify_data->vbmeta_images[i].vbmeta_size;
    ret = avb_aftl_find_aftl_image(
        ops, part_name, vbmeta_size, current_aftl_blob, &aftl_image_size);
    if (ret != AFTL_SLOT_VERIFY_RESULT_OK) {
      avb_errorv(part_name, ": Unable to find the AftlImage.\n", NULL);
      break;
    }

    /* Validate the AFTL image in the vbmeta image. */
    ret = avb_aftl_verify_image(slot_verify_data->vbmeta_images[i].vbmeta_data,
                                vbmeta_size,
                                current_aftl_blob,
                                aftl_image_size,
                                key_bytes,
                                key_size);
    if (ret != AVB_SLOT_VERIFY_RESULT_OK) break;
  }

  avb_free(current_aftl_blob);
  return ret;
}
