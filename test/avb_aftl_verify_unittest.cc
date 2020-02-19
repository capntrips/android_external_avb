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

#include <gtest/gtest.h>

#include <libavb_aftl/libavb_aftl.h>

#include "avb_unittest_util.h"
#include "libavb_aftl/avb_aftl_types.h"
#include "libavb_aftl/avb_aftl_util.h"
#include "libavb_aftl/avb_aftl_validate.h"
#include "libavb_aftl/avb_aftl_verify.h"

#define AFTL_DESCRIPTOR_SIZE 3554ul
#define AFTL_MAGIC "4146544c"

namespace {

const char kAftlDescriptorFindTestBin[] = "test/data/find_aftl_descriptor.bin";
const char kAftlTestKey[] = "test/data/aftl_log_key_bytes.bin";
const char kVbmetaBin[] = "test/data/aftl_verify_vbmeta.bin";
const char kAftlBin[] = "test/data/aftl_verify_aftl.bin";
const char kVbmetaFullBin[] = "test/data/aftl_verify_full.bin";

} /* namespace */

namespace avb {

/* Extend BaseAvbToolTest to take advantage of common checks and tooling. */
class AvbAftlVerifyTest : public BaseAvbToolTest {
 public:
  AvbAftlVerifyTest() {}
  ~AvbAftlVerifyTest() {}
  void SetUp() override {
    BaseAvbToolTest::SetUp();
    asv_test_data_ = NULL;

    /* Read in the test data. */
    base::GetFileSize(base::FilePath(kAftlDescriptorFindTestBin),
                      &blob_with_aftl_size_);
    blob_with_aftl_ = (uint8_t*)avb_malloc(blob_with_aftl_size_);
    if (blob_with_aftl_ == NULL) return;
    base::ReadFile(base::FilePath(kAftlDescriptorFindTestBin),
                   (char*)blob_with_aftl_,
                   blob_with_aftl_size_);

    base::GetFileSize(base::FilePath(kAftlTestKey), &key_size_);
    key_bytes_ = (uint8_t*)avb_malloc(key_size_);
    if (key_bytes_ == NULL) {
      return;
    }
    base::ReadFile(base::FilePath(kAftlTestKey), (char*)key_bytes_, key_size_);

    base::GetFileSize(base::FilePath(kVbmetaBin), &aftl_vbmeta_blob_size_);
    aftl_vbmeta_blob_ = (uint8_t*)avb_malloc(aftl_vbmeta_blob_size_);
    if (aftl_vbmeta_blob_ == NULL) {
      return;
    }
    base::ReadFile(base::FilePath(kVbmetaBin),
                   (char*)aftl_vbmeta_blob_,
                   aftl_vbmeta_blob_size_);

    base::GetFileSize(base::FilePath(kAftlBin), &aftl_blob_size_);
    aftl_blob_ = (uint8_t*)avb_malloc(aftl_blob_size_);
    if (aftl_blob_ == NULL) {
      return;
    }
    base::ReadFile(
        base::FilePath(kAftlBin), (char*)aftl_blob_, aftl_blob_size_);

    base::GetFileSize(base::FilePath(kVbmetaFullBin), &vbmeta_full_blob_size_);
    vbmeta_full_blob_ = (uint8_t*)avb_malloc(vbmeta_full_blob_size_);
    if (vbmeta_full_blob_ == NULL) {
      return;
    }
    base::ReadFile(base::FilePath(kVbmetaFullBin),
                   (char*)vbmeta_full_blob_,
                   vbmeta_full_blob_size_);

    /* Set up required parts of asv_test_data */
    asv_test_data_ = (AvbSlotVerifyData*)avb_calloc(sizeof(AvbSlotVerifyData));
    if (asv_test_data_ == NULL) {
      return;
    }
    asv_test_data_->num_vbmeta_images = 1;
    asv_test_data_->vbmeta_images =
        (AvbVBMetaData*)avb_calloc(sizeof(AvbVBMetaData));
    if (asv_test_data_->vbmeta_images == NULL) {
      return;
    }
    asv_test_data_->vbmeta_images[0].vbmeta_size = vbmeta_full_blob_size_;
    asv_test_data_->vbmeta_images[0].vbmeta_data =
        (uint8_t*)avb_calloc(asv_test_data_->vbmeta_images[0].vbmeta_size);
    if (asv_test_data_->vbmeta_images[0].vbmeta_data == NULL) {
      return;
    }
    memcpy(asv_test_data_->vbmeta_images[0].vbmeta_data,
           vbmeta_full_blob_,
           vbmeta_full_blob_size_);
  }

  void TearDown() override {
    if (blob_with_aftl_ != NULL) avb_free(blob_with_aftl_);
    if (key_bytes_ != NULL) avb_free(key_bytes_);
    if (aftl_vbmeta_blob_ != NULL) avb_free(aftl_vbmeta_blob_);
    if (aftl_blob_ != NULL) avb_free(aftl_blob_);
    if (vbmeta_full_blob_ != NULL) avb_free(vbmeta_full_blob_);
    if (asv_test_data_ != NULL) {
      if (asv_test_data_->vbmeta_images != NULL) {
        if (asv_test_data_->vbmeta_images[0].vbmeta_data != NULL) {
          avb_free(asv_test_data_->vbmeta_images[0].vbmeta_data);
        }
        avb_free(asv_test_data_->vbmeta_images);
      }
      avb_free(asv_test_data_);
    }
    BaseAvbToolTest::TearDown();
  }

 protected:
  AvbSlotVerifyData* asv_test_data_;
  uint8_t* key_bytes_;
  int64_t key_size_;
  uint8_t* blob_with_aftl_;
  int64_t blob_with_aftl_size_;

  uint8_t* aftl_vbmeta_blob_;
  int64_t aftl_vbmeta_blob_size_;
  uint8_t* aftl_blob_;
  int64_t aftl_blob_size_;
  uint8_t* vbmeta_full_blob_;
  int64_t vbmeta_full_blob_size_;
};

TEST_F(AvbAftlVerifyTest, AvbAftlFindAftlDescriptor) {
  uint8_t* aftl_offset;
  size_t aftl_size;

  aftl_size = aftl_vbmeta_blob_size_;
  aftl_offset = avb_aftl_find_aftl_descriptor(aftl_vbmeta_blob_, &aftl_size);
  EXPECT_EQ(aftl_offset, nullptr);
  EXPECT_EQ(aftl_size, 0ul);
  aftl_size = vbmeta_full_blob_size_;
  aftl_offset = avb_aftl_find_aftl_descriptor(vbmeta_full_blob_, &aftl_size);
  EXPECT_EQ(mem_to_hexstring(aftl_offset, 4), AFTL_MAGIC);
  EXPECT_EQ(aftl_size, AFTL_DESCRIPTOR_SIZE);
}

TEST_F(AvbAftlVerifyTest, AvbAftlVerifyDescriptor) {
  AvbSlotVerifyResult result;
  result = avb_aftl_verify_descriptor(aftl_vbmeta_blob_,
                                      aftl_vbmeta_blob_size_,
                                      aftl_vbmeta_blob_,
                                      aftl_vbmeta_blob_size_,
                                      key_bytes_,
                                      key_size_);
  EXPECT_EQ(result, AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION);

  result = avb_aftl_verify_descriptor(aftl_vbmeta_blob_,
                                      aftl_vbmeta_blob_size_,
                                      aftl_blob_,
                                      aftl_blob_size_,
                                      key_bytes_,
                                      key_size_);

  EXPECT_EQ(result, AVB_SLOT_VERIFY_RESULT_OK);
}

TEST_F(AvbAftlVerifyTest, AftlSlotVerify) {
  AvbSlotVerifyResult result =
      aftl_slot_verify(asv_test_data_, key_bytes_, key_size_);
  EXPECT_EQ(result, AVB_SLOT_VERIFY_RESULT_OK);
}

} /* namespace avb */
