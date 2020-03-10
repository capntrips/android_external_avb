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
#include "fake_avb_ops.h"
#include "libavb_aftl/avb_aftl_types.h"
#include "libavb_aftl/avb_aftl_util.h"
#include "libavb_aftl/avb_aftl_validate.h"
#include "libavb_aftl/avb_aftl_verify.h"

namespace {

/* Log transparency key */
const char kAftlTestKey[] = "test/data/aftl_log_key_bytes.bin";
/* Regular VBMeta structure without AFTL-specific data */
const char kVbmetaBin[] = "test/data/aftl_verify_vbmeta.bin";
/* Full vbmeta partition which contains the VBMeta above followed by its
 * associated AftlDescriptor */
const char kVbmetaWithAftlDescBin[] = "test/data/aftl_verify_full.img";

} /* namespace */

namespace avb {

/* Extend BaseAvbToolTest to take advantage of common checks and tooling. */
class AvbAftlVerifyTest : public BaseAvbToolTest,
                          public FakeAvbOpsDelegateWithDefaults {
 public:
  AvbAftlVerifyTest() {}
  ~AvbAftlVerifyTest() {}
  void SetUp() override {
    BaseAvbToolTest::SetUp();
    ops_.set_delegate(this);
    ops_.set_partition_dir(base::FilePath("test/data"));
    asv_test_data_ = NULL;

    /* Read in the test data. */
    base::GetFileSize(base::FilePath(kAftlTestKey), &key_size_);
    key_bytes_ = (uint8_t*)avb_malloc(key_size_);
    ASSERT_TRUE(key_bytes_ != NULL);
    base::ReadFile(base::FilePath(kAftlTestKey), (char*)key_bytes_, key_size_);

    base::GetFileSize(base::FilePath(kVbmetaBin), &vbmeta_blob_size_);
    vbmeta_blob_ = (uint8_t*)avb_malloc(vbmeta_blob_size_);
    ASSERT_TRUE(vbmeta_blob_ != NULL);
    base::ReadFile(
        base::FilePath(kVbmetaBin), (char*)vbmeta_blob_, vbmeta_blob_size_);

    base::GetFileSize(base::FilePath(kVbmetaWithAftlDescBin),
                      &vbmeta_full_blob_size_);
    vbmeta_full_blob_ = (uint8_t*)avb_malloc(vbmeta_full_blob_size_);
    ASSERT_TRUE(vbmeta_full_blob_ != NULL);
    base::ReadFile(base::FilePath(kVbmetaWithAftlDescBin),
                   (char*)vbmeta_full_blob_,
                   vbmeta_full_blob_size_);

    /* Set up required parts of asv_test_data */
    asv_test_data_ = (AvbSlotVerifyData*)avb_calloc(sizeof(AvbSlotVerifyData));
    ASSERT_TRUE(asv_test_data_ != NULL);
    asv_test_data_->ab_suffix = (char*)"";
    asv_test_data_->num_vbmeta_images = 1;
    asv_test_data_->vbmeta_images =
        (AvbVBMetaData*)avb_calloc(sizeof(AvbVBMetaData));
    ASSERT_TRUE(asv_test_data_->vbmeta_images != NULL);
    asv_test_data_->vbmeta_images[0].vbmeta_size = vbmeta_blob_size_;
    asv_test_data_->vbmeta_images[0].vbmeta_data =
        (uint8_t*)avb_calloc(vbmeta_blob_size_);
    ASSERT_TRUE(asv_test_data_->vbmeta_images[0].vbmeta_data != NULL);
    memcpy(asv_test_data_->vbmeta_images[0].vbmeta_data,
           vbmeta_blob_,
           vbmeta_blob_size_);
    asv_test_data_->vbmeta_images[0].partition_name = (char*)"aftl_verify_full";
  }

  void TearDown() override {
    if (key_bytes_ != NULL) avb_free(key_bytes_);
    if (vbmeta_blob_ != NULL) avb_free(vbmeta_blob_);
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

  uint8_t* vbmeta_blob_;
  int64_t vbmeta_blob_size_;
  uint8_t* vbmeta_full_blob_;
  int64_t vbmeta_full_blob_size_;
};

TEST_F(AvbAftlVerifyTest, Basic) {
  AvbSlotVerifyResult result =
      aftl_slot_verify(ops_.avb_ops(), asv_test_data_, key_bytes_, key_size_);
  EXPECT_EQ(result, AVB_SLOT_VERIFY_RESULT_OK);
}

TEST_F(AvbAftlVerifyTest, MissingAFTLDescriptor) {
  asv_test_data_->vbmeta_images[0].partition_name = (char*)"do-no-exist";
  AvbSlotVerifyResult result =
      aftl_slot_verify(ops_.avb_ops(), asv_test_data_, key_bytes_, key_size_);
  EXPECT_EQ(result, AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA);
}

TEST_F(AvbAftlVerifyTest, NonMatchingVBMeta) {
  asv_test_data_->vbmeta_images[0].vbmeta_data[0] = 'X';
  AvbSlotVerifyResult result =
      aftl_slot_verify(ops_.avb_ops(), asv_test_data_, key_bytes_, key_size_);
  EXPECT_EQ(result, AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION);
}

} /* namespace avb */
