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
const char kAftlTestKey[] = "test/data/aftl_pubkey_1.bin";
/* Full VBMeta partition which contains an AftlImage */
/* TODO(b/154115873): These VBMetas are manually generated. We need to implement
 * a mock in aftltool that generates an inclusion proof and call that mock from
 * the unit tests, similarly to what is done with GenerateVBMetaImage. */
const char kVbmetaWithAftlDescBin[] =
    "test/data/aftl_output_vbmeta_with_1_icp.img";
/* Size of the VBMetaImage in the partition */
const uint64_t kVbmetaSize = 0x1100;

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
    ASSERT_TRUE(base::ReadFileToString(base::FilePath(kAftlTestKey), &key_));
    ASSERT_TRUE(base::ReadFileToString(base::FilePath(kVbmetaWithAftlDescBin),
                                       &vbmeta_icp_));
    /* Keep a truncated version of the image without the ICP */
    vbmeta_ = vbmeta_icp_.substr(0, kVbmetaSize);

    /* Set up required parts of asv_test_data */
    asv_test_data_ = (AvbSlotVerifyData*)avb_calloc(sizeof(AvbSlotVerifyData));
    ASSERT_TRUE(asv_test_data_ != NULL);
    asv_test_data_->ab_suffix = (char*)"";
    asv_test_data_->num_vbmeta_images = 1;
    asv_test_data_->vbmeta_images =
        (AvbVBMetaData*)avb_calloc(sizeof(AvbVBMetaData));
    ASSERT_TRUE(asv_test_data_->vbmeta_images != NULL);
    asv_test_data_->vbmeta_images[0].vbmeta_size = vbmeta_.size();
    asv_test_data_->vbmeta_images[0].vbmeta_data =
        (uint8_t*)avb_calloc(vbmeta_.size());
    ASSERT_TRUE(asv_test_data_->vbmeta_images[0].vbmeta_data != NULL);
    memcpy(asv_test_data_->vbmeta_images[0].vbmeta_data,
           vbmeta_.data(),
           vbmeta_.size());
    asv_test_data_->vbmeta_images[0].partition_name =
        (char*)"aftl_output_vbmeta_with_1_icp";
  }

  void TearDown() override {
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
  std::string key_;
  std::string vbmeta_;
  std::string vbmeta_icp_;
};

TEST_F(AvbAftlVerifyTest, Basic) {
  AftlSlotVerifyResult result = aftl_slot_verify(
      ops_.avb_ops(), asv_test_data_, (uint8_t*)key_.data(), key_.size());
  EXPECT_EQ(result, AFTL_SLOT_VERIFY_RESULT_OK);
}

TEST_F(AvbAftlVerifyTest, PartitionError) {
  asv_test_data_->vbmeta_images[0].partition_name = (char*)"do-no-exist";
  AftlSlotVerifyResult result = aftl_slot_verify(
      ops_.avb_ops(), asv_test_data_, (uint8_t*)key_.data(), key_.size());
  EXPECT_EQ(result, AFTL_SLOT_VERIFY_RESULT_ERROR_IMAGE_NOT_FOUND);
}

TEST_F(AvbAftlVerifyTest, MismatchingVBMeta) {
  asv_test_data_->vbmeta_images[0].vbmeta_data[0] = 'X';
  AftlSlotVerifyResult result = aftl_slot_verify(
      ops_.avb_ops(), asv_test_data_, (uint8_t*)key_.data(), key_.size());
  EXPECT_EQ(result, AFTL_SLOT_VERIFY_RESULT_ERROR_VBMETA_HASH_MISMATCH);
}

TEST_F(AvbAftlVerifyTest, InvalidKey) {
  // Corrupt the key in order to fail the verification: complement the last
  // byte, we keep the key header valid.
  key_[key_.size() - 1] = ~key_[key_.size() - 1];
  AftlSlotVerifyResult result = aftl_slot_verify(
      ops_.avb_ops(), asv_test_data_, (uint8_t*)key_.data(), key_.size());
  EXPECT_EQ(result, AFTL_SLOT_VERIFY_RESULT_ERROR_INVALID_PROOF_SIGNATURE);
}

} /* namespace avb */
