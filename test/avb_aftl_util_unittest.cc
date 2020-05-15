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

#include "libavb_aftl/avb_aftl_util.h"
#include <libavb_aftl/libavb_aftl.h>
#include "avb_unittest_util.h"
#include "libavb_aftl/avb_aftl_types.h"

namespace {

/* TODO(b/154115873): These VBMetas are manually generated. We need to implement
 * a mock in aftltool that generates an inclusion proof and call that mock from
 * the unit tests, similarly to what is done with GenerateVBMetaImage. */
const char kAftlImagePath[] = "test/data/aftl_output_vbmeta_with_1_icp.img";
const uint64_t kAftlImageOffset = 0x1100;
const char kAftlImageMultiPath[] =
    "test/data/aftl_output_vbmeta_with_2_icp_same_log.img";

}  // namespace

namespace avb {
/* Extend BaseAvbToolTest to take advantage of common checks and tooling. */
class AvbAftlUtilTest : public BaseAvbToolTest {
 public:
  AvbAftlUtilTest() {}
  ~AvbAftlUtilTest() {}
  void SetUp() override {
    std::string content;

    BaseAvbToolTest::SetUp();
    /* Read in test data from the aftl_image binaries. */
    ASSERT_TRUE(
        base::ReadFileToString(base::FilePath(kAftlImagePath), &content));
    content = content.substr(kAftlImageOffset);
    /* Allocate and populate an AftlImage for testing. */
    aftl_image_ = parse_aftl_image((uint8_t*)content.data(), content.size());

    /* Read in test data from the aftl_image file with multiple ICPs. */
    ASSERT_TRUE(
        base::ReadFileToString(base::FilePath(kAftlImageMultiPath), &content));
    content = content.substr(kAftlImageOffset);
    /* Allocate and populate an AftlImage for testing. */
    aftl_image_multi_ =
        parse_aftl_image((uint8_t*)content.data(), content.size());
  }

  void TearDown() override {
    free_aftl_image(aftl_image_);
    free_aftl_image(aftl_image_multi_);
    BaseAvbToolTest::TearDown();
  }

  void TestAftlImageHeader(AftlImageHeader* aftl_header, uint16_t icp_count) {
    EXPECT_EQ(aftl_header->magic, 0x4c544641ul);
    EXPECT_EQ(aftl_header->required_icp_version_major, 1ul);
    EXPECT_EQ(aftl_header->required_icp_version_minor, 2ul);
    EXPECT_EQ(aftl_header->icp_count, icp_count);
  }

  void TestAftlIcpEntry(AftlIcpEntry* icp_entry) {
    /* Test each field in the AftlIcpEntry. */
    EXPECT_GT(icp_entry->log_url_size, 0ul);
    EXPECT_GT(icp_entry->leaf_index, 1ul);
    EXPECT_GT(icp_entry->log_root_descriptor_size, 0ul);
    EXPECT_GT(icp_entry->annotation_leaf_size, 0ul);
    EXPECT_EQ(icp_entry->log_root_sig_size, AVB_AFTL_SIGNATURE_SIZE);
    EXPECT_GT(icp_entry->proof_hash_count, 0ul);
    EXPECT_LT(icp_entry->proof_hash_count, 64ul);
    EXPECT_GT(icp_entry->inc_proof_size, 0ul);
    EXPECT_EQ(mem_to_hexstring(icp_entry->log_url, 8), "6c6f672e656e6470");
    /* Test the TrillianLogRootDescriptor fields. */
    EXPECT_EQ(icp_entry->log_root_descriptor.version, 1ul);
    EXPECT_GT(icp_entry->log_root_descriptor.tree_size, 0ull);
    EXPECT_EQ(icp_entry->log_root_descriptor.root_hash_size,
              AVB_AFTL_HASH_SIZE);
    EXPECT_GT(icp_entry->log_root_descriptor.timestamp, 0ull);
    EXPECT_GT(icp_entry->log_root_descriptor.revision, 0ull);
    EXPECT_EQ(icp_entry->log_root_descriptor.metadata_size, 0);
    /* Test the FirmwareInfo fields. */
    EXPECT_EQ(icp_entry->annotation_leaf->annotation->vbmeta_hash_size,
              AVB_AFTL_HASH_SIZE);
    EXPECT_EQ(icp_entry->proof_hash_count * 32ul, icp_entry->inc_proof_size);
  }

 protected:
  AftlImage* aftl_image_;
  AftlImage* aftl_image_multi_;
};

TEST_F(AvbAftlUtilTest, AftlImageHeaderStructure) {
  AftlImageHeader* header;
  ASSERT_NE(aftl_image_, nullptr);
  header = &(aftl_image_->header);
  ASSERT_NE(header, nullptr);
  TestAftlImageHeader(header, 1);
}

TEST_F(AvbAftlUtilTest, AftlImageMultipleIcps) {
  AftlImageHeader* header;
  size_t i;

  ASSERT_NE(aftl_image_multi_, nullptr);
  header = &(aftl_image_multi_->header);
  ASSERT_NE(header, nullptr);
  TestAftlImageHeader(header, 2);

  for (i = 0; i < header->icp_count; i++) {
    ASSERT_NE(aftl_image_multi_->entries[i], nullptr)
        << " Failed at entry " << i;
    TestAftlIcpEntry(aftl_image_multi_->entries[i]);
  }
}

TEST_F(AvbAftlUtilTest, AftlIcpEntryStructure) {
  AftlIcpEntry* icp_entry;

  icp_entry = aftl_image_->entries[0];
  ASSERT_NE(icp_entry, nullptr);
  TestAftlIcpEntry(icp_entry);
}

} /* namespace avb */
