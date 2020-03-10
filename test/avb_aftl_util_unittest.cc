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

const char kAftlDescriptorPath[] = "test/data/aftl_descriptor.bin";
const char kAftlDescriptorMultiPath[] = "test/data/aftl_descriptor_multi.bin";

}  // namespace

namespace avb {
/* Extend BaseAvbToolTest to take advantage of common checks and tooling. */
class AvbAftlUtilTest : public BaseAvbToolTest {
 public:
  AvbAftlUtilTest() {}
  ~AvbAftlUtilTest() {}
  void SetUp() override {
    uint8_t* aftl_blob;
    int64_t aftl_descriptor_size;

    BaseAvbToolTest::SetUp();
    /* Read in test data from the aftl_descriptor binaries. */
    base::GetFileSize(base::FilePath(kAftlDescriptorPath),
                      &aftl_descriptor_size);
    ASSERT_GT(aftl_descriptor_size, 0);
    aftl_blob = (uint8_t*)avb_malloc(aftl_descriptor_size);
    ASSERT_TRUE(aftl_blob != NULL);
    base::ReadFile(base::FilePath(kAftlDescriptorPath),
                   (char*)aftl_blob,
                   aftl_descriptor_size);
    /* Allocate and populate an AftlDescriptor for testing. */
    aftl_descriptor_ = parse_aftl_descriptor(aftl_blob, aftl_descriptor_size);
    avb_free(aftl_blob);

    /* Read in test data from the aftl_descriptor file with multiple ICPs. */
    base::GetFileSize(base::FilePath(kAftlDescriptorMultiPath),
                      &aftl_descriptor_size);
    ASSERT_GT(aftl_descriptor_size, 0);
    aftl_blob = (uint8_t*)avb_malloc(aftl_descriptor_size);
    ASSERT_TRUE(aftl_blob != NULL);
    base::ReadFile(base::FilePath(kAftlDescriptorMultiPath),
                   (char*)aftl_blob,
                   aftl_descriptor_size);
    /* Allocate and populate an AftlDescriptor for testing. */
    aftl_descriptor_multi_ =
        parse_aftl_descriptor(aftl_blob, aftl_descriptor_size);
    avb_free(aftl_blob);
  }

  void TearDown() override {
    free_aftl_descriptor(aftl_descriptor_);
    free_aftl_descriptor(aftl_descriptor_multi_);
    BaseAvbToolTest::TearDown();
  }

  void TestAftlIcpHeader(AftlIcpHeader* aftl_header,
                         uint16_t icp_count) {
    EXPECT_EQ(aftl_header->magic, 0x4c544641ul);
    EXPECT_EQ(aftl_header->required_icp_version_major, 1ul);
    EXPECT_EQ(aftl_header->required_icp_version_minor, 1ul);
    EXPECT_EQ(aftl_header->icp_count, icp_count);
  }

  void TestAftlIcpEntry(AftlIcpEntry* icp_entry) {
    /* Test each field in the AftlIcpEntry. */
    EXPECT_GT(icp_entry->log_url_size, 0ul);
    EXPECT_GT(icp_entry->leaf_index, 1ul);
    EXPECT_GT(icp_entry->log_root_descriptor_size, 0ul);
    EXPECT_GT(icp_entry->fw_info_leaf_size, 0ul);
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
    EXPECT_EQ(icp_entry->fw_info_leaf.vbmeta_hash_size, AVB_AFTL_HASH_SIZE);
    EXPECT_EQ(icp_entry->proof_hash_count * 32ul, icp_entry->inc_proof_size);
  }

 protected:
  AftlDescriptor* aftl_descriptor_;
  AftlDescriptor* aftl_descriptor_multi_;
};

TEST_F(AvbAftlUtilTest, AftlIcpHeaderStructure) {
  AftlIcpHeader* header;
  ASSERT_NE(aftl_descriptor_, nullptr);
  header = &(aftl_descriptor_->header);
  ASSERT_NE(header, nullptr);
  TestAftlIcpHeader(header, 1);
}

TEST_F(AvbAftlUtilTest, AftlDescriptorMultipleIcps) {
  AftlIcpHeader* header;
  size_t i;

  ASSERT_NE(aftl_descriptor_multi_, nullptr);
  header = &(aftl_descriptor_multi_->header);
  ASSERT_NE(header, nullptr);
  TestAftlIcpHeader(header, 2);

  for (i = 0; i < header->icp_count; i++) {
    ASSERT_NE(aftl_descriptor_multi_->entries[i], nullptr)
        << " Failed at entry " << i;
    TestAftlIcpEntry(aftl_descriptor_multi_->entries[i]);
  }
}

TEST_F(AvbAftlUtilTest, AftlIcpEntryStructure) {
  AftlIcpEntry* icp_entry;

  icp_entry = aftl_descriptor_->entries[0];
  ASSERT_NE(icp_entry, nullptr);
  TestAftlIcpEntry(icp_entry);
}

} /* namespace avb */
