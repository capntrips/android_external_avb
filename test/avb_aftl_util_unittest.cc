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

#define AFTL_DESCRIPTOR_SIZE 1652ul
#define AFTL_DESCRIPTOR_MULTI_SIZE 3358ul

const char kAftlLogSigPath[] = "test/data/aftl_log_sig.bin";
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
    /* Read in test data from the aftl_descriptor and log_sig binaries. */
    base::GetFileSize(base::FilePath(kAftlLogSigPath), &log_sig_size_);
    if (log_sig_size_ != AVB_AFTL_SIGNATURE_SIZE) return;
    log_sig_bytes_ = (uint8_t*)avb_malloc(log_sig_size_);
    if (!log_sig_bytes_) return;
    base::ReadFile(
        base::FilePath(kAftlLogSigPath), (char*)log_sig_bytes_, log_sig_size_);

    base::GetFileSize(base::FilePath(kAftlDescriptorPath),
                      &aftl_descriptor_size);
    if (aftl_descriptor_size != AFTL_DESCRIPTOR_SIZE) return;
    aftl_blob = (uint8_t*)avb_malloc(aftl_descriptor_size);
    if (!aftl_blob) return;
    base::ReadFile(base::FilePath(kAftlDescriptorPath),
                   (char*)aftl_blob,
                   aftl_descriptor_size);
    /* Allocate and populate an AftlDescriptor for testing. */
    aftl_descriptor_ = parse_aftl_descriptor(aftl_blob, aftl_descriptor_size);
    avb_free(aftl_blob);
    /* Read in test data from the aftl_descriptor file with multiple ICPs. */
    base::GetFileSize(base::FilePath(kAftlDescriptorMultiPath),
                      &aftl_descriptor_size);
    if (aftl_descriptor_size != AFTL_DESCRIPTOR_MULTI_SIZE) return;
    aftl_blob = (uint8_t*)avb_malloc(aftl_descriptor_size);
    if (!aftl_blob) return;
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
    avb_free(log_sig_bytes_);
    BaseAvbToolTest::TearDown();
  }

  void TestAftlIcpHeader(AftlIcpHeader* aftl_header,
                         uint32_t descriptor_size,
                         uint16_t icp_count) {
    EXPECT_EQ(aftl_header->magic, 0x4c544641ul);
    EXPECT_EQ(aftl_header->required_icp_version_major, 1ul);
    EXPECT_EQ(aftl_header->required_icp_version_minor, 1ul);
    EXPECT_EQ(aftl_header->aftl_descriptor_size, descriptor_size);
    EXPECT_EQ(aftl_header->icp_count, icp_count);
  }

  void TestAftlIcpEntry(AftlIcpEntry* icp_entry) {
    /* Test each field in the AftlIcpEntry. */
    EXPECT_EQ(icp_entry->log_url_size, 10ul);
    EXPECT_EQ(icp_entry->leaf_index, 2ul);
    EXPECT_EQ(icp_entry->log_root_descriptor_size, 61ul);
    EXPECT_EQ(icp_entry->fw_info_leaf_size, 992ul);
    EXPECT_EQ(icp_entry->log_root_sig_size, AVB_AFTL_SIGNATURE_SIZE);
    EXPECT_EQ(icp_entry->proof_hash_count, 1);
    EXPECT_EQ(icp_entry->inc_proof_size, 32ul);
    EXPECT_EQ(mem_to_hexstring(icp_entry->log_url, 10), "61616161616161616161");
    /* Test the TrillianLogRootDescriptor fields. */
    EXPECT_EQ(icp_entry->log_root_descriptor.version, 1ul);
    EXPECT_EQ(icp_entry->log_root_descriptor.tree_size, 3ull);
    EXPECT_EQ(icp_entry->log_root_descriptor.root_hash_size,
              AVB_AFTL_HASH_SIZE);
    EXPECT_EQ(mem_to_hexstring(icp_entry->log_root_descriptor.root_hash,
                               AVB_AFTL_HASH_SIZE),
              "4414e445033df6006bd1f01a14188a79"
              "1fdd09464edc7016032c9f855f281088");
    EXPECT_EQ(icp_entry->log_root_descriptor.timestamp, 322325503ull);
    EXPECT_EQ(icp_entry->log_root_descriptor.revision, 0ull);
    EXPECT_EQ(icp_entry->log_root_descriptor.metadata_size, 0);
    /* Test the FirmwareInfo fields. */
    EXPECT_EQ(icp_entry->fw_info_leaf.vbmeta_hash_size, AVB_AFTL_HASH_SIZE);
    EXPECT_EQ(
        mem_to_hexstring(icp_entry->fw_info_leaf.vbmeta_hash,
                         AVB_AFTL_HASH_SIZE),
        "992e3ad5d916b8ab4f10d9aa69542983fc681d43cdb2a46f9eb875b8b5242824");
    /* Test the log_root_signature. */
    EXPECT_EQ(mem_to_hexstring(icp_entry->log_root_signature,
                               AVB_AFTL_SIGNATURE_SIZE),
              mem_to_hexstring(log_sig_bytes_, AVB_AFTL_SIGNATURE_SIZE));
    /* And finally the proof blob. */
    EXPECT_EQ(mem_to_hexstring((uint8_t*)icp_entry->proofs,
                               icp_entry->inc_proof_size),
              "fac54203e7cc696cf0dfcb42c92a1d9d"
              "baf70ad9e621f4bd8d98662f00e38255");
  }

 protected:
  AftlDescriptor* aftl_descriptor_;
  AftlDescriptor* aftl_descriptor_multi_;
  uint8_t* log_sig_bytes_;
  int64_t log_sig_size_;
};

TEST_F(AvbAftlUtilTest, AftlIcpHeaderStructure) {
  AftlIcpHeader* header;
  ASSERT_NE(aftl_descriptor_, nullptr);
  header = &(aftl_descriptor_->header);
  ASSERT_NE(header, nullptr);
  TestAftlIcpHeader(header, AFTL_DESCRIPTOR_SIZE, 1);
}

TEST_F(AvbAftlUtilTest, AftlDescriptorMultipleIcps) {
  AftlIcpHeader* header;
  size_t i;

  ASSERT_NE(aftl_descriptor_multi_, nullptr);
  header = &(aftl_descriptor_multi_->header);
  ASSERT_NE(header, nullptr);
  TestAftlIcpHeader(header, AFTL_DESCRIPTOR_MULTI_SIZE, 2);

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
