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

namespace {

/* Public part of testkey_rsa4096.pem, in the AvbRsaPublicKey format. Generated
 * using:
 *   $ openssl rsa -in testkey_rsa4096.pem -pubout -out testkey_rsa4096_pub.pem
 *   $ avbtool extract_public_key --key testkey_rsa4096_pub.pem --output \
 *     testkey_rsa4096_pub.bin.
 */
const char kKeyBytesPath[] = "test/data/testkey_rsa4096_pub.bin";
/* Example VBMeta. Its hash should match the value kVBMetaHash defined below. */
const char kVBMetaPath[] = "test/data/aftl_input_vbmeta.img";

} /* namespace */

namespace avb {

/* Extend BaseAvbToolTest to take advantage of common checks and tooling. */
class AvbAftlValidateTest : public BaseAvbToolTest {
 public:
  AvbAftlValidateTest() {}
  ~AvbAftlValidateTest() {}
  void SetUp() override {
    /* Generate an artificial inclusion proof with its own annotation. The
     * annotation matches the kVBMetaPath file. It is signed using the
     * testkey_rsa4096.pem key. */
    /* We define the constants below as string literals (to be able to annotate
     * the bytes). We keep their sizes in a separate variable as sizeof will
     * include the final null byte that is automatically appended. */
    const uint8_t kAnnotationLeafHeader[] =
        "\x01"                              // Version
        "\x00\x00\x00\x00\x00\x00\x00\x00"  // Timestamp
        "\x01";                             // Leaf Type
    const size_t kAnnotationLeafHeaderSize = sizeof(kAnnotationLeafHeader) - 1;
    const uint8_t kSignature[] =
        "\x00"   // Hash Type
        "\x00"   // Signature Type
        "\x00";  // Signature size
    const size_t kSignatureSize = sizeof(kSignature) - 1;
    const uint8_t kAnnotationHeader[] = "\x20";  // VBMeta hash size
    const size_t kAnnotationHeaderSize = sizeof(kAnnotationHeader) - 1;
    /* This is the SHA256 hash of the image at kVBMetaPath */
    const uint8_t kVBMetaHash[] =
        "\x34\x1c\x6c\xf2\x4b\xc1\xe6\x4a\xb1\x03\xa0\xee\xe1\x9d\xee\x9c"
        "\x35\x34\xdb\x07\x17\x29\xb4\xad\xd0\xce\xa0\xbd\x52\x92\x54\xec";
    const uint8_t kAnnotationFooter[] =
        "\x03"      // Version incremental size
        "123"       // Version incremental
        "\x00"      // Manufacturer key hash size
        "\x00\x05"  // Description size
        "abcde";    // Description
    const size_t kAnnotationFooterSize = sizeof(kAnnotationFooter) - 1;
    const uint8_t kLogRootDescriptorHeader[] =
        "\x00\x01"                          // Version
        "\x00\x00\x00\x00\x00\x00\x00\x03"  // Tree size
        "\x20";                             // Root hash size
    const size_t kLogRootDescriptorHeaderSize =
        sizeof(kLogRootDescriptorHeader) - 1;
    const uint8_t kLogRootDescriptorRootHash[] =
        "\x40\x79\x2f\xf1\xcb\xfc\xd1\x8a\x13\x70\x90\xaf\x6a\x16\x4d\xa9"
        "\x36\x80\x99\xb3\xf9\x7f\x99\x13\x3e\x07\xff\xbc\x73\x42\xfc\xc7";
    const uint8_t kLogRootDescriptorFooter[] =
        "\x00\x00\x00\x00\x13\x36\x4b\xff"  // Timestamp
        "\x00\x00\x00\x00\x00\x00\x00\x00"  // Revision
        "\x00\x00";                         // Metadata size
    const size_t kLogRootDescriptorFooterSize =
        sizeof(kLogRootDescriptorFooter) - 1;
    /* Signature of the log root descriptor.
     *   $ openssl dgst -sha256 -sign testkey_rsa4096.pem \
     *   -out kLogRootHashSignature log_root_descriptor_raw
     * log_root_descriptor_raw is defined as the concatenation:
     * kLogRootDescriptorHeader || kLogRootDescriptorRootHash ||
     * kLogRootDescriptorFooter */
    const uint8_t kLogRootHashSignature[] = {
        0x55, 0x1d, 0xd3, 0x13, 0x3c, 0x41, 0xde, 0x67, 0x79, 0xf1, 0xc6, 0xad,
        0x72, 0x10, 0xff, 0xfb, 0x6d, 0xac, 0xc1, 0x1c, 0x06, 0x2a, 0x3e, 0xa8,
        0xd9, 0xf3, 0x8c, 0x9c, 0x67, 0xbe, 0x1e, 0x8e, 0xe1, 0x02, 0xf6, 0xdb,
        0xd2, 0x5c, 0x31, 0x4b, 0x26, 0xad, 0x9a, 0xd1, 0xf5, 0x7d, 0xb9, 0x6b,
        0x4b, 0xf1, 0x7a, 0x89, 0x9d, 0xf0, 0x17, 0xb4, 0xee, 0xb2, 0x08, 0x0d,
        0xd8, 0x99, 0xac, 0x7b, 0x34, 0x1f, 0xd1, 0x9c, 0x2e, 0x0c, 0xd1, 0xb1,
        0x42, 0x34, 0xf2, 0x65, 0xbb, 0x79, 0x7a, 0xac, 0x23, 0x37, 0xec, 0xfc,
        0xff, 0xbf, 0x66, 0x51, 0xed, 0x3e, 0xa7, 0x45, 0x3a, 0xf9, 0x72, 0xaa,
        0x01, 0x3c, 0xfd, 0x59, 0x01, 0x67, 0x67, 0xb4, 0x57, 0x23, 0xb6, 0x7e,
        0x59, 0x82, 0xb3, 0x98, 0xa2, 0x57, 0xd4, 0x64, 0x83, 0xaa, 0x02, 0x17,
        0x87, 0xfd, 0xa2, 0xe2, 0x3b, 0xa8, 0xf5, 0xc2, 0xfb, 0xce, 0x7f, 0x59,
        0x72, 0x10, 0xc5, 0x11, 0x81, 0x80, 0x20, 0x4a, 0x3e, 0xf9, 0x85, 0x2e,
        0x44, 0x94, 0x87, 0xec, 0xfa, 0x2e, 0x8f, 0x75, 0x00, 0x6f, 0x52, 0x1b,
        0x4d, 0x5c, 0xfc, 0xe4, 0x1f, 0xe2, 0x94, 0xbc, 0x8c, 0xe8, 0x7f, 0x74,
        0x14, 0x2f, 0x66, 0x8e, 0xfb, 0x11, 0x34, 0xde, 0x80, 0x21, 0x92, 0xc3,
        0x52, 0xa7, 0xf7, 0x5e, 0x49, 0x53, 0x21, 0x7d, 0x8b, 0xa2, 0xcb, 0x84,
        0x80, 0x64, 0x0d, 0xd7, 0xd0, 0x6d, 0x6f, 0x2a, 0x98, 0x57, 0x3b, 0x95,
        0xa1, 0x63, 0x39, 0x00, 0x22, 0x9e, 0x5a, 0x75, 0x07, 0x10, 0x1f, 0x7e,
        0xdb, 0x05, 0x5d, 0x3d, 0x76, 0x75, 0x3c, 0x1a, 0xd4, 0x1e, 0x8d, 0x6e,
        0xce, 0x57, 0xd6, 0xce, 0x23, 0xc0, 0x23, 0x4c, 0xcb, 0x10, 0xec, 0x59,
        0x22, 0x64, 0x57, 0x33, 0x1c, 0x3f, 0xa9, 0x43, 0x97, 0xc1, 0xc0, 0x93,
        0x5a, 0x16, 0x80, 0x51, 0x56, 0x28, 0x98, 0x33, 0xee, 0x1a, 0xf8, 0x38,
        0x7a, 0xaa, 0xdb, 0x43, 0x39, 0x90, 0x9e, 0x74, 0xb7, 0x9f, 0xfe, 0xa5,
        0x84, 0x69, 0xf5, 0x77, 0x80, 0x92, 0xec, 0x06, 0x06, 0xe0, 0xd2, 0x98,
        0x34, 0x66, 0x25, 0xc3, 0x7c, 0x89, 0x78, 0x3a, 0x0b, 0x48, 0x49, 0x37,
        0x46, 0x07, 0xc4, 0xc8, 0x04, 0x72, 0x45, 0x60, 0x36, 0x98, 0x2d, 0x47,
        0xfe, 0xba, 0x74, 0xb9, 0xb0, 0xe4, 0xf5, 0x45, 0xa0, 0xfb, 0x4a, 0x53,
        0xe0, 0x16, 0x6a, 0x6b, 0x82, 0xcc, 0x33, 0x1c, 0x3c, 0x64, 0xe0, 0x90,
        0x3c, 0x59, 0xfa, 0x04, 0x51, 0xe0, 0xe8, 0xaa, 0xe9, 0x92, 0x43, 0x04,
        0x2a, 0x49, 0xd4, 0xdf, 0xac, 0x1d, 0x46, 0x44, 0xad, 0x65, 0x62, 0xaf,
        0x44, 0x16, 0xb0, 0x05, 0x56, 0x2b, 0xa4, 0xad, 0x4c, 0x7e, 0xbd, 0x04,
        0x95, 0xcb, 0xce, 0x0e, 0xf6, 0xd5, 0x4b, 0x3a, 0xc0, 0xde, 0x1e, 0xf8,
        0xfa, 0xf5, 0x73, 0x4a, 0x6d, 0xc2, 0x4a, 0xe1, 0xaf, 0xae, 0xd8, 0x31,
        0x23, 0x16, 0x5d, 0x15, 0x41, 0xe6, 0xbf, 0x4a, 0xe0, 0xf3, 0xdd, 0x74,
        0x32, 0x96, 0x64, 0x4c, 0x16, 0x7d, 0xd3, 0xad, 0x21, 0x47, 0x2b, 0x17,
        0xb9, 0xf3, 0x84, 0x38, 0x80, 0x60, 0xb6, 0xcb, 0x24, 0x45, 0x24, 0x90,
        0x74, 0xe9, 0x50, 0xea, 0x2e, 0x1f, 0xc2, 0x74, 0x36, 0xa2, 0xf5, 0xd7,
        0x24, 0xb3, 0xa1, 0x1f, 0xd3, 0x39, 0x61, 0x67, 0x37, 0xe4, 0x2a, 0x20,
        0x67, 0x95, 0x53, 0x9d, 0xd4, 0xdb, 0x4f, 0xa6, 0xb8, 0x7f, 0x91, 0xb2,
        0xc5, 0x6f, 0x71, 0x3c, 0x86, 0xc8, 0x36, 0x8d, 0xa4, 0x4d, 0x53, 0x6b,
        0x3f, 0xe6, 0xce, 0xf1, 0x7a, 0xa2, 0x2e, 0x53, 0x80, 0x4c, 0x52, 0x9d,
        0x3e, 0xd7, 0xec, 0x47, 0x4a, 0xfa, 0x84, 0xa5, 0x9a, 0x2f, 0x7b, 0xfc,
        0xfc, 0xe8, 0xa4, 0x09, 0xfb, 0xb5, 0xb7, 0xf2};
    BaseAvbToolTest::SetUp();

    /* Read in test data from the key and log_sig binaries. */
    ASSERT_TRUE(
        base::ReadFileToString(base::FilePath(kKeyBytesPath), &key_bytes_));

    /* Allocate and populate the inclusion proof */
    icp_entry_ = (AftlIcpEntry*)avb_malloc(sizeof(AftlIcpEntry));
    if (!icp_entry_) return;
    icp_entry_->log_root_descriptor.version = 1;
    icp_entry_->log_root_descriptor.tree_size = 3;
    icp_entry_->log_root_descriptor.root_hash_size = AVB_AFTL_HASH_SIZE;
    icp_entry_->log_root_descriptor.timestamp = 322325503;
    icp_entry_->log_root_descriptor.revision = 0;
    icp_entry_->log_root_descriptor.metadata_size = 0;
    icp_entry_->log_root_descriptor.metadata = NULL;
    icp_entry_->log_root_descriptor_size = kLogRootDescriptorHeaderSize +
                                           AVB_AFTL_HASH_SIZE +
                                           kLogRootDescriptorFooterSize;
    icp_entry_->log_root_descriptor_raw =
        (uint8_t*)avb_malloc(icp_entry_->log_root_descriptor_size);
    if (!icp_entry_->log_root_descriptor_raw) {
      return;
    }
    memcpy(icp_entry_->log_root_descriptor_raw,
           kLogRootDescriptorHeader,
           kLogRootDescriptorHeaderSize);
    memcpy(icp_entry_->log_root_descriptor_raw + kLogRootDescriptorHeaderSize,
           kLogRootDescriptorRootHash,
           AVB_AFTL_HASH_SIZE);
    memcpy(icp_entry_->log_root_descriptor_raw + kLogRootDescriptorHeaderSize +
               AVB_AFTL_HASH_SIZE,
           kLogRootDescriptorFooter,
           kLogRootDescriptorFooterSize);
    icp_entry_->log_root_descriptor.root_hash =
        (uint8_t*)avb_malloc(AVB_AFTL_HASH_SIZE);
    if (!icp_entry_->log_root_descriptor.root_hash) return;
    /* Copy the hash from within the raw version */
    memcpy(icp_entry_->log_root_descriptor.root_hash,
           kLogRootDescriptorRootHash,
           AVB_AFTL_HASH_SIZE);
    icp_entry_->log_root_sig_size = AVB_AFTL_SIGNATURE_SIZE;
    icp_entry_->log_root_signature =
        (uint8_t*)avb_malloc(AVB_AFTL_SIGNATURE_SIZE);
    memcpy(icp_entry_->log_root_signature,
           kLogRootHashSignature,
           AVB_AFTL_SIGNATURE_SIZE);

    /* Allocate the annotation leaf */
    icp_entry_->annotation_leaf_size =
        kAnnotationLeafHeaderSize + kSignatureSize + kAnnotationHeaderSize +
        AVB_AFTL_HASH_SIZE + kAnnotationFooterSize;
    icp_entry_->annotation_leaf =
        (SignedVBMetaPrimaryAnnotationLeaf*)avb_calloc(
            sizeof(SignedVBMetaPrimaryAnnotationLeaf));
    if (!icp_entry_->annotation_leaf) return;
    icp_entry_->annotation_leaf->version = 1;
    icp_entry_->annotation_leaf->timestamp = 0;
    icp_entry_->annotation_leaf->leaf_type =
        AVB_AFTL_SIGNED_VBMETA_PRIMARY_ANNOTATION_LEAF;
    icp_entry_->annotation_leaf->annotation =
        (VBMetaPrimaryAnnotation*)avb_calloc(sizeof(VBMetaPrimaryAnnotation));
    if (!icp_entry_->annotation_leaf->annotation) return;
    icp_entry_->annotation_leaf->annotation->vbmeta_hash_size =
        AVB_AFTL_HASH_SIZE;
    icp_entry_->annotation_leaf->annotation->vbmeta_hash =
        (uint8_t*)avb_calloc(AVB_AFTL_HASH_SIZE);
    if (!icp_entry_->annotation_leaf->annotation->vbmeta_hash) return;
    memcpy(icp_entry_->annotation_leaf->annotation->vbmeta_hash,
           kVBMetaHash,
           AVB_AFTL_HASH_SIZE);
    icp_entry_->annotation_leaf_raw =
        (uint8_t*)avb_calloc(icp_entry_->annotation_leaf_size);
    if (!icp_entry_->annotation_leaf_raw) return;
    memcpy(icp_entry_->annotation_leaf_raw,
           kAnnotationLeafHeader,
           kAnnotationLeafHeaderSize);
    memcpy(icp_entry_->annotation_leaf_raw + kAnnotationLeafHeaderSize,
           kSignature,
           kSignatureSize);
    memcpy(icp_entry_->annotation_leaf_raw + kAnnotationLeafHeaderSize +
               kSignatureSize,
           kAnnotationHeader,
           kAnnotationHeaderSize);
    memcpy(icp_entry_->annotation_leaf_raw + kAnnotationLeafHeaderSize +
               kSignatureSize + kAnnotationHeaderSize,
           kVBMetaHash,
           AVB_AFTL_HASH_SIZE);
    memcpy(icp_entry_->annotation_leaf_raw + kAnnotationLeafHeaderSize +
               kSignatureSize + kAnnotationHeaderSize + AVB_AFTL_HASH_SIZE,
           kAnnotationFooter,
           kAnnotationFooterSize);

    icp_entry_->leaf_index = 2;
    icp_entry_->proofs =
        (uint8_t(*)[AVB_AFTL_HASH_SIZE])avb_calloc(AVB_AFTL_HASH_SIZE);
    memcpy(icp_entry_->proofs[0],
           "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
           "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
           AVB_AFTL_HASH_SIZE);
    icp_entry_->proof_hash_count = 1;
  }

  void TearDown() override {
    if (icp_entry_) {
      if (icp_entry_->annotation_leaf_raw)
        avb_free(icp_entry_->annotation_leaf_raw);
      if (icp_entry_->annotation_leaf) {
        if (icp_entry_->annotation_leaf->annotation) {
          if (icp_entry_->annotation_leaf->annotation->vbmeta_hash)
            avb_free(icp_entry_->annotation_leaf->annotation->vbmeta_hash);
          avb_free(icp_entry_->annotation_leaf->annotation);
        }
        avb_free(icp_entry_->annotation_leaf);
      }
      if (icp_entry_->log_root_descriptor.root_hash)
        avb_free(icp_entry_->log_root_descriptor.root_hash);
      if (icp_entry_->log_root_descriptor_raw)
        avb_free(icp_entry_->log_root_descriptor_raw);
      if (icp_entry_->log_root_signature)
        avb_free(icp_entry_->log_root_signature);
      if (icp_entry_->proofs) avb_free(icp_entry_->proofs);
      avb_free(icp_entry_);
    }
    BaseAvbToolTest::TearDown();
  }

 protected:
  AftlIcpEntry* icp_entry_;
  std::string key_bytes_;
};

TEST_F(AvbAftlValidateTest, VerifyEntrySignature) {
  EXPECT_EQ(true,
            avb_aftl_verify_entry_signature(
                (uint8_t*)key_bytes_.data(), key_bytes_.size(), icp_entry_));
}

TEST_F(AvbAftlValidateTest, VerifyIcpRootHash) {
  EXPECT_EQ(true, avb_aftl_verify_icp_root_hash(icp_entry_));
}

TEST_F(AvbAftlValidateTest, VerifyVbmetaHash) {
  std::string vbmeta;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath(kVBMetaPath), &vbmeta));
  EXPECT_EQ(true,
            avb_aftl_verify_vbmeta_hash(
                (uint8_t*)vbmeta.data(), vbmeta.size(), icp_entry_));
}

TEST_F(AvbAftlValidateTest, RootFromIcp) {
  /* Tests from trillian root_from_icp functionality:
     https://github.com/google/trillian/blob/master/merkle/log_verifier_test.go
  */
  uint64_t leaf_index;
  uint64_t tree_size;
  uint8_t proof[3][AVB_AFTL_HASH_SIZE];
  uint8_t leaf_hash[AVB_AFTL_HASH_SIZE];
  uint8_t hash[AVB_AFTL_HASH_SIZE];

  leaf_index = 0;
  tree_size = 8;
  avb_aftl_rfc6962_hash_leaf((uint8_t*)"", 0, leaf_hash);
  memcpy(proof[0],
         "\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
         "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7",
         AVB_AFTL_HASH_SIZE);
  memcpy(proof[1],
         "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
         "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
         AVB_AFTL_HASH_SIZE);
  memcpy(proof[2],
         "\x6b\x47\xaa\xf2\x9e\xe3\xc2\xaf\x9a\xf8\x89\xbc\x1f\xb9\x25\x4d"
         "\xab\xd3\x11\x77\xf1\x62\x32\xdd\x6a\xab\x03\x5c\xa3\x9b\xf6\xe4",
         AVB_AFTL_HASH_SIZE);
  avb_aftl_root_from_icp(
      leaf_index, tree_size, proof, 3, leaf_hash, AVB_AFTL_HASH_SIZE, hash);
  EXPECT_EQ("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on test #1";

  leaf_index = 5;
  tree_size = 8;
  avb_aftl_rfc6962_hash_leaf((uint8_t*)"@ABC", 4, leaf_hash);
  memcpy(proof[0],
         "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
         "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
         AVB_AFTL_HASH_SIZE);
  memcpy(proof[1],
         "\xca\x85\x4e\xa1\x28\xed\x05\x0b\x41\xb3\x5f\xfc\x1b\x87\xb8\xeb"
         "\x2b\xde\x46\x1e\x9e\x3b\x55\x96\xec\xe6\xb9\xd5\x97\x5a\x0a\xe0",
         AVB_AFTL_HASH_SIZE);
  memcpy(proof[2],
         "\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
         "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7",
         AVB_AFTL_HASH_SIZE);
  avb_aftl_root_from_icp(
      leaf_index, tree_size, proof, 3, leaf_hash, AVB_AFTL_HASH_SIZE, hash);
  EXPECT_EQ("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on test #2";

  leaf_index = 2;
  tree_size = 3;
  avb_aftl_rfc6962_hash_leaf((uint8_t*)"\x10", 1, leaf_hash);
  memcpy(proof[0],
         "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
         "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
         AVB_AFTL_HASH_SIZE);
  avb_aftl_root_from_icp(
      leaf_index, tree_size, proof, 1, leaf_hash, AVB_AFTL_HASH_SIZE, hash);
  EXPECT_EQ("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on test #3";

  leaf_index = 1;
  tree_size = 5;
  avb_aftl_rfc6962_hash_leaf((uint8_t*)"\x00", 1, leaf_hash);
  memcpy(proof[0],
         "\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
         "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d",
         AVB_AFTL_HASH_SIZE);
  memcpy(proof[1],
         "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
         "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
         AVB_AFTL_HASH_SIZE);
  memcpy(proof[2],
         "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
         "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
         AVB_AFTL_HASH_SIZE);
  avb_aftl_root_from_icp(
      leaf_index, tree_size, proof, 3, leaf_hash, AVB_AFTL_HASH_SIZE, hash);
  EXPECT_EQ("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on test #4";
}

TEST_F(AvbAftlValidateTest, ChainInner) {
  uint8_t hash[AVB_AFTL_HASH_SIZE];
  uint8_t seed[AVB_AFTL_HASH_SIZE];
  uint8_t proof[4][AVB_AFTL_HASH_SIZE];
  uint64_t i;

  for (i = 0; i < AVB_AFTL_HASH_SIZE; i++) {
    hash[i] = 0;
  }

  memcpy(seed, "1234567890abcdefghijklmnopqrstuv", AVB_AFTL_HASH_SIZE);
  memcpy(proof[0], "abcdefghijklmnopqrstuvwxyz123456", AVB_AFTL_HASH_SIZE);
  avb_aftl_chain_inner(seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 1, 0, hash);
  EXPECT_EQ("9cb6af81b146b6a81d911d26f4c0d467265a3385d6caf926d5515e58efd161a3",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\", proof ["
      << "\"abcdefghijklmnopqrstuvwxyz123456\"], and leaf_index 0";
  memcpy(proof[1], "7890abcdefghijklmnopqrstuvwxyz12", AVB_AFTL_HASH_SIZE);
  avb_aftl_chain_inner(seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 2, 0, hash);
  EXPECT_EQ("368d8213cd7d62335a84b3a3d75c8a0302c0d63c93cbbd22c5396dc4c75ba019",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\", proof ["
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\"],"
      << " and leaf_index 0";
  avb_aftl_chain_inner(seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 2, 1, hash);
  EXPECT_EQ("78418158eb5943c50ec581b41f105ba9aecc1b9e7aba3ea2e93021cbd5bd166e",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\", proof ["
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\"],"
      << " and leaf_index 1";
  memcpy(proof[2], "abcdefghijklmn0pqrstuvwxyz123456", AVB_AFTL_HASH_SIZE);
  memcpy(proof[3], "7890abcdefgh1jklmnopqrstuvwxyz12", AVB_AFTL_HASH_SIZE);
  avb_aftl_chain_inner(seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 4, 1, hash);
  EXPECT_EQ("83309c48fb92707f5788b6dd4c9a89042dff20856ad9529b7fb8e5cdf47c04f8",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\", proof ["
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\","
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\"]"
      << " and leaf_index 1";
  avb_aftl_chain_inner(seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 4, 3, hash);
  EXPECT_EQ("13e5f7e441dc4dbea659acbc989ac33222f4447546e3dac36b0e0c9977d52b97",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\", proof ["
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\","
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\"]"
      << " and leaf_index 3";
}

TEST_F(AvbAftlValidateTest, ChainBorderRight) {
  uint8_t hash[AVB_AFTL_HASH_SIZE];
  uint8_t seed[AVB_AFTL_HASH_SIZE];
  uint8_t proof[2][AVB_AFTL_HASH_SIZE];
  uint64_t i;

  for (i = 0; i < AVB_AFTL_HASH_SIZE; i++) {
    hash[i] = 0;
  }

  memcpy(seed, "1234567890abcdefghijklmnopqrstuv", AVB_AFTL_HASH_SIZE);
  memcpy(proof[0], "abcdefghijklmnopqrstuvwxyz123456", AVB_AFTL_HASH_SIZE);
  avb_aftl_chain_border_right(
      seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 1, hash);
  EXPECT_EQ("363aa8a62b784be38392ab69ade1aac2562f8989ce8986bec685d2957d657310",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\" and proof "
         "[\"abcdefghijklmnopqrstuvwxyz123456\"]";
  memcpy(proof[1], "7890abcdefghijklmnopqrstuvwxyz12", AVB_AFTL_HASH_SIZE);
  avb_aftl_chain_border_right(
      seed, AVB_AFTL_HASH_SIZE, (uint8_t*)proof, 2, hash);
  EXPECT_EQ("618fc58c45faea808e0bbe0f82afbe7687f4db2608824120e8ade507cbce221f",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed with seed: "
      << "\"1234567890abcdefghijklmnopqrstuv\" and proof ["
      << "\"abcdefghijklmnopqrstuvwxyz123456\", "
         "\"7890abcdefghijklmnopqrstuvwxyz12\"]";
}

TEST_F(AvbAftlValidateTest, RFC6962HashChildren) {
  uint8_t hash[AVB_AFTL_HASH_SIZE];

  avb_aftl_rfc6962_hash_children((uint8_t*)"", 0, (uint8_t*)"", 0, hash);
  EXPECT_EQ("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on inputs \"\" and \"\"";

  avb_aftl_rfc6962_hash_children((uint8_t*)"abcd", 4, (uint8_t*)"", 0, hash);
  EXPECT_EQ("b75eb7b06e69c1c49597fba37398e0f5ba319c7164ed67bb19b41e9d576313b9",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on inputs \"abcd\" and \"\"";

  avb_aftl_rfc6962_hash_children((uint8_t*)"", 0, (uint8_t*)"efgh", 4, hash);
  EXPECT_EQ("8d65f3e92e3853cee633345caca3e035f01c2e44815371985baed2c45c10ca40",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on inputs \"\" and \"efgh\"";

  avb_aftl_rfc6962_hash_children(
      (uint8_t*)"abcd", 4, (uint8_t*)"efgh", 4, hash);
  EXPECT_EQ("41561b1297f692dad705e28ece8bf47060fba1abeeebda0aa67c43570a36bf79",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on inputs \"abcd\" and \"efgh\"";
}

TEST_F(AvbAftlValidateTest, RFC6962HashLeaf) {
  uint8_t hash[AVB_AFTL_HASH_SIZE];
  avb_aftl_rfc6962_hash_leaf((uint8_t*)"", 0, hash);
  EXPECT_EQ("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on input \"\"";
  avb_aftl_rfc6962_hash_leaf((uint8_t*)"abcdefg", 7, hash);
  EXPECT_EQ("6b43f785b72386e132b275bc918c25dbc687ab8427836bef6ce4509b64f4f54d",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE))
      << "Failed on input \"abcdefg\"";
}

TEST_F(AvbAftlValidateTest, Sha256) {
  /* Computed with:
   *
   * $ echo -n foobar |sha256sum
   * c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2
   */
  uint8_t hash[AVB_AFTL_HASH_SIZE];
  avb_aftl_sha256(NULL, 0, hash);
  EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE));
  avb_aftl_sha256((uint8_t*)"foobar", 6, hash);
  EXPECT_EQ("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, AvbAftlCountLeadingZeros) {
  /* Spot checks to ensure aftl_count_leading_zeros is correct. */
  EXPECT_EQ(52ull, avb_aftl_count_leading_zeros(4095))
      << "Failed on input 4095";
  EXPECT_EQ(12ull, avb_aftl_count_leading_zeros(0xfffffffffffff))
      << "Failed on input 0xfffffffffffff";
  EXPECT_EQ(64ull, avb_aftl_count_leading_zeros(0)) << "Failed on input 0";
  EXPECT_EQ(0ull, avb_aftl_count_leading_zeros(0xffffffffffffffff))
      << "Failed on input 0xffffffffffffffff";
}

} /* namespace avb */
