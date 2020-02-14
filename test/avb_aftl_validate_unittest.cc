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

const char kAftlKeyBytesPath[] = "test/data/aftl_key_bytes.bin";
const char kAftlLogSigPath[] = "test/data/aftl_log_sig.bin";

} /* namespace */

namespace avb {

/* Extend BaseAvbToolTest to take advantage of common checks and tooling. */
class AvbAftlValidateTest : public BaseAvbToolTest {
 public:
  AvbAftlValidateTest() {}
  ~AvbAftlValidateTest() {}
  void SetUp() override {
    uint8_t kAftlJsonData[] =
        "{\"timestamp\":{\"seconds\":1581533076,\"nanos\":884246745},\"Value\":"
        "{\"FwInfo\":{\"info\":{\"info\":{\"vbmeta_hash\":"
        "\"mS461dkWuKtPENmqaVQpg/"
        "xoHUPNsqRvnrh1uLUkKCQ=\",\"version_incremental\":\"1\",\"manufacturer_"
        "key_hash\":\"JkjCeRzSiHsHxxiVVieHNEvd9bsehav59qmB4BRvYGs=\"},\"info_"
        "signature\":{\"hash_algorithm\":4,\"signature_algorithm\":1,"
        "\"signature\":\"YqMyK9rOly4dG+"
        "QX3qXwkCedZK8w8iXHX90i0OXV4reCNS8xP51scQoh/"
        "SINWjJQ3hDjIfveQ0SRtY748GeNfrajCDslRAce8f48M3B9Jf5RezbY/MA4ZE/"
        "IfgTQp6sFLPp2xM+RoPd/GMHtEP0zc98+0/7hsDC7wZeGip7HoxGGiaWqpy+zkp/"
        "NpD4aSEIz5gtvBisPI/blQbyPoH6cfNT9rJLvzfHIa6Cp/xpZoY7e2EUH/"
        "XoG6cJGDC3ddPxuLISITQ6ddZkpyhTcA5+xSN8zJxjei1EQOk02Oo9Bqs4srIuO1o/"
        "b91bTteykCK6ScCMt/rSsfxW6N9o/KvNSOr/"
        "csXyIBkeHQZ952MaD8vGNX3NkE+FdOEXBr6AWdAwIuHsjVK1uSp+nR/"
        "kQ2NuXnALXTsM1nB70rnUYdD0cC8OIHvJs9JvV4ATJ/"
        "SQAoGIDdk1up7w6y7+QOtXC+Dd2Y6aul96xiqDRrdza0ZyEzOBPIssNq34dVR+k7+"
        "jofkMsDD/"
        "VT3Ngec17SeZUFfKj1Uv1z6bt6fusfv6Veb84ch0Yx5elLXNfnvvguF0z5qZp+"
        "AjlkUEbhI5sRKrE9v1wV/IFiwYuHNMX3NBuKpx+8e7SXwZodXRBeocpSlA/"
        "Qf8dtomxAALZrB30HSOzYavMs/4=\"}}}}}";
    BaseAvbToolTest::SetUp();

    /* Read in test data from the key and log_sig binaries. */
    base::GetFileSize(base::FilePath(kAftlKeyBytesPath), &key_size_);
    if (key_size_ != AVB_AFTL_PUB_KEY_SIZE) return;
    key_bytes_ = (uint8_t*)avb_malloc(key_size_);
    if (!key_bytes_) return;
    base::ReadFile(
        base::FilePath(kAftlKeyBytesPath), (char*)key_bytes_, key_size_);
    base::GetFileSize(base::FilePath(kAftlLogSigPath), &log_sig_size_);
    if (log_sig_size_ != AVB_AFTL_SIGNATURE_SIZE) return;
    log_sig_bytes_ = (uint8_t*)avb_malloc(log_sig_size_);
    if (!log_sig_bytes_) return;
    base::ReadFile(
        base::FilePath(kAftlLogSigPath), (char*)log_sig_bytes_, log_sig_size_);
    icp_entry_ =
        (AftlIcpEntry*)avb_malloc(sizeof(AftlIcpEntry) + AVB_AFTL_HASH_SIZE);
    if (!icp_entry_) return;
    icp_entry_->log_root_descriptor.version = 1;
    icp_entry_->log_root_descriptor.tree_size = 3;
    icp_entry_->log_root_descriptor.root_hash_size = AVB_AFTL_HASH_SIZE;
    icp_entry_->log_root_descriptor.timestamp = 322325503;
    icp_entry_->log_root_descriptor.revision = 0;
    icp_entry_->log_root_descriptor.metadata_size = 0;
    icp_entry_->log_root_descriptor.metadata = NULL;
    icp_entry_->log_root_descriptor_size =
        icp_entry_->log_root_descriptor.root_hash_size +
        icp_entry_->log_root_descriptor.metadata_size + 29;

    icp_entry_->fw_info_leaf_size = sizeof(kAftlJsonData);
    icp_entry_->fw_info_leaf.vbmeta_hash_size = AVB_AFTL_HASH_SIZE;
    icp_entry_->fw_info_leaf.vbmeta_hash =
        (uint8_t*)avb_malloc(AVB_AFTL_HASH_SIZE);
    if (!icp_entry_->fw_info_leaf.vbmeta_hash) {
      return;
    }
    memcpy(icp_entry_->fw_info_leaf.vbmeta_hash,
           "\x65\xec\x58\x83\x43\x62\x8e\x81\x4d\xc7\x75\xa8\xcb\x77\x1f\x46"
           "\x81\xcc\x79\x6f\xba\x32\xf0\x68\xc7\x17\xce\x2e\xe2\x14\x4d\x39",
           AVB_AFTL_HASH_SIZE);
    icp_entry_->fw_info_leaf.json_data =
        (uint8_t*)avb_calloc(icp_entry_->fw_info_leaf_size);
    if (icp_entry_->fw_info_leaf.json_data == NULL) {
      avb_free(icp_entry_->fw_info_leaf.vbmeta_hash);
      return;
    }
    memcpy(icp_entry_->fw_info_leaf.json_data,
           kAftlJsonData,
           icp_entry_->fw_info_leaf_size);
    icp_entry_->leaf_index = 2;

    memcpy(icp_entry_->proofs[0],
           "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
           "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
           AVB_AFTL_HASH_SIZE);
    icp_entry_->proof_hash_count = 1;
    icp_entry_->log_root_descriptor.root_hash =
        (uint8_t*)avb_malloc(AVB_AFTL_HASH_SIZE);
    if (!icp_entry_->log_root_descriptor.root_hash) return;
    memcpy(icp_entry_->log_root_descriptor.root_hash,
           "\x5a\xb3\x43\x21\x8f\x54\x4d\x05\x46\x34\x62\x86\x2f\xa8\xf8\x6e"
           "\x3b\xa3\x19\x2d\xe9\x9c\xb2\xab\x8e\x09\xd8\x55\xc3\xde\x34\xd6",
           AVB_AFTL_HASH_SIZE);
  }

  void TearDown() override {
    if (icp_entry_ != NULL) {
      if (icp_entry_->fw_info_leaf.json_data != NULL)
        avb_free(icp_entry_->fw_info_leaf.json_data);
      if (icp_entry_->fw_info_leaf.vbmeta_hash != NULL)
        avb_free(icp_entry_->fw_info_leaf.vbmeta_hash);
      if (icp_entry_->log_root_descriptor.root_hash != NULL)
        avb_free(icp_entry_->log_root_descriptor.root_hash);
      avb_free(icp_entry_);
    }
    avb_free(key_bytes_);
    avb_free(log_sig_bytes_);
    BaseAvbToolTest::TearDown();
  }

 protected:
  AftlIcpEntry* icp_entry_;
  uint8_t* key_bytes_;
  uint8_t* log_sig_bytes_;
  int64_t key_size_;
  int64_t log_sig_size_;
};

TEST_F(AvbAftlValidateTest, AvbAftlVerifySignature) {
  icp_entry_->log_root_sig_size = AVB_AFTL_SIGNATURE_SIZE;
  icp_entry_->log_root_signature =
      (uint8_t*)avb_malloc(AVB_AFTL_SIGNATURE_SIZE);
  memcpy(
      icp_entry_->log_root_signature, log_sig_bytes_, AVB_AFTL_SIGNATURE_SIZE);
  EXPECT_EQ(true,
            avb_aftl_verify_entry_signature(key_bytes_, key_size_, icp_entry_));
  avb_free(icp_entry_->log_root_signature);
}

TEST_F(AvbAftlValidateTest, AvbAftlHashLogRootDescriptor) {
  uint8_t hash[AVB_AFTL_HASH_SIZE];

  /* Initialize the icp_entry components used with the test. */

  avb_aftl_hash_log_root_descriptor(icp_entry_, hash);
  EXPECT_EQ("4f932f328f4b1c9b16500d6d09005c46abebf5c4dc761bbd1e8602378789edac",
            mem_to_hexstring(hash, AVB_AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, AvbAftlVerifyIcpRootHash) {
  /* Initialize the icp_entry components used with the test. */
  EXPECT_EQ(true, avb_aftl_verify_icp_root_hash(icp_entry_));
}

TEST_F(AvbAftlValidateTest, AftlVerifyVbmetaHash) {
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA4096",
                      0,
                      base::FilePath("test/data/testkey_rsa4096.pem"));

  EXPECT_EQ(true,
            avb_aftl_verify_vbmeta_hash(
                vbmeta_image_.data(), vbmeta_image_.size(), icp_entry_));
}

TEST_F(AvbAftlValidateTest, AvbAftlRootFromIcp) {
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

TEST_F(AvbAftlValidateTest, AvbAftlChainInner) {
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

TEST_F(AvbAftlValidateTest, AvbAftlChainBorderRight) {
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

TEST_F(AvbAftlValidateTest, AvbAftlRFC6962HashChildren) {
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

TEST_F(AvbAftlValidateTest, AvbAftlRFC6962HashLeaf) {
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

TEST_F(AvbAftlValidateTest, AvbAftlSha256) {
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
