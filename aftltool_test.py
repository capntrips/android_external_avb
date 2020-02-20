#!/usr/bin/env python

# Copyright 2019, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""Unit tests for aftltool."""

# pylint: disable=unused-import
from __future__ import print_function

import base64
import binascii
import io
import os
import sys
import unittest

import aftltool
import avbtool
import proto.aftl_pb2
import proto.api_pb2
import proto.trillian_pb2


# Workaround for b/149307145 in order to pick up the test data from the right
# location independent where the script is called from.
# TODO(b/149307145): Remove workaround once the referenced bug is fixed.
TEST_EXEC_PATH = os.path.dirname(os.path.realpath(__file__))


class AftltoolTestCase(unittest.TestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftltoolTestCase, self).setUp()

    # Redirects the stderr to /dev/null when running the unittests. The reason
    # is that soong interprets any output on stderr as an error and marks the
    # unit test as failed although the test itself succeeded.
    self.stderr = sys.stderr
    self.null = open(os.devnull, 'wb')
    sys.stderr = self.null

    # AFTL public key.
    self.test_aftl_pub_key = (
        '-----BEGIN PUBLIC KEY-----\n'
        'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4ilqCNsenNA013iCdwgD\n'
        'YPxZ853nbHG9lMBp9boXiwRcqT/8bUKHIL7YX5z7s+QoRYVY3rkMKppRabclXzyx\n'
        'H59YnPMaU4uv7NqwWzjgaZo7E+vo7IF+KBjV3cJulId5Av0yIYUCsrwd7MpGtWdC\n'
        'Q3S+7Vd4zwzCKEhcvliNIhnNlp1U3wNkPCxOyCAsMEn6k8O5ar12ke5TvxDv15db\n'
        'rPDeHh8G2OYWoCkWL+lSN35L2kOJqKqVbLKWrrOd96RCYrrtbPCi580OADJRcUlG\n'
        'lgcjwmNwmypBWvQMZ6ITj0P0ksHnl1zZz1DE2rXe1goLI1doghb5KxLaezlR8c2C\n'
        'E3w/uo9KJgNmNgUVzzqZZ6FE0moyIDNOpP7KtZAL0DvEZj6jqLbB0ccPQElrg52m\n'
        'Dv2/A3nYSr0mYBKeskT4+Bg7PGgoC8p7WyLSxMyzJEDYdtrj9OFx6eZaA23oqTQx\n'
        'k3Qq5H8RfNBeeSUEeKF7pKH/7gyqZ2bNzBFMA2EBZgBozwRfaeN/HCv3qbaCnwvu\n'
        '6caacmAsK+RxiYxSL1QsJqyhCWWGxVyenmxdc1KG/u5ypi7OIioztyzR3t2tAzD3\n'
        'Nb+2t8lgHBRxbV24yiPlnvPmB1ZYEctXnlRR9Evpl1o9xA9NnybPHKr9rozN39CZ\n'
        'V/USB8K6ao1y5xPZxa8CZksCAwEAAQ==\n'
        '-----END PUBLIC KEY-----\n')

    # Test AftlIcpEntry #1
    self.test_tl_url_1 = 'aftl-test-server.google.com'

    self.test_sth_1 = aftltool.TrillianLogRootDescriptor()
    self.test_sth_1.tree_size = 2
    self.test_sth_1.root_hash_size = 32
    self.test_sth_1.root_hash = bytearray('f' * 32)
    self.test_sth_1.timestamp = 0x1234567890ABCDEF
    self.test_sth_1.revision = 0xFEDCBA0987654321

    self.test_sth_1_bytes = bytearray(
        '\x00\x01'                          # version
        '\x00\x00\x00\x00\x00\x00\x00\x02'  # tree_size
        '\x20'                              # root_hash_size
        + 'f' * 32 +                        # root_hash
        '\x12\x34\x56\x78\x90\xAB\xCD\xEF'  # timestamp
        '\xFE\xDC\xBA\x09\x87\x65\x43\x21'  # revision
        '\x00\x00'                          # metadata_size
        ''                                  # metadata (empty)
    )

    # Fill each structure with an easily observable pattern for easy validation.
    self.test_proof_hashes_1 = []
    self.test_proof_hashes_1.append(bytearray('b' * 32))
    self.test_proof_hashes_1.append(bytearray('c' * 32))
    self.test_proof_hashes_1.append(bytearray('d' * 32))
    self.test_proof_hashes_1.append(bytearray('e' * 32))

    # Valid test AftlIcpEntry #1.
    self.test_entry_1 = aftltool.AftlIcpEntry()
    self.test_entry_1.log_url = self.test_tl_url_1
    self.test_entry_1.leaf_index = 1
    self.test_entry_1.log_root_descriptor = self.test_sth_1
    self.test_entry_1.proofs = self.test_proof_hashes_1
    self.test_entry_1.log_root_signature = 'g' * 512  # bytearray('g' * 512)

    self.test_entry_1_bytes = bytearray(
        '\x00\x00\x00\x1b'                  # Transparency log url size.
        '\x00\x00\x00\x00\x00\x00\x00\x01'  # Leaf index.
        '\x00\x00\x00\x3d'                  # Log root descriptor size.
        '\x00\x00\x00\x00'                  # Firmware info leaf size.
        '\x02\x00'                          # Log root signature size.
        '\x04'                              # Number of hashes in ICP.
        '\x00\x00\x00\x80'                  # Size of ICP in bytes.
        + self.test_tl_url_1                # Transparency log url.
        + self.test_sth_1_bytes
        + 'g' * 512                         # Log root signature.
        + 'b' * 32                          # Hashes...
        + 'c' * 32
        + 'd' * 32
        + 'e' * 32)

    # Valid test AftlIcpEntry #2.
    self.test_tl_url_2 = 'aftl-test-server.google.ch'

    self.test_sth_2 = aftltool.TrillianLogRootDescriptor()
    self.test_sth_2.tree_size = 4
    self.test_sth_2.root_hash_size = 32
    self.test_sth_2.root_hash = bytearray('e' * 32)
    self.test_sth_2.timestamp = 6
    self.test_sth_2.revision = 7
    self.test_sth_2.metadata_size = 2
    self.test_sth_2.metadata = '12'

    self.test_sth_2_bytes = bytearray(
        '\x00\x01'                          # version
        '\x00\x00\x00\x00\x00\x00\x00\x04'  # tree_size
        '\x20'                              # root_hash_size
        + 'e' * 32 +                        # root_hash
        '\x00\x00\x00\x00\x00\x00\x00\x06'  # timestamp
        '\x00\x00\x00\x00\x00\x00\x00\x07'  # revision
        '\x00\x02'                          # metadata_size
        '12'                                # metadata
    )

    # Fill each structure with an easily observable pattern for easy validation.
    self.test_proof_hashes_2 = []
    self.test_proof_hashes_2.append(bytearray('g' * 32))
    self.test_proof_hashes_2.append(bytearray('h' * 32))

    self.test_entry_2 = aftltool.AftlIcpEntry()
    self.test_entry_2.log_url = self.test_tl_url_2
    self.test_entry_2.leaf_index = 2
    self.test_entry_2.log_root_descriptor = self.test_sth_2
    self.test_entry_2.log_root_signature = bytearray('d' * 512)
    self.test_entry_2.proofs = self.test_proof_hashes_2

    self.test_entry_2_bytes = bytearray(
        '\x00\x00\x00\x1a'                  # Transparency log url size.
        '\x00\x00\x00\x00\x00\x00\x00\x02'  # Leaf index.
        '\x00\x00\x00\x3f'                  # Log root descriptor size.
        '\x00\x00\x00\x00'                  # Firmware info leaf size.
        '\x02\x00'                          # Log root signature size.
        '\x02'                              # Number of hashes in ICP.
        '\x00\x00\x00\x40'                  # Size of ICP in bytes.
        + self.test_tl_url_2                # Transparency log url.
        + self.test_sth_2_bytes             # Log root
        + 'd' * 512                         # Log root signature.
        + 'g' * 32                          # Hashes...
        + 'h' * 32)

    # Valid test AftlDescriptor made out of AftlEntry #1 and #2.
    self.test_aftl_desc = aftltool.AftlDescriptor()
    self.test_aftl_desc.add_icp_entry(self.test_entry_1)
    self.test_aftl_desc.add_icp_entry(self.test_entry_2)

    self.test_expected_aftl_descriptor_bytes = bytearray(
        'AFTL'                              # Magic.
        '\x00\x00\x00\x01'                  # Major version.
        '\x00\x00\x00\x01'                  # Minor version.
        '\x00\x00\x05\xb9'                  # Descriptor size.
        '\x00\x02'                          # Number of ICP entries.
        + self.test_entry_1_bytes
        + self.test_entry_2_bytes)

    # pylint: disable=no-member
    self.test_afi_resp = proto.api_pb2.AddFirmwareInfoResponse()
    self.test_afi_resp.fw_info_proof.proof.leaf_index = 6263
    hashes = [
        '3ad99869646980c0a51d637a9791f892d12e0bc83f6bac5d305a9e289e7f7e8b',
        '2e5c664d2aee64f71cb4d292e787d0eae7ca9ed80d1e08abb41d26baca386c05',
        'a671dd99f8d97e9155cc2f0a9dc776a112a5ec5b821ec71571bb258ac790717a',
        '78046b839595e4e49ad4b0c73f92bf4803aacd4a3351181086509d057ef0d7a9',
        'c0a7e013f03e7c69e9402070e113dadb345868cf144ccb174fabc384b5605abf',
        'dc36e5dbe36abe9f4ad10f14170aa0148b6fe3fcaba9df43deaf4dede01b02e8',
        'b063e7fb665370a361718208756c363dc5206e2e9af9b4d847d81289cdae30de',
        'a69ea5ba88a221103636d3f4245c800570eb86ad9276121481521f97d0a04a81']
    for h in hashes:
      self.test_afi_resp.fw_info_proof.proof.hashes.append(
          binascii.unhexlify(h))
    self.test_afi_resp.fw_info_proof.sth.key_hint = binascii.unhexlify(
        '5af859abce8fe1ea')
    self.test_afi_resp.fw_info_proof.sth.log_root = binascii.unhexlify(
        '000100000000000018782053b182b55dc1377197c938637f50093131daea4'
        'd0696b1eae5b8a014bfde884a15edb28f1fc7954400000000000013a50000'
    )
    self.test_afi_resp.fw_info_proof.sth.log_root_signature = binascii.unhexlify(
        'c264bc7986a1cf56364ca4dd04989f45515cb8764d05b4fb2b880172585ea404'
        '2105f95a0e0471fb6e0f8c762b14b2e526fb78eaddcc61484917795a12f6ab3b'
        '557b5571d492d07d7950595f9ad8647a606c7c633f4697c5eb59c272aeca0419'
        '397c70a3b9b51537537c4ea6b49d356110e70a9286902f814cc6afbeafe612e4'
        '9e180146140e902bdd9e9dae66b37b4943150a9571949027a648db88a4eea3ad'
        'f930b4fa6a183e97b762ab0e55a3a26aa6b0fd44d30531e2541ecb94bf645e62'
        '59e8e3151e7c3b51a09fe24557ce2fd2c0ecdada7ce99c390d2ef10e5d075801'
        '7c10d49c55cdee930959cc35f0104e04f296591eeb5defbc9ebb237da7b204ca'
        'a4608cb98d6bc3a01f18585a04441caf8ec7a35aa2d35f7483b92b14fd0f4a41'
        '3a91133545579309adc593222ca5032a103b00d8fcaea911936dbec11349e4dd'
        '419b091ea7d1130570d70e2589dd9445fd77fd7492507e1c87736847b9741cc6'
        '236868af42558ff6e833e12010c8ede786e43ada40ff488f5f1870d1619887d7'
        '66a24ad0a06a47cc14e2f7db07361be191172adf3155f49713807c7c265f5a84'
        '040fc84246ccf7913e44721f0043cea05ee774e457e13206775eee992620c3f9'
        'd2b2584f58aac19e4afe35f0a17df699c45729f94101083f9fc4302659a7e6e0'
        'e7eb36f8d1ca0be2c9010160d329bd2d17bb707b010fdd63c30b667a0b886cf9'
    )
    self.test_afi_resp.fw_info_leaf = (
        '{\"timestamp\":{\"seconds\":1580115370,\"nanos\":621454825},\"Va'
        'lue\":{\"FwInfo\":{\"info\":{\"info\":{\"vbmeta_hash\":\"ViNzEQS'
        '/oc/bJ13yl40fk/cvXw90bxHQbzCRxgHDIGc=\",\"version_incremental\":'
        '\"1\",\"manufacturer_key_hash\":\"yBCrUOdjvaAh4git5EgqWa5neegUao'
        'XeLlB67+N8ObY=\"}}}}}')

    self.test_fw_info_leaf = aftltool.FirmwareInfoLeaf(
        self.test_afi_resp.fw_info_leaf)

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    # Reconnects stderr back to the normal stderr; see setUp() for details.
    sys.stderr = self.stderr

    super(AftltoolTestCase, self).tearDown()

  def get_testdata_path(self, relative_path):
    """Retrieves the absolute path for testdata given the relative path.

    Arguments:
      relative_path: The relative path to the testdata in the testdata
        directory.

    Returns:
      The absolute path to the testdata.
    """
    rel_path_parts = ['test', 'data']
    rel_path_parts.extend(relative_path.split(os.path.sep))
    return os.path.join(TEST_EXEC_PATH, *rel_path_parts)


class AftltoolTest(AftltoolTestCase):

  def test_merkle_root_hash(self):
    """Tests validation of inclusion proof and the merkle tree calculations.

    The test vectors have been taken from the Trillian tests:
    https://github.com/google/trillian/blob/v1.3.3/merkle/log_verifier_test.go
    """

    inclusion_proofs = [
        (1,
         8,
         [
             binascii.unhexlify('96a296d224f285c67bee93c30f8a3091'
                                '57f0daa35dc5b87e410b78630a09cfc7'),
             binascii.unhexlify('5f083f0a1a33ca076a95279832580db3'
                                'e0ef4584bdff1f54c8a360f50de3031e'),
             binascii.unhexlify('6b47aaf29ee3c2af9af889bc1fb9254d'
                                'abd31177f16232dd6aab035ca39bf6e4')
         ]),
        (6,
         8,
         [
             binascii.unhexlify('bc1a0643b12e4d2d7c77918f44e0f4f7'
                                '9a838b6cf9ec5b5c283e1f4d88599e6b'),
             binascii.unhexlify('ca854ea128ed050b41b35ffc1b87b8eb'
                                '2bde461e9e3b5596ece6b9d5975a0ae0'),
             binascii.unhexlify('d37ee418976dd95753c1c73862b9398f'
                                'a2a2cf9b4ff0fdfe8b30cd95209614b7')
         ]),
        (3,
         3,
         [
             binascii.unhexlify('fac54203e7cc696cf0dfcb42c92a1d9d'
                                'baf70ad9e621f4bd8d98662f00e3c125')
         ]),
        (2,
         5,
         [
             binascii.unhexlify('6e340b9cffb37a989ca544e6bb780a2c'
                                '78901d3fb33738768511a30617afa01d'),
             binascii.unhexlify('5f083f0a1a33ca076a95279832580db3'
                                'e0ef4584bdff1f54c8a360f50de3031e'),
             binascii.unhexlify('bc1a0643b12e4d2d7c77918f44e0f4f7'
                                '9a838b6cf9ec5b5c283e1f4d88599e6b')
         ]
        )
    ]

    leaves = [
        binascii.unhexlify(''),
        binascii.unhexlify('00'),
        binascii.unhexlify('10'),
        binascii.unhexlify('2021'),
        binascii.unhexlify('3031'),
        binascii.unhexlify('40414243'),
        binascii.unhexlify('5051525354555657'),
        binascii.unhexlify('606162636465666768696a6b6c6d6e6f'),
    ]

    roots = [
        binascii.unhexlify('6e340b9cffb37a989ca544e6bb780a2c'
                           '78901d3fb33738768511a30617afa01d'),
        binascii.unhexlify('fac54203e7cc696cf0dfcb42c92a1d9d'
                           'baf70ad9e621f4bd8d98662f00e3c125'),
        binascii.unhexlify('aeb6bcfe274b70a14fb067a5e5578264'
                           'db0fa9b51af5e0ba159158f329e06e77'),
        binascii.unhexlify('d37ee418976dd95753c1c73862b9398f'
                           'a2a2cf9b4ff0fdfe8b30cd95209614b7'),
        binascii.unhexlify('4e3bbb1f7b478dcfe71fb631631519a3'
                           'bca12c9aefca1612bfce4c13a86264d4'),
        binascii.unhexlify('76e67dadbcdf1e10e1b74ddc608abd2f'
                           '98dfb16fbce75277b5232a127f2087ef'),
        binascii.unhexlify('ddb89be403809e325750d3d263cd7892'
                           '9c2942b7942a34b77e122c9594a74c8c'),
        binascii.unhexlify('5dc9da79a70659a9ad559cb701ded9a2'
                           'ab9d823aad2f4960cfe370eff4604328'),
    ]

    for icp in inclusion_proofs:
      leaf_id = icp[0] - 1
      leaf_hash = aftltool.rfc6962_hash_leaf(leaves[leaf_id])
      root_hash = aftltool.root_from_icp(leaf_id, icp[1], icp[2], leaf_hash)
      self.assertEqual(root_hash, roots[icp[1] -1])


class AftlDescriptorTest(AftltoolTestCase):

  def test__init__(self):
    """Tests the constructor."""
    # Calls constructor without data.
    d = aftltool.AftlDescriptor()
    self.assertIsInstance(d.icp_header, aftltool.AftlIcpHeader)
    self.assertEqual(d.icp_header.icp_count, 0)
    self.assertEqual(d.icp_entries, [])
    self.assertTrue(d.is_valid())

    # Calls constructor with data.
    d = aftltool.AftlDescriptor(self.test_expected_aftl_descriptor_bytes)
    self.assertIsInstance(d.icp_header, aftltool.AftlIcpHeader)
    self.assertEqual(d.icp_header.icp_count, 2)
    self.assertEqual(len(d.icp_entries), 2)
    for entry in d.icp_entries:
      self.assertIsInstance(entry, aftltool.AftlIcpEntry)
    self.assertTrue(d.is_valid())

  def test_add_icp_entry(self):
    """Tests the add_icp_entry method."""
    d = aftltool.AftlDescriptor()

    # Adds 1st ICP.
    d.add_icp_entry(self.test_entry_1)
    self.assertEqual(d.icp_header.icp_count, 1)
    self.assertEqual(len(d.icp_entries), 1)
    self.assertTrue(d.is_valid())

    # Adds 2nd ICP.
    d.add_icp_entry(self.test_entry_2)
    self.assertEqual(d.icp_header.icp_count, 2)
    self.assertEqual(len(d.icp_entries), 2)
    self.assertTrue(d.is_valid())

  def test_verify_vbmeta_image_with_1_icp(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 1 ICP.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_1_icp.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_descriptor(image_path)

    # Valid image checked against correct log key.
    self.assertTrue(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftltool/aftl_pubkey_1.pub')]))

    # Valid image checked with a key from another log.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftltool/aftl_pubkey_2.pub')]))

    # Valid image checked with non existed key file path.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('non_existent_blabli')]))

    # Valid image checked with an invalid key.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('large_blob.bin')]))

    # Valid image checked with empty list of keys.
    self.assertFalse(desc.verify_vbmeta_image(vbmeta_image, []))

    # Valid image checked with empty list of keys.
    self.assertFalse(desc.verify_vbmeta_image(vbmeta_image, None))

  def test_verify_vbmeta_image_with_2_icp_from_same_log(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 2 ICPs from same log.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_2_icp_same_log.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_descriptor(image_path)

    # Valid image checked against correct log key.
    self.assertTrue(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftltool/aftl_pubkey_1.pub')]))

    # Valid vbmeta image checked with key from another log.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftltool/aftl_pubkey_2.pub')]))

    # Valid image checked with non existed key file path.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('non_existent_blabli')]))

    # Valid image checked with invalid key.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('large_blob.bin')]))

    # Valid image but checked with empty list of keys.
    self.assertFalse(desc.verify_vbmeta_image(vbmeta_image, []))

  def test_verify_vbmeta_image_with_2_icp_from_different_logs(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 2 ICPs from different logs.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_2_icp_different_logs.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_descriptor(image_path)

    # Valid image checked against log keys from both logs.
    self.assertTrue(desc.verify_vbmeta_image(
        vbmeta_image, [
            self.get_testdata_path('aftltool/aftl_pubkey_1.pub'),
            self.get_testdata_path('aftltool/aftl_pubkey_2.pub')
        ]))

    # Valid image checked with one of the keys with an invalid file path.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [
            self.get_testdata_path('aftltool/aftl_pubkey_1.pub'),
            self.get_testdata_path('non_existent_blabli')
        ]))

    # Valid image checked with one of the keys being a invalid key.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [
            self.get_testdata_path('aftltool/aftl_pubkey_1.pub'),
            self.get_testdata_path('large_blob.bin')
        ]))

    # Valid image checked with one of the keys being None.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [
            self.get_testdata_path('aftltool/aftl_pubkey_1.pub'),
            None
        ]))

    # Valid vbmeta image checked against only one of the log keys.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftltool/aftl_pubkey_1.pub')]))
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftltool/aftl_pubkey_2.pub')]))

    # Valid image checked with invalid key.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('large_blob.bin')]))

    # Valid image but checked with empty list of keys.
    self.assertFalse(desc.verify_vbmeta_image(vbmeta_image, []))

  def test_save(self):
    """Tests save method."""
    buf = io.BytesIO()
    self.test_aftl_desc.save(buf)
    self.assertEqual(buf.getvalue(), self.test_expected_aftl_descriptor_bytes)

  def test_encode(self):
    """Tests encode method."""
    desc_bytes = self.test_aftl_desc.encode()
    self.assertEqual(desc_bytes, self.test_expected_aftl_descriptor_bytes)

  def test_is_valid(self):
    """Tests is_valid method."""
    d = aftltool.AftlDescriptor()
    d.add_icp_entry(self.test_entry_1)
    d.add_icp_entry(self.test_entry_2)

    # Force invalid ICP header.
    old_magic = d.icp_header.magic
    d.icp_header.magic = 'YOLO'
    self.assertFalse(d.is_valid())
    d.icp_header.magic = old_magic
    self.assertTrue(d.is_valid())

    # Force count mismatch between header and actual entries.
    old_icp_count = d.icp_header.icp_count
    d.icp_header.icp_count = 1
    self.assertFalse(d.is_valid())
    d.icp_header.icp_count = old_icp_count
    self.assertTrue(d.is_valid())

    # Force invalid ICP entry.
    old_leaf_index = d.icp_entries[0].leaf_index
    d.icp_entries[0].leaf_index = -10
    self.assertFalse(d.is_valid())
    d.icp_entries[0].leaf_index = old_leaf_index
    self.assertTrue(d.is_valid())

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.BytesIO()
    self.test_aftl_desc.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Log Root Descriptor:', desc)


class AftlIcpHeaderTest(AftltoolTestCase):
  """Test suite for testing the AftlIcpHeader descriptor."""

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftlIcpHeaderTest, self).setUp()

    self.test_header_valid = aftltool.AftlIcpHeader()
    self.test_header_valid.icp_count = 1

    self.test_header_invalid = aftltool.AftlIcpHeader()
    self.test_header_invalid.icp_count = -34

    self.test_header_bytes = bytearray('\x41\x46\x54\x4c\x00\x00\x00\x01'
                                       '\x00\x00\x00\x01\x00\x00\x00\x12'
                                       '\x00\x01')

  def test__init__(self):
    """Tests constructor."""

    # Calls constructor without data.
    header = aftltool.AftlIcpHeader()
    self.assertEqual(header.magic, 'AFTL')
    self.assertEqual(header.required_icp_version_major,
                     avbtool.AVB_VERSION_MAJOR)
    self.assertEqual(header.required_icp_version_minor,
                     avbtool.AVB_VERSION_MINOR)
    self.assertEqual(header.aftl_descriptor_size, aftltool.AftlIcpHeader.SIZE)
    self.assertEqual(header.icp_count, 0)
    self.assertTrue(header.is_valid())

    # Calls constructor with data.
    header = aftltool.AftlIcpHeader(self.test_header_bytes)
    self.assertEqual(header.magic, 'AFTL')
    self.assertEqual(header.required_icp_version_major, 1)
    self.assertEqual(header.required_icp_version_minor, 1)
    self.assertEqual(header.aftl_descriptor_size, aftltool.AftlIcpHeader.SIZE)
    self.assertTrue(header.icp_count, 1)
    self.assertTrue(header.is_valid())

  def test_save(self):
    """Tests save method."""
    buf = io.BytesIO()
    self.test_header_valid.save(buf)
    self.assertEqual(buf.getvalue(), self.test_header_bytes)

  def test_encode(self):
    """Tests encode method."""
    # Valid header.
    header_bytes = self.test_header_valid.encode()
    self.assertEqual(header_bytes, self.test_header_bytes)

    # Invalid header
    with self.assertRaises(aftltool.AftlError):
      header_bytes = self.test_header_invalid.encode()

  def test_is_valid(self):
    """Tests is_valid method."""
    # Valid default record.
    header = aftltool.AftlIcpHeader()
    self.assertTrue(header.is_valid())

    # Invalid magic.
    header = aftltool.AftlIcpHeader()
    header.magic = 'YOLO'
    self.assertFalse(header.is_valid())

    # Valid ICP count.
    self.assertTrue(self.test_header_valid.is_valid())

    # Invalid ICP count.
    self.assertFalse(self.test_header_invalid.is_valid())

    header = aftltool.AftlIcpHeader()
    header.icp_count = 10000000
    self.assertFalse(header.is_valid())

    # Invalid ICP major version.
    header = aftltool.AftlIcpHeader()
    header.required_icp_version_major = avbtool.AVB_VERSION_MAJOR + 1
    self.assertFalse(header.is_valid())

    # Invalid ICP minor version.
    header = aftltool.AftlIcpHeader()
    header.required_icp_version_minor = avbtool.AVB_VERSION_MINOR + 1
    self.assertFalse(header.is_valid())

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.BytesIO()
    self.test_header_valid.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Major version:', desc)


class AftlIcpEntryTest(AftltoolTestCase):
  """Test suite for testing the AftlIcpEntry descriptor."""

  def test__init__and_properties(self):
    """Tests constructor and properties methods."""

    # Calls constructor without data.
    entry = aftltool.AftlIcpEntry()
    self.assertEqual(entry.log_url_size, 0)
    self.assertEqual(entry.leaf_index, 0)
    self.assertEqual(entry.log_root_descriptor_size, 29)
    self.assertEqual(entry.fw_info_leaf_size, 0)
    self.assertEqual(entry.log_root_sig_size, 0)
    self.assertEqual(entry.proof_hash_count, 0)
    self.assertEqual(entry.inc_proof_size, 0)
    self.assertEqual(entry.log_url, '')
    self.assertIsInstance(entry.log_root_descriptor,
                          aftltool.TrillianLogRootDescriptor)
    self.assertEqual(entry.proofs, [])
    self.assertTrue(entry.is_valid())

    # Calls constructor with data.
    entry = aftltool.AftlIcpEntry(self.test_entry_1_bytes)
    self.assertEqual(entry.log_url_size, len(self.test_tl_url_1))
    self.assertEqual(entry.leaf_index, 1)
    self.assertEqual(entry.fw_info_leaf_size, 0)
    self.assertEqual(entry.log_root_sig_size, 512)
    self.assertEqual(entry.proof_hash_count, len(self.test_proof_hashes_1))
    self.assertEqual(entry.inc_proof_size, 128)
    self.assertEqual(entry.log_url, self.test_tl_url_1)
    self.assertEqual(entry.proofs, self.test_proof_hashes_1)
    self.assertTrue(entry.is_valid())

  def test_encode(self):
    """Tests encode method."""
    entry_bytes = self.test_entry_1.encode()
    self.assertEqual(entry_bytes, self.test_entry_1_bytes)

  def test_save(self):
    """Tests save method."""
    buf = io.BytesIO()
    self.test_entry_1.save(buf)
    self.assertEqual(buf.getvalue(), self.test_entry_1_bytes)

  def test_get_expected_size(self):
    """Tests get_expected_size method."""
    # Default record.
    entry = aftltool.AftlIcpEntry()
    self.assertEqual(entry.get_expected_size(), 56)
    self.assertEqual(entry.get_expected_size(), len(entry.encode()))

    # Test record.
    self.assertEqual(self.test_entry_1.get_expected_size(), 755)
    self.assertEqual(self.test_entry_1.get_expected_size(),
                     len(self.test_entry_1.encode()))

  def test_is_valid(self):
    """Tests is_valid method."""
    # Valid default record.
    entry = aftltool.AftlIcpEntry()
    entry.leaf_index = 2
    entry.log_url = self.test_tl_url_1
    entry.set_log_root_descriptor = self.test_sth_1
    entry.proofs = self.test_proof_hashes_1
    self.assertTrue(entry.is_valid())

    # Invalid leaf index.
    entry = aftltool.AftlIcpEntry()
    entry.leaf_index = -1
    self.assertFalse(entry.is_valid())

    # Invalid log_root_descriptor
    entry = aftltool.AftlIcpEntry()
    entry.log_root_descriptor = None
    self.assertFalse(entry.is_valid())

    entry.log_root_descriptor = ''
    self.assertFalse(entry.is_valid())

    entry.log_root_descriptor = 'blabli'
    self.assertFalse(entry.is_valid())

  def test_translate_response(self):
    """Tests translate_response method."""
    entry = aftltool.AftlIcpEntry()
    entry.translate_response('aftl-test.foo.bar:80', self.test_afi_resp)
    self.assertEqual(entry.log_url, 'aftl-test.foo.bar:80')
    self.assertEqual(entry.leaf_index, 6263)
    self.assertEqual(entry.log_root_descriptor.encode(),
                     self.test_afi_resp.fw_info_proof.sth.log_root)
    self.assertEqual(entry.log_root_signature,
                     self.test_afi_resp.fw_info_proof.sth.log_root_signature)
    self.assertEqual(entry.proofs,
                     self.test_afi_resp.fw_info_proof.proof.hashes)

  def test_verify_icp(self):
    """Tests verify_icp method."""
    key_file = 'transparency_log_pub_key.pem'
    with open(key_file, 'w') as f:
      f.write(self.test_aftl_pub_key)

    # Valid ICP.
    entry = aftltool.AftlIcpEntry()
    entry.translate_response(self.test_tl_url_1, self.test_afi_resp)
    self.assertTrue(entry.verify_icp(key_file))

    # Invalid ICP where fw_info_leaf is not matching up with proofs.
    entry = aftltool.AftlIcpEntry()
    entry.translate_response(self.test_tl_url_1, self.test_afi_resp)
    fw_info_leaf_bytes = entry.fw_info_leaf._fw_info_leaf_bytes.replace(
        'ViNzEQS', '1234567')
    entry.fw_info_leaf._fw_info_leaf_bytes = fw_info_leaf_bytes
    self.assertFalse(entry.verify_icp(key_file))

    os.remove(key_file)

  def test_verify_vbmeta_image(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 1 ICP.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_1_icp.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_descriptor(image_path)

    # Checks that there is 1 ICP.
    self.assertEqual(desc.icp_header.icp_count, 1)
    entry = desc.icp_entries[0]

    # Valid vbmeta image checked with correct log key.
    self.assertTrue(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('aftltool/aftl_pubkey_1.pub')))

    # Valid vbmeta image checked with public key of another log.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('aftltool/aftl_pubkey_2.pub')))

    # Valid vbmeta image checked with invalid key.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('large_blob.bin')))

    # Valid vbmeta image checked with no key.
    self.assertFalse(entry.verify_vbmeta_image(vbmeta_image, None))

  def test_verify_invalid_vbmeta_image(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 1 ICP.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_1_icp.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_descriptor(image_path)

    self.assertEqual(desc.icp_header.icp_count, 1)
    entry = desc.icp_entries[0]

    # Modify vbmeta image to become invalid
    vbmeta_image = 'A' * len(vbmeta_image)

    # Invalid vbmeta image checked with correct log key.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('aftltool/aftl_pubkey_1.pub')))

    # Invalid vbmeta image checked with invalid key.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('large_blob.bin')))

    # Valid vbmeta image checked with no key.
    self.assertFalse(entry.verify_vbmeta_image(vbmeta_image, None))

    # None image checked with a key.
    self.assertFalse(entry.verify_vbmeta_image(
        None, self.get_testdata_path('aftltool/aftl_pubkey_1.pub')))

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.BytesIO()
    self.test_entry_1.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('ICP hashes:', desc)


class TrillianLogRootDescriptorTest(AftltoolTestCase):
  """Test suite for testing the TrillianLogRootDescriptor descriptor."""

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(TrillianLogRootDescriptorTest, self).setUp()

    # Creates basic log root without metadata fields.
    base_log_root = (
        '0001'                              # version
        '00000000000002e5'                  # tree_size
        '20'                                # root_hash_size
        '2d614759ad408a111a3351c0cb33c099'  # root_hash
        '422c30a5c5104788a343332bde2b387b'
        '15e1c97e3b4bd239'                  # timestamp
        '00000000000002e4'                  # revision
    )

    # Create valid log roots with metadata fields w/ and w/o metadata.
    self.test_log_root_bytes_wo_metadata = binascii.unhexlify(
        base_log_root + '0000')
    self.test_log_root_bytes_with_metadata = binascii.unhexlify(
        base_log_root + '00023132')

  def test__init__(self):
    """Tests constructor."""
    # Calls constructor without data.
    d = aftltool.TrillianLogRootDescriptor()
    self.assertTrue(d.is_valid())
    self.assertEqual(d.version, 1)
    self.assertEqual(d.tree_size, 0)
    self.assertEqual(d.root_hash_size, 0)
    self.assertEqual(d.root_hash, bytearray())
    self.assertEqual(d.timestamp, 0)
    self.assertEqual(d.revision, 0)
    self.assertEqual(d.metadata_size, 0)
    self.assertEqual(d.metadata, bytearray())

    # Calls constructor with log_root w/o metadata
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_bytes_wo_metadata)
    self.assertTrue(d.is_valid())
    self.assertEqual(d.version, 1)
    self.assertEqual(d.tree_size, 741)
    self.assertEqual(d.root_hash_size, 32)
    self.assertEqual(d.root_hash,
                     binascii.unhexlify('2d614759ad408a111a3351c0cb33c099'
                                        '422c30a5c5104788a343332bde2b387b'))
    self.assertEqual(d.timestamp, 1576762888554271289)
    self.assertEqual(d.revision, 740)
    self.assertEqual(d.metadata_size, 0)
    self.assertEqual(d.metadata, bytearray())

    # Calls constructor with log_root with metadata
    d = aftltool.TrillianLogRootDescriptor(
        self.test_log_root_bytes_with_metadata)
    self.assertEqual(d.metadata_size, 2)
    self.assertEqual(d.metadata, bytearray('12'))

  def test_get_expected_size(self):
    """Tests get_expected_size method."""
    # Default constructor.
    d = aftltool.TrillianLogRootDescriptor()
    self.assertEqual(d.get_expected_size(), 11 + 18)

    # Log root without metadata.
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_bytes_wo_metadata)
    self.assertEqual(d.get_expected_size(), 11 + 18 + 32)

    # Log root with metadata.
    d = aftltool.TrillianLogRootDescriptor(
        self.test_log_root_bytes_with_metadata)
    self.assertEqual(d.get_expected_size(), 11 + 18 + 32 + 2)

  def test_encode(self):
    """Tests encode method."""
    # Log root from default constructor.
    d = aftltool.TrillianLogRootDescriptor()
    expected_bytes = (
        '0001'                              # version
        '0000000000000000'                  # tree_size
        '00'                                # root_hash_size
        ''                                  # root_hash (empty)
        '0000000000000000'                  # timestamp
        '0000000000000000'                  # revision
        '0000'                              # metadata size
        ''                                  # metadata (empty)
    )
    self.assertEqual(d.encode(), binascii.unhexlify(expected_bytes))

    # Log root without metadata.
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_bytes_wo_metadata)
    self.assertEqual(d.encode(), self.test_log_root_bytes_wo_metadata)

    # Log root with metadata.
    d = aftltool.TrillianLogRootDescriptor(
        self.test_log_root_bytes_with_metadata)
    self.assertEqual(d.encode(), self.test_log_root_bytes_with_metadata)

  def test_is_valid(self):
    """Tests is_valid method."""
    d = aftltool.TrillianLogRootDescriptor()
    self.assertTrue(d.is_valid())

    # Invalid version.
    d = aftltool.TrillianLogRootDescriptor()
    d.version = 2
    self.assertFalse(d.is_valid())

    # Invalid tree_size.
    d = aftltool.TrillianLogRootDescriptor()
    d.tree_size = -1
    self.assertFalse(d.is_valid())

    # Invalid root_hash_size.
    d = aftltool.TrillianLogRootDescriptor()
    d.root_hash_size = -1
    self.assertFalse(d.is_valid())
    d.root_hash_size = 300
    self.assertFalse(d.is_valid())

    # Invalid/valid root_hash_size / root_hash combination.
    d = aftltool.TrillianLogRootDescriptor()
    d.root_hash_size = 4
    d.root_hash = '123'
    self.assertFalse(d.is_valid())
    d.root_hash = '1234'
    self.assertTrue(d.is_valid())

    # Invalid timestamp.
    d = aftltool.TrillianLogRootDescriptor()
    d.timestamp = -1
    self.assertFalse(d.is_valid())

    # Invalid revision.
    d = aftltool.TrillianLogRootDescriptor()
    d.revision = -1
    self.assertFalse(d.is_valid())

    # Invalid metadata_size.
    d = aftltool.TrillianLogRootDescriptor()
    d.metadata_size = -1
    self.assertFalse(d.is_valid())
    d.metadata_size = 70000
    self.assertFalse(d.is_valid())

    # Invalid/valid metadata_size / metadata combination.
    d = aftltool.TrillianLogRootDescriptor()
    d.metadata_size = 4
    d.metadata = '123'
    self.assertFalse(d.is_valid())
    d.metadata = '1234'
    self.assertTrue(d.is_valid())

  def test_print_desc(self):
    """Tests print_desc method."""
    # Log root without metadata
    buf = io.BytesIO()
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_bytes_wo_metadata)
    d.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Version:', desc)
    self.assertNotIn('Metadata:', desc)

    # Log root with metadata
    buf = io.BytesIO()
    d = aftltool.TrillianLogRootDescriptor(
        self.test_log_root_bytes_with_metadata)
    d.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Version:', desc)
    self.assertIn('Metadata:', desc)


class FirmwareInfoLeafTest(AftltoolTestCase):
  """Test suite for testing the FirmwareInfoLeaf."""

  def test__init__(self):
    """Tests constructor and properties methods."""
    # Calls constructor without data.
    leaf = aftltool.FirmwareInfoLeaf()
    self.assertTrue(leaf.is_valid())
    self.assertEqual(leaf.vbmeta_hash, None)
    self.assertEqual(leaf.version_incremental, None)
    self.assertEqual(leaf.platform_key, None)
    self.assertEqual(leaf.manufacturer_key_hash, None)
    self.assertEqual(leaf.description, None)

    # Calls constructor with data.
    leaf = aftltool.FirmwareInfoLeaf(self.test_afi_resp.fw_info_leaf)
    self.assertTrue(leaf.is_valid())
    self.assertEqual(
        leaf.vbmeta_hash,
        base64.b64decode('ViNzEQS/oc/bJ13yl40fk/cvXw90bxHQbzCRxgHDIGc='))
    self.assertEqual(leaf.version_incremental, '1')
    self.assertEqual(leaf.platform_key, None)
    self.assertEqual(
        leaf.manufacturer_key_hash,
        base64.b64decode('yBCrUOdjvaAh4git5EgqWa5neegUaoXeLlB67+N8ObY='))
    self.assertEqual(leaf.description, None)

    # Calls constructor with invalid JSON data.
    with self.assertRaises(aftltool.AftlError):
      leaf = aftltool.FirmwareInfoLeaf('Invalid JSON.')

  def test_get_expected_size(self):
    """Tests get_expected_size method."""
    # Calls constructor without data.
    leaf = aftltool.FirmwareInfoLeaf()
    self.assertEqual(leaf.get_expected_size(), 0)

    # Calls constructor with data.
    leaf = aftltool.FirmwareInfoLeaf(self.test_afi_resp.fw_info_leaf)
    self.assertEqual(leaf.get_expected_size(),
                     len(self.test_afi_resp.fw_info_leaf))

  def test_encode(self):
    """Tests encode method."""
    # Calls constructor without data.
    leaf = aftltool.FirmwareInfoLeaf()
    self.assertEqual(leaf.encode(), '')

    # Calls constructor with data.
    self.assertEqual(self.test_fw_info_leaf.encode(),
                     self.test_afi_resp.fw_info_leaf)

  def test_is_valid(self):
    """Tests is_valid method."""
    # Calls constructor without data.
    leaf = aftltool.FirmwareInfoLeaf()
    self.assertTrue(leaf.is_valid())

    # Calls constructor with data.
    self.assertTrue(self.test_fw_info_leaf.is_valid())

    # Incorrect name for Value key.
    invalid_value_key_name = (
        '{\"timestamp\":{\"seconds\":1580115370,\"nanos\":621454825},\"In'
        'val\":{\"FwInfo\":{\"info\":{\"info\":{\"vbmeta_hash\":\"ViNzEQS'
        '/oc/bJ13yl40fk/cvXw90bxHQbzCRxgHDIGc=\",\"version_incremental\":'
        '\"1\",\"manufacturer_key_hash\":\"yBCrUOdjvaAh4git5EgqWa5neegUao'
        'XeLlB67+N8ObY=\"}}}}}')

    with self.assertRaises(aftltool.AftlError):
      aftltool.FirmwareInfoLeaf(invalid_value_key_name)

    # Within Firmware Info having a field which does not exist in
    # proto.aftl_pb2.FirmwareInfo.
    invalid_fields = (
        '{\"timestamp\":{\"seconds\":1580115370,\"nanos\":621454825},\"Va'
        'lue\":{\"FwInfo\":{\"info\":{\"info\":{\"invalid_field\":\"ViNzEQS'
        '/oc/bJ13yl40fk/cvXw90bxHQbzCRxgHDIGc=\",\"version_incremental\":'
        '\"1\",\"manufacturer_key_hash\":\"yBCrUOdjvaAh4git5EgqWa5neegUao'
        'XeLlB67+N8ObY=\"}}}}}')

    with self.assertRaises(aftltool.AftlError):
      aftltool.FirmwareInfoLeaf(invalid_fields)

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.BytesIO()
    self.test_fw_info_leaf.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('VBMeta hash:', desc)


class AftlMockCommunication(aftltool.AftlCommunication):
  """Testing Mock implementation of AftlCommunication."""

  def __init__(self, transparency_log, canned_response):
    """Initializes the object.

    Arguments:
      transparency_log: String containing the URL of a transparency log server.
      canned_response: AddFirmwareInfoResponse to return or the Exception to
        raise.
    """
    super(AftlMockCommunication, self).__init__(transparency_log, timeout=None)
    self.request = None
    self.canned_response = canned_response

  def add_firmware_info(self, request):
    """Records the request and returns the canned response."""
    self.request = request

    if isinstance(self.canned_response, aftltool.AftlError):
      raise self.canned_response
    return self.canned_response


class AftlMock(aftltool.Aftl):
  """Mock for aftltool.Aftl to mock the communication piece."""

  def __init__(self, canned_response):
    """Initializes the object.

    Arguments:
      canned_response: AddFirmwareInfoResponse to return or the Exception to
        raise.
    """
    self.mock_canned_response = canned_response

  def request_inclusion_proof(self, transparency_log, vbmeta_descriptor,
                              version_inc, manufacturer_key_path,
                              signing_helper, signing_helper_with_files,
                              timeout, aftl_comms=None):
    """Mocked request_inclusion_proof function."""
    aftl_comms = AftlMockCommunication(transparency_log,
                                       self.mock_canned_response)
    return super(AftlMock, self).request_inclusion_proof(
        transparency_log, vbmeta_descriptor, version_inc, manufacturer_key_path,
        signing_helper, signing_helper_with_files, timeout,
        aftl_comms=aftl_comms)


class AftlTestCase(AftltoolTestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftlTestCase, self).setUp()
    self.set_up_environment()
    self.output_filename = 'vbmeta_icp.img'

    self.make_icp_default_params = {
        'vbmeta_image_path': self.vbmeta_image,
        'output': None,
        'signing_helper': None,
        'signing_helper_with_files': None,
        'version_incremental': '1',
        'transparency_log_servers': [self.aftl_host],
        'transparency_log_pub_keys': [self.aftl_pubkey],
        'manufacturer_key': self.manufacturer_key,
        'padding_size': 0,
        'timeout': None
    }

    self.info_icp_default_params = {
        'vbmeta_image_path': self.output_filename,
        'output': io.BytesIO()
    }

    self.verify_icp_default_params = {
        'vbmeta_image_path': self.output_filename,
        'transparency_log_pub_keys': [self.aftl_pubkey],
        'output': io.BytesIO()
    }

    self.load_test_aftl_default_params = {
        'vbmeta_image_path': self.vbmeta_image,
        'output': io.BytesIO(),
        'transparency_log_server': self.aftl_host,
        'transparency_log_pub_key': self.aftl_pubkey,
        'manufacturer_key': self.manufacturer_key,
        'process_count': 1,
        'submission_count': 1,
        'stats_filename': None,
        'preserve_icp_images': False,
        'timeout': None
    }

    self.load_test_stats_file_p1_s1 = 'load_test_p1_s1.csv'
    self.load_test_stats_file_p2_p2 = 'load_test_p2_s2.csv'

    self.files_to_cleanup = [
        self.output_filename,
        self.load_test_stats_file_p1_s1,
        self.load_test_stats_file_p2_p2
    ]

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    for filename in self.files_to_cleanup:
      try:
        os.remove(filename)
      except OSError:
        pass
    super(AftlTestCase, self).tearDown()

  def set_up_environment(self):
    """Sets up member variables for the particular test environment.

    This allows to have different settings and mocking for unit tests and
    integration tests.
    """
    raise NotImplementedError('set_up_environment() needs to be implemented '
                              'by subclass.')

  def get_aftl_implementation(self):
    """Gets the aftltool.Aftl implementation used for testing.

    This allows to have different Aftl implementations for unit tests and
    integration tests.
    """
    raise NotImplementedError('get_aftl_implementation() needs to be'
                              'implemented by subclass.')


class AftlTest(AftlTestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftlTest, self).setUp()
    self.mock_aftl_host = 'test.foo.bar:9000'

  def set_up_environment(self):
    """Sets up the environment for unit testing without networking."""
    self.aftl_host = 'test.foo.bar:9000'
    self.aftl_pubkey = self.get_testdata_path('aftltool/aftl_pubkey_1.pub')
    self.vbmeta_image = self.get_testdata_path('aftltool/aftl_input_vbmeta.img')
    self.manufacturer_key = self.get_testdata_path('testkey_rsa4096.pem')

  def get_aftl_implementation(self, canned_response):
    """Retrieves the AftlMock for unit testing without networking."""
    return AftlMock(canned_response)

  def test_get_vbmeta_image(self):
    """Tests the get_vbmeta_image method."""
    tool = aftltool.Aftl()

    # Valid vbmeta image without footer and AftlDescriptor.
    image, footer = tool.get_vbmeta_image(
        self.get_testdata_path('aftltool/aftl_input_vbmeta.img'))
    self.assertIsNotNone(image)
    self.assertEqual(len(image), 4352)
    self.assertIsNone(footer)

    # Valid vbmeta image without footer but with AftlDescriptor.
    image, footer = tool.get_vbmeta_image(
        self.get_testdata_path('aftltool/aftl_output_vbmeta_with_1_icp.img'))
    self.assertIsNotNone(image)
    self.assertEqual(len(image), 4352)
    self.assertIsNone(footer)

    # Invalid vbmeta image.
    image, footer = tool.get_vbmeta_image(
        self.get_testdata_path('large_blob.bin'))
    self.assertIsNone(image)
    self.assertIsNone(footer)

    # Invalid file path.
    image, footer = tool.get_vbmeta_image(
        self.get_testdata_path('blabli_not_existing_file'))
    self.assertIsNone(image)
    self.assertIsNone(footer)

  def test_get_aftl_descriptor(self):
    """Tests the get_aftl_descriptor method."""
    tool = aftltool.Aftl()

    # Valid vbmeta image without footer with AftlDescriptor.
    desc = tool.get_aftl_descriptor(
        self.get_testdata_path('aftltool/aftl_output_vbmeta_with_1_icp.img'))
    self.assertIsInstance(desc, aftltool.AftlDescriptor)

    # Valid vbmeta image without footer and AftlDescriptor.
    desc = tool.get_aftl_descriptor(
        self.get_testdata_path('aftltool/aftl_input_vbmeta.img'))
    self.assertIsNone(desc)

    # Invalid vbmeta image.
    desc = tool.get_aftl_descriptor(self.get_testdata_path('large_blob.bin'))
    self.assertIsNone(desc)

  # pylint: disable=no-member
  def test_request_inclusion_proof(self):
    """Tests the request_inclusion_proof method."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_afi_resp)

    icp = aftl.request_inclusion_proof(
        self.mock_aftl_host, 'a' * 1024, '1',
        self.get_testdata_path('testkey_rsa4096.pem'), None, None, None)
    self.assertEqual(icp.leaf_index,
                     self.test_afi_resp.fw_info_proof.proof.leaf_index)
    self.assertEqual(icp.proof_hash_count,
                     len(self.test_afi_resp.fw_info_proof.proof.hashes))
    self.assertEqual(icp.log_url, self.mock_aftl_host)
    self.assertEqual(
        icp.log_root_descriptor.root_hash, binascii.unhexlify(
            '53b182b55dc1377197c938637f50093131daea4d0696b1eae5b8a014bfde884a'))

    self.assertEqual(icp.fw_info_leaf.version_incremental, '1')
    # To calculate the hash of the a RSA key use the following command:
    # openssl rsa -in test/data/testkey_rsa4096.pem -pubout \
    #    -outform DER | sha256sum
    self.assertEqual(icp.fw_info_leaf.manufacturer_key_hash, base64.b64decode(
        'yBCrUOdjvaAh4git5EgqWa5neegUaoXeLlB67+N8ObY='))

    self.assertEqual(icp.log_root_signature,
                     self.test_afi_resp.fw_info_proof.sth.log_root_signature)
    self.assertEqual(icp.proofs, self.test_afi_resp.fw_info_proof.proof.hashes)

  # pylint: disable=no-member
  def test_request_inclusion_proof_failure(self):
    """Tests the request_inclusion_proof method in case of a comms problem."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(aftltool.AftlError('Comms error'))

    with self.assertRaises(aftltool.AftlError):
      aftl.request_inclusion_proof(
          self.mock_aftl_host, 'a' * 1024, 'version_inc',
          self.get_testdata_path('testkey_rsa4096.pem'), None, None, None)

  def test_request_inclusion_proof_manuf_key_not_4096(self):
    """Tests request_inclusion_proof with manufacturing key not of size 4096."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_afi_resp)
    with self.assertRaises(aftltool.AftlError) as e:
      aftl.request_inclusion_proof(
          self.mock_aftl_host, 'a' * 1024, 'version_inc',
          self.get_testdata_path('testkey_rsa2048.pem'), None, None, None)
    self.assertIn('not of size 4096: 2048', str(e.exception))

  def test_make_and_verify_icp_with_1_log(self):
    """Tests make_icp_from_vbmeta, verify_image_icp & info_image_icp."""
    aftl = self.get_aftl_implementation(self.test_afi_resp)

    # Make a VBmeta image with ICP.
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(**self.make_icp_default_params)
    self.assertTrue(result)

    # Checks that there is 1 ICP.
    aftl_descriptor = aftl.get_aftl_descriptor(self.output_filename)
    self.assertEqual(aftl_descriptor.icp_header.icp_count, 1)

    # Verifies the generated image.
    result = aftl.verify_image_icp(**self.verify_icp_default_params)
    self.assertTrue(result)

    # Prints the image details.
    result = aftl.info_image_icp(**self.info_icp_default_params)
    self.assertTrue(result)

  def test_make_and_verify_icp_with_2_logs(self):
    """Tests make_icp_from_vbmeta, verify_image_icp & info_image_icp."""
    aftl = self.get_aftl_implementation(self.test_afi_resp)

    # Reconfigures default parameters with two transparency logs.
    self.make_icp_default_params['transparency_log_servers'] = [
        self.aftl_host, self.aftl_host]
    self.make_icp_default_params['transparency_log_pub_keys'] = [
        self.aftl_pubkey, self.aftl_pubkey]

    # Make a VBmeta image with ICP.
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      self.assertTrue(result)

    # Checks that there are 2 ICPs.
    aftl_descriptor = aftl.get_aftl_descriptor(self.output_filename)
    self.assertEqual(aftl_descriptor.icp_header.icp_count, 2)

    # Verifies the generated image.
    result = aftl.verify_image_icp(**self.verify_icp_default_params)
    self.assertTrue(result)

    # Prints the image details.
    result = aftl.info_image_icp(**self.info_icp_default_params)
    self.assertTrue(result)

  def test_info_image_icp(self):
    """Tests info_image_icp with vbmeta image with 2 ICP."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_afi_resp)

    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_2_icp_different_logs.img')
    self.info_icp_default_params['vbmeta_image_path'] = image_path

    # Verifies the generated image.
    result = aftl.info_image_icp(**self.info_icp_default_params)
    self.assertTrue(result)

  def test_info_image_icp_fail(self):
    """Tests info_image_icp with invalid vbmeta image."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_afi_resp)

    image_path = self.get_testdata_path('large_blob.bin')
    self.info_icp_default_params['vbmeta_image_path'] = image_path

    # Verifies the generated image.
    result = aftl.info_image_icp(**self.info_icp_default_params)
    self.assertFalse(result)

  def test_verify_image_icp(self):
    """Tets verify_image_icp with 2 ICP with all matching log keys."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_afi_resp)

    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_2_icp_different_logs.img')
    self.verify_icp_default_params['vbmeta_image_path'] = image_path
    self.verify_icp_default_params['transparency_log_pub_keys'] = [
        self.get_testdata_path('aftltool/aftl_pubkey_1.pub'),
        self.get_testdata_path('aftltool/aftl_pubkey_2.pub')
    ]

    result = aftl.verify_image_icp(**self.verify_icp_default_params)
    self.assertTrue(result)

  def test_verify_image_icp_failure(self):
    """Tests verify_image_icp with 2 ICP but only one matching log key."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_afi_resp)

    image_path = self.get_testdata_path(
        'aftltool/aftl_output_vbmeta_with_2_icp_different_logs.img')
    self.verify_icp_default_params['vbmeta_image_path'] = image_path
    self.verify_icp_default_params['transparency_log_pub_keys'] = [
        self.get_testdata_path('aftltool/aftl_pubkey_1.pub')
    ]

    result = aftl.verify_image_icp(**self.verify_icp_default_params)
    self.assertFalse(result)

  def test_make_icp_with_invalid_grpc_service(self):
    """Tests make_icp_from_vbmeta command with a host that does not support GRPC."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))
    self.make_icp_default_params[
        'transparency_log_servers'] = ['www.google.com:80']
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      self.assertFalse(result)

  def test_make_icp_grpc_timeout(self):
    """Tests make_icp_from_vbmeta command when running into GRPC timeout."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))

    # The timeout is set to 1 second which is way below the minimum processing
    # time of the transparency log per load test results in b/139407814#2 where
    # it was 3.43 seconds.
    self.make_icp_default_params['timeout'] = 1
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      self.assertFalse(result)

  def test_load_test_single_process_single_submission(self):
    """Tests load_test_aftl command with 1 process which does 1 submission."""
    aftl = self.get_aftl_implementation(self.test_afi_resp)

    result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
    self.assertTrue(result)

    output = self.load_test_aftl_default_params['output'].getvalue()
    self.assertRegexpMatches(output, 'Succeeded:.+?1\n')
    self.assertRegexpMatches(output, 'Failed:.+?0\n')

    self.assertTrue(os.path.exists(self.load_test_stats_file_p1_s1))

  def test_load_test_multi_process_multi_submission(self):
    """Tests load_test_aftl command with 2 processes and 2 submissions each."""
    aftl = self.get_aftl_implementation(self.test_afi_resp)

    self.load_test_aftl_default_params['process_count'] = 2
    self.load_test_aftl_default_params['submission_count'] = 2
    result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
    self.assertTrue(result)

    output = self.load_test_aftl_default_params['output'].getvalue()
    self.assertRegexpMatches(output, 'Succeeded:.+?4\n')
    self.assertRegexpMatches(output, 'Failed:.+?0\n')

    self.assertTrue(os.path.exists(self.load_test_stats_file_p2_p2))

  def test_load_test_invalid_grpc_service(self):
    """Tests load_test_aftl command with a host that does not support GRPC."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))

    self.load_test_aftl_default_params[
        'transparency_log_server'] = 'www.google.com:80'
    result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
    self.assertFalse(result)

    output = self.load_test_aftl_default_params['output'].getvalue()
    self.assertRegexpMatches(output, 'Succeeded:.+?0\n')
    self.assertRegexpMatches(output, 'Failed:.+?1\n')

  def test_load_test_grpc_timeout(self):
    """Tests load_test_aftl command when running into timeout."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))

    self.load_test_aftl_default_params['timeout'] = 1
    result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
    self.assertFalse(result)

    output = self.load_test_aftl_default_params['output'].getvalue()
    self.assertRegexpMatches(output, 'Succeeded:.+?0\n')
    self.assertRegexpMatches(output, 'Failed:.+?1\n')


if __name__ == '__main__':
  unittest.main(verbosity=2)
