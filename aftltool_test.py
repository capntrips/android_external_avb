#!/usr/bin/env python3

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

import argparse
import binascii
import io
import os
import struct
import sys
import tempfile
import unittest

import aftltool
import avbtool

# pylint: disable=import-error
import api_pb2
# pylint: enable=import-error


# Workaround for b/149307145 in order to pick up the test data from the right
# location independent where the script is called from.
# TODO(b/149307145): Remove workaround once the referenced bug is fixed.
TEST_EXEC_PATH = os.path.dirname(os.path.realpath(__file__))

class TlsDataTest(unittest.TestCase):

  def test_decode(self):
    data = io.BytesIO(b'\x01\x02')
    value = aftltool.tls_decode_bytes('B', data)
    self.assertEqual(value, b'\x02')
    self.assertEqual(data.read(), b'')

    data = io.BytesIO(b'\x00\x01\x03\xff')
    value = aftltool.tls_decode_bytes('H', data)
    self.assertEqual(value, b'\x03')
    self.assertEqual(data.read(), b'\xff')

    data = io.BytesIO(b'\x00\x00\x00\x02\x04\x05\xff\xff')
    value = aftltool.tls_decode_bytes('L', data)
    self.assertEqual(value, b'\x04\x05')
    self.assertEqual(data.read(), b'\xff\xff')

  def test_decode_invalid(self):
    # Insufficient data for reading the size.
    with self.assertRaises(aftltool.AftlError):
      aftltool.tls_decode_bytes('B', io.BytesIO(b''))

    # Invalid byte_size character.
    with self.assertRaises(aftltool.AftlError):
      aftltool.tls_decode_bytes('/o/', io.BytesIO(b'\x01\x02\xff'))

    # Insufficient data for reading the value.
    with self.assertRaises(aftltool.AftlError):
      aftltool.tls_decode_bytes('B', io.BytesIO(b'\x01'))

  def test_encode(self):
    stream = io.BytesIO()
    aftltool.tls_encode_bytes('B', b'\x01\x02\x03\x04', stream)
    self.assertEqual(stream.getvalue(), b'\x04\x01\x02\x03\x04')

    stream = io.BytesIO()
    aftltool.tls_encode_bytes('H', b'\x01\x02\x03\x04', stream)
    self.assertEqual(stream.getvalue(), b'\x00\x04\x01\x02\x03\x04')

  def test_encode_invalid(self):
    # Byte size is not large enough to encode the value.
    stream = io.BytesIO()
    with self.assertRaises(aftltool.AftlError):
      aftltool.tls_encode_bytes('B', b'\x01'*256, stream)

    # Invalid byte_size character.
    stream = io.BytesIO()
    with self.assertRaises(aftltool.AftlError):
      aftltool.tls_encode_bytes('/o/', b'\x01\x02', stream)


class VBMetaPrimaryAnnotationTest(unittest.TestCase):

  def test_decode(self):
    stream = io.BytesIO(b'\x00\x00\x00\x00\x00')
    anno = aftltool.VBMetaPrimaryAnnotation.parse(stream)
    self.assertEqual(anno.vbmeta_hash, b'')
    self.assertEqual(anno.version_incremental, '')
    self.assertEqual(anno.manufacturer_key_hash, b'')
    self.assertEqual(anno.description, '')

  def test_encode(self):
    stream = io.BytesIO()
    anno = aftltool.VBMetaPrimaryAnnotation()
    anno.encode(stream)
    self.assertEqual(stream.getvalue(), b'\x00\x00\x00\x00\x00')

  def test_encode_invalid(self):
    stream = io.BytesIO()
    anno = aftltool.VBMetaPrimaryAnnotation()
    # Version incremental should be ASCII only.
    anno.version_incremental = '☃'
    with self.assertRaises(aftltool.AftlError):
      anno.encode(stream)


class SignedVBMetaAnnotationLeafTest(unittest.TestCase):

  def test_encode(self):
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf()
    self.assertEqual(leaf.encode(),
                     b'\x01'   # Version
                     b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Timestamp
                     b'\x01' + # Leaf Type
                     b'\x00' * 4 + # Empty Signature
                     b'\x00' * 5) # Empty Annotation

  def test_encode_invalid_type(self):
    # The version field must be a 1-byte integer.
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf()
    leaf.version = 'x'
    with self.assertRaises(aftltool.AftlError):
      leaf.encode()

  def test_encode_invalid_size(self):
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf()
    leaf.version = 256
    with self.assertRaises(aftltool.AftlError):
      leaf.encode()


class AftltoolTestCase(unittest.TestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftltoolTestCase, self).setUp()

    # Redirects the stderr to /dev/null when running the unittests. The reason
    # is that soong interprets any output on stderr as an error and marks the
    # unit test as failed although the test itself succeeded.
    self.stderr = sys.stderr
    self.null = open(os.devnull, 'wt')
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
    self.test_sth_1.root_hash = b'f' * 32
    self.test_sth_1.timestamp = 0x1234567890ABCDEF
    self.test_sth_1.revision = 0xFEDCBA0987654321

    self.test_sth_1_bytes = (
        b'\x00\x01'                          # version
        b'\x00\x00\x00\x00\x00\x00\x00\x02'  # tree_size
        b'\x20'                              # root_hash_size
        + b'f' * 32 +                        # root_hash
        b'\x12\x34\x56\x78\x90\xAB\xCD\xEF'  # timestamp
        b'\xFE\xDC\xBA\x09\x87\x65\x43\x21'  # revision
        b'\x00\x00'                          # metadata_size
        b''                                  # metadata (empty)
    )

    # Test Annotation #1
    anno_1 = aftltool.VBMetaPrimaryAnnotation(vbmeta_hash=b'w'*32,
                                              version_incremental='x'*5,
                                              manufacturer_key_hash=b'y'*32,
                                              description='z'*51)
    signed_anno_1 = aftltool.SignedVBMetaPrimaryAnnotation(annotation=anno_1)

    self.test_anno_1 = aftltool.SignedVBMetaPrimaryAnnotationLeaf(
        signed_vbmeta_primary_annotation=signed_anno_1)
    self.test_anno_1_bytes = (
        b'\x01'                              # version
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # timestamp
        b'\x01'                              # leaf_type
        b'\x00'                              # hash_algorithm
        b'\x00'                              # signature_algorithm
        + b'\x00\x00'                        # signature
        + b'\x20' + b'w' * 32                # vbmeta_hash
        + b'\x05' + b'x' * 5                 # version_incremental
        + b'\x20' + b'y' * 32                # manufacturer_key_hash
        + b'\x00\x33' + b'z' * 51            # description
    )

    # Fill each structure with an easily observable pattern for easy validation.
    self.test_proof_hashes_1 = []
    self.test_proof_hashes_1.append(b'b' * 32)
    self.test_proof_hashes_1.append(b'c' * 32)
    self.test_proof_hashes_1.append(b'd' * 32)
    self.test_proof_hashes_1.append(b'e' * 32)

    # Valid test AftlIcpEntry #1.
    self.test_entry_1 = aftltool.AftlIcpEntry()
    self.test_entry_1.log_url = self.test_tl_url_1
    self.test_entry_1.leaf_index = 1
    self.test_entry_1.annotation_leaf = self.test_anno_1
    self.test_entry_1.log_root_descriptor = self.test_sth_1
    self.test_entry_1.proofs = self.test_proof_hashes_1
    self.test_entry_1.log_root_signature = b'g' * 512

    self.test_entry_1_bytes = (
        b'\x00\x00\x00\x1b'                  # Transparency log url size.
        b'\x00\x00\x00\x00\x00\x00\x00\x01'  # Leaf index.
        b'\x00\x00\x00\x3d'                  # Log root descriptor size.
        b'\x00\x00\x00\x8b'                  # Annotation leaf size.
        b'\x02\x00'                          # Log root signature size.
        b'\x04'                              # Number of hashes in ICP.
        b'\x00\x00\x00\x80'                  # Size of ICP in bytes.
        + self.test_tl_url_1.encode('ascii') # Transparency log url.
        + self.test_sth_1_bytes
        + self.test_anno_1_bytes
        + b'g' * 512                         # Log root signature.
        + b'b' * 32                          # Hashes...
        + b'c' * 32
        + b'd' * 32
        + b'e' * 32)

    # Valid test AftlIcpEntry #2.
    self.test_tl_url_2 = 'aftl-test-server.google.ch'

    self.test_sth_2 = aftltool.TrillianLogRootDescriptor()
    self.test_sth_2.tree_size = 4
    self.test_sth_2.root_hash_size = 32
    self.test_sth_2.root_hash = b'e' * 32
    self.test_sth_2.timestamp = 6
    self.test_sth_2.revision = 7
    self.test_sth_2.metadata_size = 2
    self.test_sth_2.metadata = b'12'

    self.test_sth_2_bytes = (
        b'\x00\x01'                          # version
        b'\x00\x00\x00\x00\x00\x00\x00\x04'  # tree_size
        b'\x20'                              # root_hash_size
        + b'e' * 32 +                        # root_hash
        b'\x00\x00\x00\x00\x00\x00\x00\x06'  # timestamp
        b'\x00\x00\x00\x00\x00\x00\x00\x07'  # revision
        b'\x00\x02'                          # metadata_size
        b'12'                                # metadata
    )

    # Fill each structure with an easily observable pattern for easy validation.
    self.test_proof_hashes_2 = []
    self.test_proof_hashes_2.append(b'g' * 32)
    self.test_proof_hashes_2.append(b'h' * 32)

    self.test_entry_2 = aftltool.AftlIcpEntry()
    self.test_entry_2.log_url = self.test_tl_url_2
    self.test_entry_2.leaf_index = 2
    self.test_entry_2.annotation_leaf = self.test_anno_1
    self.test_entry_2.log_root_descriptor = self.test_sth_2
    self.test_entry_2.log_root_signature = b'd' * 512
    self.test_entry_2.proofs = self.test_proof_hashes_2

    self.test_entry_2_bytes = (
        b'\x00\x00\x00\x1a'                   # Transparency log url size.
        b'\x00\x00\x00\x00\x00\x00\x00\x02'   # Leaf index.
        b'\x00\x00\x00\x3f'                   # Log root descriptor size.
        b'\x00\x00\x00\x8b'                   # Annotation leaf size.
        b'\x02\x00'                           # Log root signature size.
        b'\x02'                               # Number of hashes in ICP.
        b'\x00\x00\x00\x40'                   # Size of ICP in bytes.
        + self.test_tl_url_2.encode('ascii')  # Transparency log url.
        + self.test_sth_2_bytes               # Log root
        + self.test_anno_1_bytes
        + b'd' * 512                          # Log root signature.
        + b'g' * 32                           # Hashes...
        + b'h' * 32)

    # Valid test AftlImage made out of AftlEntry #1 and #2.
    self.test_aftl_desc = aftltool.AftlImage()
    self.test_aftl_desc.add_icp_entry(self.test_entry_1)
    self.test_aftl_desc.add_icp_entry(self.test_entry_2)

    self.test_expected_aftl_image_bytes = (
        b'AFTL'                                         # Magic.
        + struct.pack('!L', avbtool.AVB_VERSION_MAJOR)  # Major version.
        + struct.pack('!L', avbtool.AVB_VERSION_MINOR)  # Minor version.
        + b'\x00\x00\x06\xcf'                           # Image size.
        b'\x00\x02'                                     # Number of ICP entries.
        + self.test_entry_1_bytes
        + self.test_entry_2_bytes)

    self.test_avbm_resp = api_pb2.AddVBMetaResponse()
    self.test_avbm_resp.annotation_proof.proof.leaf_index = 9127
    hashes = [
        '61076ca285b4982669e67757f55682ddc43ab5c11ba671260f82a8efa8831f94',
        '89c2fbcc58da25a65ce5e9b4fb22aaf208b20601f0bc023f73f05d35bc1f3bac',
        '75d26b5f754b4bed332a3ce2a2bfea0334706a974b7e00ee663f0279fa8b446e',
        'e1cd9c96feb893b5ef7771e424ac1c6c47509c2b98bc578d22ad07369c9641aa',
        'e83e0e4dd352b1670a55f93f88781a73bb41efcadb9927399f59459dfa14bc40',
        '8d5d25996117c88655d66f685baa3c94390867a040507b10587b17fbe92b496a',
        '5de4c627e9ca712f207d6056f56f0d3286ed4a5381ed7f3cc1aa470217734138',
        '19acfdb424d7fe28d1f850c76302f78f9a50146a5b9c65f9fdfbbc0173fd6993']
    for h in hashes:
      self.test_avbm_resp.annotation_proof.proof.hashes.append(
          binascii.unhexlify(h))
    self.test_avbm_resp.annotation_proof.sth.key_hint = binascii.unhexlify(
        '5af859abce8fe1ea')
    self.test_avbm_resp.annotation_proof.sth.log_root = binascii.unhexlify(
        '0001'
        '00000000000023a8'
        '20'
        '9a5f71340f8dc98bdc6320f976dda5f34db8554cb273ba5ab60f1697c519d6f6'
        '1609ae15024774b1'
        '0000000000001e5a'
        '0000'
    )
    self.test_avbm_resp.annotation_proof.sth.log_root_signature = (
        binascii.unhexlify(
            '7c37903cc76e8689a6b31da9ad56c3daeb6194029510297cc7d147278390da33'
            '09c4d9eb1f6be0cdcd1de5315b0b3b573cc9fcd8620d3fab956abbe3c597a572'
            '46e5a5d277c4cc4b590872d0292fa64e1d3285626b1dedeb00b6aa0a7a0717c0'
            '7d4c89b68fda9091be06180be1369675a7c4ce7f42cca133ef0daf8dcc5ba1ee'
            '930cef6dcb71b0a7690446e19661c8e18c089a5d6f6fc9299a0592efb33a4db5'
            '4c640027fa4f0ad0009f8bf75ec5fc17e0fa1091fabe74fe52738443745066ab'
            '48f99b297809b863c01016abda17a2479fce91f9929c60bc2ce15e474204fc5a'
            '8e79b2190aadb7c149671e8c76a4da506860f8d6020fb2eaabfee025cc267bad'
            '3c8257186c8aaf1da9eefe50cae4b3e8deb66033ebc4bfcda2b317f9e7d2dd78'
            'b47f2d86795815d82058ad4cba8fc7983a3bbf843e9b8c7ec7f1ae137be6848d'
            '03c76eefdac40ce5e66cc23d9f3e79ad87acbe7ec0c0bb419a7d368ae1e73c85'
            '742871f847bde69c871e8797638e0e270282fb058ef1cbcba52aded9dcc8249b'
            '38fbed8424c33b8cfcde4f49797c64dda8d089d73b84062602fd41c66091543c'
            'e13c18cfa7f8300530ad4b7adb8924bbb86d17bcc5f1d3d74c522a7dcc8c3c1f'
            '28a999f2fe1bfe5520c66f93f7c90996dc7f52e62dd95ace9ceace90324c3040'
            '669b7f5aeb5c5a53f217f1de46e32f80d0aaaf7d9cc9d0e8f8fd7026c612103a'
        )
    )

    anno = aftltool.VBMetaPrimaryAnnotation(
        vbmeta_hash=bytes.fromhex(
            '5623731104bfa1cfdb275df2978d1f93f72f5f0f746f11d06f3091c601c32067'),
        version_incremental='only_for_testing',
        manufacturer_key_hash=bytes.fromhex(
            '83ab3b109b73a1d32dce4153a2de57a1a0485052db8364f3180d98614749d7f7'))
    raw_signature = bytes.fromhex(
        '6a523021bc5b933bb58c38c8238be3a5fe1166002f5df8b77dee9dd22d353595'
        'be7996656d3824ebf4e1411a05ee3652d64669d3d62b167d3290dbdf4f2741ba'
        '4b6472e1bd71fc1860465fdcdca1ff08c4ab0420d7dcbf4ad144f64e211d8f92'
        '081ba51192358e2478195e573d000282423b23e6dd945069907dcf11520ff11a'
        '250e26643b820f8a5d80ccfe7d5d84f58e549cd05630f2254ade8edc88d9aa8a'
        'ec2089f84643854e1f265a4f746598ce4cae529c4eaa637f6e35fa1d1da9254e'
        'ec8dfede7a4313f7b151547dcdde98782ce6fb3149326ee5b8e750813d3fd37a'
        '738fe92f6111bf0dff4091769e216b842980e05716f2e50268a7dcca430e175e'
        '711f80e41a1a28f20635741ac11a56f97492d30db6d1955a827daf8e83faebe5'
        'a96e18a13c558ae561a02c90982514c853db0296c2e791e68b77c30e6232a3b7'
        'ed355441d4706277f33a01735f56cb8279336491731939691683f96f1c3e3183'
        'a0b77510d6ff0199b7688902044829793106546fd6fd4a5294d63c31c91256ad'
        'f7be6d053e77875698ad32ffaaeaac5d54b432e537f72549d2543072ae35578f'
        '138d82afcadd668511ba276ce02b6f9c18ef3b6f2f6ae0d123e9f8cb930f21a9'
        'c49a6d9e95de741c7860593a956735e1b77e9851ecb1f6572abf6e2c8ba15085'
        'e37e0f7bab0a30d108b997ed5edd74cf7f89cf082590a6f0af7a3a1f68c0077a')
    signature = aftltool.Signature(signature=raw_signature)
    signed_anno = aftltool.SignedVBMetaPrimaryAnnotation(annotation=anno,
                                                         signature=signature)
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf(
        timestamp=1587991742919072870,
        signed_vbmeta_primary_annotation=signed_anno).encode()
    self.test_avbm_resp.annotation_leaf = leaf


  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    # Reconnects stderr back to the normal stderr; see setUp() for details.
    sys.stderr = self.stderr
    self.null.close()

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


class AftlImageTest(AftltoolTestCase):

  def test__init__(self):
    """Tests the constructor."""
    # Calls constructor without data.
    d = aftltool.AftlImage()
    self.assertIsInstance(d.image_header, aftltool.AftlImageHeader)
    self.assertEqual(d.image_header.icp_count, 0)
    self.assertEqual(d.icp_entries, [])
    self.assertTrue(d.is_valid())

    # Calls constructor with data.
    d = aftltool.AftlImage(self.test_expected_aftl_image_bytes)
    self.assertIsInstance(d.image_header, aftltool.AftlImageHeader)
    self.assertEqual(d.image_header.icp_count, 2)
    self.assertEqual(len(d.icp_entries), 2)
    for entry in d.icp_entries:
      self.assertIsInstance(entry, aftltool.AftlIcpEntry)
    self.assertTrue(d.is_valid())

  def test_add_icp_entry(self):
    """Tests the add_icp_entry method."""
    d = aftltool.AftlImage()

    # Adds 1st ICP.
    d.add_icp_entry(self.test_entry_1)
    self.assertEqual(d.image_header.icp_count, 1)
    self.assertEqual(len(d.icp_entries), 1)
    self.assertTrue(d.is_valid())

    # Adds 2nd ICP.
    d.add_icp_entry(self.test_entry_2)
    self.assertEqual(d.image_header.icp_count, 2)
    self.assertEqual(len(d.icp_entries), 2)
    self.assertTrue(d.is_valid())

  def test_verify_vbmeta_image_with_1_icp(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 1 ICP.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftl_output_vbmeta_with_1_icp.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_image(image_path)

    # Valid image checked against correct log key.
    self.assertTrue(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftl_pubkey_1.pem')]))

    # Valid image checked with a key from another log.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('testkey_rsa4096_pub.pem')]))

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
        'aftl_output_vbmeta_with_2_icp_same_log.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_image(image_path)

    # Valid image checked against correct log key.
    self.assertTrue(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('aftl_pubkey_1.pem')]))

    # Valid vbmeta image checked with key from another log.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('testkey_rsa4096_pub.pem')]))

    # Valid image checked with non existed key file path.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('non_existent_blabli')]))

    # Valid image checked with invalid key.
    self.assertFalse(desc.verify_vbmeta_image(
        vbmeta_image, [self.get_testdata_path('large_blob.bin')]))

    # Valid image but checked with empty list of keys.
    self.assertFalse(desc.verify_vbmeta_image(vbmeta_image, []))

  def test_encode(self):
    """Tests encode method."""
    desc_bytes = self.test_aftl_desc.encode()
    self.assertEqual(desc_bytes, self.test_expected_aftl_image_bytes)

  def test_is_valid(self):
    """Tests is_valid method."""
    d = aftltool.AftlImage()
    d.add_icp_entry(self.test_entry_1)
    d.add_icp_entry(self.test_entry_2)

    # Force invalid ICP header.
    old_magic = d.image_header.magic
    d.image_header.magic = b'YOLO'
    self.assertFalse(d.is_valid())
    d.image_header.magic = old_magic
    self.assertTrue(d.is_valid())

    # Force count mismatch between header and actual entries.
    old_icp_count = d.image_header.icp_count
    d.image_header.icp_count = 1
    self.assertFalse(d.is_valid())
    d.image_header.icp_count = old_icp_count
    self.assertTrue(d.is_valid())

    # Force invalid ICP entry.
    old_leaf_index = d.icp_entries[0].leaf_index
    d.icp_entries[0].leaf_index = -10
    self.assertFalse(d.is_valid())
    d.icp_entries[0].leaf_index = old_leaf_index
    self.assertTrue(d.is_valid())

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.StringIO()
    self.test_aftl_desc.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Log Root Descriptor:', desc)


class AftlImageHeaderTest(AftltoolTestCase):
  """Test suite for testing the AftlImageHeader descriptor."""

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftlImageHeaderTest, self).setUp()

    self.test_header_valid = aftltool.AftlImageHeader()
    self.test_header_valid.icp_count = 1

    self.test_header_invalid = aftltool.AftlImageHeader()
    self.test_header_invalid.icp_count = -34

    self.test_header_bytes = (
        b'AFTL'                                         # Magic.
        + struct.pack('!L', avbtool.AVB_VERSION_MAJOR)  # Major version.
        + struct.pack('!L', avbtool.AVB_VERSION_MINOR)  # Minor version.
        + b'\x00\x00\x00\x12'                           # Image size.
        b'\x00\x01')                                    # Number of ICP entries.

  def test__init__(self):
    """Tests constructor."""

    # Calls constructor without data.
    header = aftltool.AftlImageHeader()
    self.assertEqual(header.magic, b'AFTL')
    self.assertEqual(header.required_icp_version_major,
                     avbtool.AVB_VERSION_MAJOR)
    self.assertEqual(header.required_icp_version_minor,
                     avbtool.AVB_VERSION_MINOR)
    self.assertEqual(header.aftl_image_size, aftltool.AftlImageHeader.SIZE)
    self.assertEqual(header.icp_count, 0)
    self.assertTrue(header.is_valid())

    # Calls constructor with data.
    header = aftltool.AftlImageHeader(self.test_header_bytes)
    self.assertEqual(header.magic, b'AFTL')
    self.assertEqual(header.required_icp_version_major,
                     avbtool.AVB_VERSION_MAJOR)
    self.assertEqual(header.required_icp_version_minor,
                     avbtool.AVB_VERSION_MINOR)
    self.assertEqual(header.aftl_image_size, aftltool.AftlImageHeader.SIZE)
    self.assertTrue(header.icp_count, 1)
    self.assertTrue(header.is_valid())

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
    header = aftltool.AftlImageHeader()
    self.assertTrue(header.is_valid())

    # Invalid magic.
    header = aftltool.AftlImageHeader()
    header.magic = b'YOLO'
    self.assertFalse(header.is_valid())

    # Valid ICP count.
    self.assertTrue(self.test_header_valid.is_valid())

    # Invalid ICP count.
    self.assertFalse(self.test_header_invalid.is_valid())

    header = aftltool.AftlImageHeader()
    header.icp_count = 10000000
    self.assertFalse(header.is_valid())

    # Invalid ICP major version.
    header = aftltool.AftlImageHeader()
    header.required_icp_version_major = avbtool.AVB_VERSION_MAJOR + 1
    self.assertFalse(header.is_valid())

    # Invalid ICP minor version.
    header = aftltool.AftlImageHeader()
    header.required_icp_version_minor = avbtool.AVB_VERSION_MINOR + 1
    self.assertFalse(header.is_valid())

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.StringIO()
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
    self.assertEqual(entry.annotation_leaf_size, 19)
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
    self.assertEqual(entry.annotation_leaf_size, 139)
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

  def test_get_expected_size(self):
    """Tests get_expected_size method."""
    # Default record.
    entry = aftltool.AftlIcpEntry()
    self.assertEqual(entry.get_expected_size(), 75)
    self.assertEqual(entry.get_expected_size(), len(entry.encode()))

    # Test record.
    self.assertEqual(self.test_entry_1.get_expected_size(), 894)
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

    entry.log_root_descriptor = b''
    self.assertFalse(entry.is_valid())

    entry.log_root_descriptor = b'blabli'
    self.assertFalse(entry.is_valid())

  def test_translate_response(self):
    """Tests translate_response method."""
    entry = aftltool.AftlIcpEntry()
    entry.translate_response('aftl-test.foo.bar:80', self.test_avbm_resp)
    self.assertEqual(entry.log_url, 'aftl-test.foo.bar:80')
    self.assertEqual(entry.leaf_index, 9127)
    self.assertEqual(entry.log_root_descriptor.encode(),
                     self.test_avbm_resp.annotation_proof.sth.log_root)
    self.assertEqual(
        entry.log_root_signature,
        self.test_avbm_resp.annotation_proof.sth.log_root_signature)
    self.assertEqual(
        entry.proofs,
        self.test_avbm_resp.annotation_proof.proof.hashes)

  def test_verify_icp(self):
    """Tests verify_icp method."""
    with tempfile.NamedTemporaryFile('wt+') as key_file:
      key_file.write(self.test_aftl_pub_key)
      key_file.flush()

      # Valid ICP.
      entry = aftltool.AftlIcpEntry()
      entry.translate_response(self.test_tl_url_1, self.test_avbm_resp)
      self.assertTrue(entry.verify_icp(key_file.name))

      # Invalid ICP where annotation_leaf is not matching up with proofs.
      # pylint: disable=protected-access
      entry = aftltool.AftlIcpEntry()
      entry.translate_response(self.test_tl_url_1, self.test_avbm_resp)
      vbmeta_hash = entry.annotation_leaf.annotation.vbmeta_hash
      vbmeta_hash = vbmeta_hash.replace(b"\x56\x23\x73\x11",
                                        b"\x00\x00\x00\x00")
      entry.annotation_leaf.annotation.vbmeta_hash = vbmeta_hash
      self.assertFalse(entry.verify_icp(key_file))

  def test_verify_vbmeta_image(self):
    """Tests the verify_vbmeta_image method."""
    # Valid vbmeta image without footer with 1 ICP.
    tool = aftltool.Aftl()
    image_path = self.get_testdata_path(
        'aftl_output_vbmeta_with_1_icp.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_image(image_path)

    # Checks that there is 1 ICP.
    self.assertEqual(desc.image_header.icp_count, 1)
    entry = desc.icp_entries[0]

    # Valid vbmeta image checked with correct log key.
    self.assertTrue(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('aftl_pubkey_1.pem')))

    # Valid vbmeta image checked with public key of another log.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('testkey_rsa4096_pub.pem')))

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
        'aftl_output_vbmeta_with_1_icp.img')
    vbmeta_image, _ = tool.get_vbmeta_image(image_path)
    desc = tool.get_aftl_image(image_path)

    self.assertEqual(desc.image_header.icp_count, 1)
    entry = desc.icp_entries[0]

    # Modify vbmeta image to become invalid
    vbmeta_image = b'A' * len(vbmeta_image)

    # Invalid vbmeta image checked with correct log key.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('aftl_pubkey_1.pem')))

    # Invalid vbmeta image checked with invalid key.
    self.assertFalse(entry.verify_vbmeta_image(
        vbmeta_image, self.get_testdata_path('large_blob.bin')))

    # Valid vbmeta image checked with no key.
    self.assertFalse(entry.verify_vbmeta_image(vbmeta_image, None))

    # None image checked with a key.
    self.assertFalse(entry.verify_vbmeta_image(
        None, self.get_testdata_path('aftl_pubkey_1.pem')))

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.StringIO()
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
    self.assertEqual(d.root_hash, b'')
    self.assertEqual(d.timestamp, 0)
    self.assertEqual(d.revision, 0)
    self.assertEqual(d.metadata_size, 0)
    self.assertEqual(d.metadata, b'')

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
    self.assertEqual(d.metadata, b'')

    # Calls constructor with log_root with metadata
    d = aftltool.TrillianLogRootDescriptor(
        self.test_log_root_bytes_with_metadata)
    self.assertEqual(d.metadata_size, 2)
    self.assertEqual(d.metadata, b'12')

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
    d.root_hash = b'123'
    self.assertFalse(d.is_valid())
    d.root_hash = b'1234'
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
    d.metadata = b'123'
    self.assertFalse(d.is_valid())
    d.metadata = b'1234'
    self.assertTrue(d.is_valid())

  def test_print_desc(self):
    """Tests print_desc method."""
    # Log root without metadata
    buf = io.StringIO()
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_bytes_wo_metadata)
    d.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Version:', desc)
    self.assertNotIn('Metadata:', desc)

    # Log root with metadata
    buf = io.StringIO()
    d = aftltool.TrillianLogRootDescriptor(
        self.test_log_root_bytes_with_metadata)
    d.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('Version:', desc)
    self.assertIn('Metadata:', desc)


class SignedVBMetaPrimaryAnnotationLeafTest(AftltoolTestCase):
  """Test suite for testing the Leaf."""

  def test__init__(self):
    """Tests constructor and properties methods."""
    # Calls constructor without data.
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf()
    self.assertEqual(leaf.version, 1)
    self.assertEqual(leaf.timestamp, 0)
    self.assertEqual(leaf.signature.signature, b'')
    self.assertEqual(leaf.annotation.vbmeta_hash, b'')
    self.assertEqual(leaf.annotation.description, '')

  def test_parse(self):
    # Calls parse with valid data.
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf.parse(
        self.test_anno_1_bytes)
    self.assertEqual(leaf.annotation.vbmeta_hash, b'w'*32)
    self.assertEqual(leaf.annotation.version_incremental, 'x'*5)
    self.assertEqual(leaf.annotation.manufacturer_key_hash, b'y'*32)
    self.assertEqual(leaf.annotation.description, 'z'*51)

    # Calls parse with invalid data.
    with self.assertRaises(aftltool.AftlError):
      leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf.parse(b'Invalid data')

  def test_get_expected_size(self):
    """Tests get_expected_size method."""
    # Calls constructor without data.
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf()
    self.assertEqual(leaf.get_expected_size(), 19)

    # Calls constructor with data.
    leaf = aftltool.SignedVBMetaPrimaryAnnotationLeaf.parse(
        self.test_anno_1_bytes)
    self.assertEqual(leaf.get_expected_size(),
                     len(self.test_anno_1_bytes))

  def test_encode(self):
    """Tests encode method."""
    # Calls constructor with data.
    self.assertEqual(self.test_anno_1.encode(),
                     self.test_anno_1_bytes)

  def test_print_desc(self):
    """Tests print_desc method."""
    buf = io.StringIO()
    self.test_anno_1.print_desc(buf)
    desc = buf.getvalue()

    # Cursory check whether the printed description contains something useful.
    self.assertGreater(len(desc), 0)
    self.assertIn('VBMeta hash:', desc)


class AftlMockCommunication(aftltool.AftlCommunication):
  """Testing Mock implementation of AftlCommunication."""

  def __init__(self, transparency_log_config, canned_response):
    """Initializes the object.

    Arguments:
      transparency_log_config: An aftltool.TransparencyLogConfig instance.
      canned_response: AddVBMetaResponse to return or the Exception to
        raise.
    """
    super(AftlMockCommunication, self).__init__(transparency_log_config,
                                                timeout=None)
    self.request = None
    self.canned_response = canned_response

  def add_vbmeta(self, request):
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
      canned_response: AddVBMetaResponse to return or the Exception to
        raise.
    """
    self.mock_canned_response = canned_response

  def request_inclusion_proof(self, transparency_log_config, vbmeta_image,
                              version_inc, manufacturer_key_path,
                              signing_helper, signing_helper_with_files,
                              timeout, aftl_comms=None):
    """Mocked request_inclusion_proof function."""
    aftl_comms = AftlMockCommunication(transparency_log_config,
                                       self.mock_canned_response)
    return super(AftlMock, self).request_inclusion_proof(
        transparency_log_config, vbmeta_image, version_inc,
        manufacturer_key_path, signing_helper, signing_helper_with_files,
        timeout, aftl_comms=aftl_comms)


class AftlTestCase(AftltoolTestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftlTestCase, self).setUp()

    # Sets up the member variables which are then configured by
    # set_up_environment() in the subclasses.
    self.aftl_host = None
    self.aftl_pubkey = None
    self.aftl_apikey = None
    self.vbmeta_image = None
    self.manufacturer_key = None
    self.set_up_environment()

    self.transparency_log_config = aftltool.TransparencyLogConfig(
        self.aftl_host, self.aftl_pubkey, self.aftl_apikey)

    self.make_icp_default_params = {
        'vbmeta_image_path': self.vbmeta_image,
        'output': None,
        'signing_helper': None,
        'signing_helper_with_files': None,
        'version_incremental': '1',
        'transparency_log_configs': [self.transparency_log_config],
        'manufacturer_key': self.manufacturer_key,
        'padding_size': 0,
        'timeout': None
    }

    self.info_icp_default_params = {
        'vbmeta_image_path': None,
        'output': io.StringIO()
    }

    self.verify_icp_default_params = {
        'vbmeta_image_path': None,
        'transparency_log_pub_keys': [self.aftl_pubkey],
        'output': io.StringIO()
    }

    self.load_test_aftl_default_params = {
        'vbmeta_image_path': self.vbmeta_image,
        'output': io.StringIO(),
        'transparency_log_config': self.transparency_log_config,
        'manufacturer_key': self.manufacturer_key,
        'process_count': 1,
        'submission_count': 1,
        'stats_filename': None,
        'preserve_icp_images': False,
        'timeout': None
    }

  def set_up_environment(self):
    """Sets up member variables for the particular test environment.

    This allows to have different settings and mocking for unit tests and
    integration tests.
    """
    raise NotImplementedError('set_up_environment() needs to be implemented '
                              'by subclass.')

  def get_aftl_implementation(self, canned_response):
    """Gets the aftltool.Aftl implementation used for testing.

    This allows to have different Aftl implementations for unit tests and
    integration tests.

    Arguments:
      canned_response: Since we are using the actual implementation and not a
      mock this gets ignored.

    Raises:
      NotImplementedError if subclass is not implementing the method.
    """
    raise NotImplementedError('get_aftl_implementation() needs to be'
                              'implemented by subclass.')


class AftlTest(AftlTestCase):

  def set_up_environment(self):
    """Sets up the environment for unit testing without networking."""
    self.aftl_host = 'test.foo.bar:9000'
    self.aftl_pubkey = self.get_testdata_path('aftl_pubkey_1.pem')
    self.vbmeta_image = self.get_testdata_path('aftl_input_vbmeta.img')
    self.manufacturer_key = self.get_testdata_path('testkey_rsa4096.pem')

  def get_aftl_implementation(self, canned_response):
    """Retrieves the AftlMock for unit testing without networking."""
    return AftlMock(canned_response)

  def test_get_vbmeta_image(self):
    """Tests the get_vbmeta_image method."""
    tool = aftltool.Aftl()

    # Valid vbmeta image without footer and AftlImage.
    image, footer = tool.get_vbmeta_image(
        self.get_testdata_path('aftl_input_vbmeta.img'))
    self.assertIsNotNone(image)
    self.assertEqual(len(image), 4352)
    self.assertIsNone(footer)

    # Valid vbmeta image without footer but with AftlImage.
    image, footer = tool.get_vbmeta_image(
        self.get_testdata_path('aftl_output_vbmeta_with_1_icp.img'))
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

  def test_get_aftl_image(self):
    """Tests the get_aftl_image method."""
    tool = aftltool.Aftl()

    # Valid vbmeta image without footer with AftlImage.
    desc = tool.get_aftl_image(
        self.get_testdata_path('aftl_output_vbmeta_with_1_icp.img'))
    self.assertIsInstance(desc, aftltool.AftlImage)

    # Valid vbmeta image without footer and AftlImage.
    desc = tool.get_aftl_image(
        self.get_testdata_path('aftl_input_vbmeta.img'))
    self.assertIsNone(desc)

    # Invalid vbmeta image.
    desc = tool.get_aftl_image(self.get_testdata_path('large_blob.bin'))
    self.assertIsNone(desc)

  # pylint: disable=no-member
  def test_request_inclusion_proof(self):
    """Tests the request_inclusion_proof method."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_avbm_resp)

    icp = aftl.request_inclusion_proof(
        self.transparency_log_config, b'a' * 1024, '1',
        self.get_testdata_path('testkey_rsa4096.pem'), None, None, None)
    self.assertEqual(icp.leaf_index,
                     self.test_avbm_resp.annotation_proof.proof.leaf_index)
    self.assertEqual(icp.proof_hash_count,
                     len(self.test_avbm_resp.annotation_proof.proof.hashes))
    self.assertEqual(icp.log_url, self.aftl_host)
    self.assertEqual(
        icp.log_root_descriptor.root_hash, binascii.unhexlify(
            '9a5f71340f8dc98bdc6320f976dda5f34db8554cb273ba5ab60f1697c519d6f6'))

    self.assertEqual(icp.annotation_leaf.annotation.version_incremental,
                     'only_for_testing')
    # To calculate the hash of the a RSA key use the following command:
    # openssl rsa -in test/data/testkey_rsa4096.pem -pubout \
    #    -outform DER | sha256sum
    self.assertEqual(
        icp.annotation_leaf.annotation.manufacturer_key_hash,
        bytes.fromhex(
            "83ab3b109b73a1d32dce4153a2de57a1a0485052db8364f3180d98614749d7f7"))

    self.assertEqual(
        icp.log_root_signature,
        self.test_avbm_resp.annotation_proof.sth.log_root_signature)
    self.assertEqual(
        icp.proofs,
        self.test_avbm_resp.annotation_proof.proof.hashes)

  # pylint: disable=no-member
  def test_request_inclusion_proof_failure(self):
    """Tests the request_inclusion_proof method in case of a comms problem."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(aftltool.AftlError('Comms error'))

    with self.assertRaises(aftltool.AftlError):
      aftl.request_inclusion_proof(
          self.transparency_log_config, b'a' * 1024, 'version_inc',
          self.get_testdata_path('testkey_rsa4096.pem'), None, None, None)

  def test_request_inclusion_proof_manuf_key_not_4096(self):
    """Tests request_inclusion_proof with manufacturing key not of size 4096."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_avbm_resp)
    with self.assertRaises(aftltool.AftlError) as e:
      aftl.request_inclusion_proof(
          self.transparency_log_config, b'a' * 1024, 'version_inc',
          self.get_testdata_path('testkey_rsa2048.pem'), None, None, None)
    self.assertIn('not of size 4096: 2048', str(e.exception))

  def test_make_and_verify_icp_with_1_log(self):
    """Tests make_icp_from_vbmeta, verify_image_icp & info_image_icp."""
    aftl = self.get_aftl_implementation(self.test_avbm_resp)

    # Make a VBmeta image with ICP.
    with tempfile.NamedTemporaryFile('wb+') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(**self.make_icp_default_params)
      output_file.flush()
      self.assertTrue(result)

      # Checks that there is 1 ICP.
      aftl_image = aftl.get_aftl_image(output_file.name)
      self.assertEqual(aftl_image.image_header.icp_count, 1)

      # Verifies the generated image.
      self.verify_icp_default_params['vbmeta_image_path'] = output_file.name
      result = aftl.verify_image_icp(**self.verify_icp_default_params)
      self.assertTrue(result)

      # Prints the image details.
      self.info_icp_default_params['vbmeta_image_path'] = output_file.name
      result = aftl.info_image_icp(**self.info_icp_default_params)
      self.assertTrue(result)

  def test_make_and_verify_icp_with_2_logs(self):
    """Tests make_icp_from_vbmeta, verify_image_icp & info_image_icp."""
    aftl = self.get_aftl_implementation(self.test_avbm_resp)

    # Reconfigures default parameters with two transparency logs.
    self.make_icp_default_params['transparency_log_configs'] = [
        self.transparency_log_config, self.transparency_log_config]

    # Make a VBmeta image with ICP.
    with tempfile.NamedTemporaryFile('wb+') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      output_file.flush()
      self.assertTrue(result)

      # Checks that there are 2 ICPs.
      aftl_image = aftl.get_aftl_image(output_file.name)
      self.assertEqual(aftl_image.image_header.icp_count, 2)

      # Verifies the generated image.
      self.verify_icp_default_params['vbmeta_image_path'] = output_file.name
      result = aftl.verify_image_icp(**self.verify_icp_default_params)
      self.assertTrue(result)

      # Prints the image details.
      self.info_icp_default_params['vbmeta_image_path'] = output_file.name
      result = aftl.info_image_icp(**self.info_icp_default_params)
      self.assertTrue(result)

  def test_info_image_icp(self):
    """Tests info_image_icp with vbmeta image with 2 ICP."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_avbm_resp)

    image_path = self.get_testdata_path(
        'aftl_output_vbmeta_with_2_icp_same_log.img')
    self.info_icp_default_params['vbmeta_image_path'] = image_path

    # Verifies the generated image.
    result = aftl.info_image_icp(**self.info_icp_default_params)
    self.assertTrue(result)

  def test_info_image_icp_fail(self):
    """Tests info_image_icp with invalid vbmeta image."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_avbm_resp)

    image_path = self.get_testdata_path('large_blob.bin')
    self.info_icp_default_params['vbmeta_image_path'] = image_path

    # Verifies the generated image.
    result = aftl.info_image_icp(**self.info_icp_default_params)
    self.assertFalse(result)

  def test_verify_image_icp(self):
    """Tets verify_image_icp with 2 ICP with all matching log keys."""
    # Always work with a mock independent if run as unit or integration tests.
    aftl = AftlMock(self.test_avbm_resp)

    image_path = self.get_testdata_path(
        'aftl_output_vbmeta_with_2_icp_same_log.img')
    self.verify_icp_default_params['vbmeta_image_path'] = image_path
    self.verify_icp_default_params['transparency_log_pub_keys'] = [
        self.get_testdata_path('aftl_pubkey_1.pem'),
    ]

    result = aftl.verify_image_icp(**self.verify_icp_default_params)
    self.assertTrue(result)

  def test_make_icp_with_invalid_grpc_service(self):
    """Tests make_icp_from_vbmeta command with a host not supporting GRPC."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))
    self.make_icp_default_params[
        'transparency_log_configs'][0].target = 'www.google.com:80'
    with tempfile.NamedTemporaryFile('wb+') as output_file:
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
    with tempfile.NamedTemporaryFile('wb+') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = aftl.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      self.assertFalse(result)

  def test_load_test_single_process_single_submission(self):
    """Tests load_test_aftl command with 1 process which does 1 submission."""
    aftl = self.get_aftl_implementation(self.test_avbm_resp)

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.load_test_aftl_default_params[
          'stats_filename'] = os.path.join(tmp_dir, 'load_test.csv')
      result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
      self.assertTrue(result)

      output = self.load_test_aftl_default_params['output'].getvalue()
      self.assertRegex(output, 'Succeeded:.+?1\n')
      self.assertRegex(output, 'Failed:.+?0\n')

      self.assertTrue(os.path.exists(
          self.load_test_aftl_default_params['stats_filename']))

  def test_load_test_multi_process_multi_submission(self):
    """Tests load_test_aftl command with 2 processes and 2 submissions each."""
    aftl = self.get_aftl_implementation(self.test_avbm_resp)

    self.load_test_aftl_default_params['process_count'] = 2
    self.load_test_aftl_default_params['submission_count'] = 2
    with tempfile.TemporaryDirectory() as tmp_dir:
      self.load_test_aftl_default_params[
          'stats_filename'] = os.path.join(tmp_dir, 'load_test.csv')
      result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
      self.assertTrue(result)

      output = self.load_test_aftl_default_params['output'].getvalue()
      self.assertRegex(output, 'Succeeded:.+?4\n')
      self.assertRegex(output, 'Failed:.+?0\n')

      self.assertTrue(os.path.exists(
          self.load_test_aftl_default_params['stats_filename']))

  def test_load_test_invalid_grpc_service(self):
    """Tests load_test_aftl command with a host that does not support GRPC."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))

    self.load_test_aftl_default_params[
        'transparency_log_config'].target = 'www.google.com:80'
    result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
    self.assertFalse(result)

    output = self.load_test_aftl_default_params['output'].getvalue()
    self.assertRegex(output, 'Succeeded:.+?0\n')
    self.assertRegex(output, 'Failed:.+?1\n')

  def test_load_test_grpc_timeout(self):
    """Tests load_test_aftl command when running into timeout."""
    aftl = self.get_aftl_implementation(aftltool.AftlError('Comms error'))

    self.load_test_aftl_default_params['timeout'] = 1
    result = aftl.load_test_aftl(**self.load_test_aftl_default_params)
    self.assertFalse(result)

    output = self.load_test_aftl_default_params['output'].getvalue()
    self.assertRegex(output, 'Succeeded:.+?0\n')
    self.assertRegex(output, 'Failed:.+?1\n')


class TransparencyLogConfigTestCase(unittest.TestCase):

  def test_from_argument(self):
    log = aftltool.TransparencyLogConfig.from_argument(
        "example.com:8080,mykey.pub")
    self.assertEqual(log.target, "example.com:8080")
    self.assertEqual(log.pub_key, "mykey.pub")

    with self.assertRaises(argparse.ArgumentTypeError):
      aftltool.TransparencyLogConfig.from_argument("example.com:8080,")

    with self.assertRaises(argparse.ArgumentTypeError):
      aftltool.TransparencyLogConfig.from_argument(",")

  def test_from_argument_with_api_key(self):
    log = aftltool.TransparencyLogConfig.from_argument(
        "example.com:8080,mykey.pub,Aipl29gj3x9")
    self.assertEqual(log.target, "example.com:8080")
    self.assertEqual(log.pub_key, "mykey.pub")
    self.assertEqual(log.api_key, "Aipl29gj3x9")

if __name__ == '__main__':
  unittest.main(verbosity=2)
