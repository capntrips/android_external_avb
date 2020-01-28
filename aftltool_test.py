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

import binascii
import os
import sys
import unittest

import aftltool

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

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    # Reconnects stderr back to the normal stderr; see setUp() for details.
    sys.stderr = self.stderr

    super(AftltoolTestCase, self).setUp()


class AftltoolTest(AftltoolTestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AftltoolTest, self).setUp()

    self.test_url = 'test'
    self.test_sth = aftltool.TrillianLogRootDescriptor()
    self.test_sth.leaf_hash = bytearray('leaf' * 8)
    self.test_sth.tree_size = 2
    self.test_sth.root_hash = bytearray('root' * 8)
    self.test_sth.root_hash_size = 32
    self.test_sth.log_root_sig = bytearray('root_sig' * 64)
    self.test_proofs = 'proofs'

  def _validate_icp_header(self, aftl_descriptor_size, icp_count):
    """Validate an ICP header structure and attempt to validate it.

    Arguments:
      aftl_descriptor_size: Total size of the AftlDescriptor.
      icp_count: Number of ICPs that follow the ICP header.

    Returns:
      True if the ICP header validates; otherwise False.
    """
    icp_header = aftltool.AftlIcpHeader()
    icp_header.aftl_descriptor_size = aftl_descriptor_size
    icp_header.icp_count = icp_count
    return icp_header.is_valid()

  def _validate_icp_entry_with_setters(
      self, log_url, leaf_index, log_root_descriptor, proofs):
    """Create an ICP entry structure and attempt to validate it.

    Returns:
      True if the tests pass, False otherwise.
    """
    icp_entry = aftltool.AftlIcpEntry()
    icp_entry.leaf_index = leaf_index
    icp_entry.set_log_url(log_url)
    icp_entry.set_log_root_descriptor(log_root_descriptor)
    icp_entry.set_proofs(proofs)
    return icp_entry.is_valid()

  def _validate_icp_entry_without_setters(
      self, log_url, log_url_size, leaf_index, log_root_descriptor,
      log_root_descriptor_size, proof_hash_count, proofs, inc_proof_size):
    """Create an ICP entry structure and attempt to validate it.

    Returns:
      True if the tests pass, False otherwise.
    """
    icp_entry = aftltool.AftlIcpEntry()
    icp_entry.log_url = log_url
    icp_entry.log_url_size = log_url_size
    icp_entry.leaf_index = leaf_index
    icp_entry.log_root_descriptor = log_root_descriptor
    icp_entry.log_root_descriptor_size = log_root_descriptor_size
    icp_entry.proof_hash_count = proof_hash_count
    icp_entry.proofs = proofs
    icp_entry.inc_proof_size = inc_proof_size
    return icp_entry.is_valid()

  def test_default_icp_header(self):
    """Tests default ICP header structure."""
    icp_header = aftltool.AftlIcpHeader()
    self.assertTrue(icp_header.is_valid())

  def test_valid_icp_header(self):
    """Tests valid ICP header structures."""
    self.assertTrue(self._validate_icp_header(icp_count=4,
                                              aftl_descriptor_size=18))

  def test_invalid_icp_header(self):
    """Tests invalid ICP header structures."""
    self.assertFalse(self._validate_icp_header(icp_count=-34,
                                               aftl_descriptor_size=18))
    self.assertFalse(self._validate_icp_header(icp_count=3,
                                               aftl_descriptor_size=10))

  def test_default_icp_entry(self):
    """Tests default ICP entry structure."""
    icp_entry = aftltool.AftlIcpEntry()
    self.assertTrue(icp_entry.is_valid())

  def test_icp_entry_valid(self):
    """Tests valid ICP entry structures."""
    self.assertTrue(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, self.test_proofs,
            len(self.test_proofs)))

    self.assertTrue(
        self._validate_icp_entry_with_setters(
            self.test_url, 2, self.test_sth, self.test_proofs))

    self.assertTrue(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, self.test_proofs,
            len(self.test_proofs)))

    self.assertTrue(
        self._validate_icp_entry_with_setters(
            self.test_url, 2, self.test_sth, self.test_proofs))

  def test_icp_entry_invalid_log_url(self):
    """Tests ICP entry with invalid log_url / log_url_size combination."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            None, 10, 2, self.test_sth, self.test_sth.get_expected_size(),
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            '', 10, 2, self.test_sth, self.test_sth.get_expected_size(),
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, -2, 2, self.test_sth,
            self.test_sth.get_expected_size(),
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url) - 3, 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, self.test_proofs,
            len(self.test_proofs)))

  def test_icp_entry_invalid_leaf_index(self):
    """Tests ICP entry with invalid leaf_index."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), -1, self.test_sth,
            self.test_sth.get_expected_size(), 2, self.test_proofs,
            len(self.test_proofs)))

  def test_icp_entry_invalid_sth(self):
    """Tests ICP entry with invalid STH / STH length."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, None, 3,
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, '', 3,
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, bytearray(), 3,
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth, -2,
            2, self.test_proofs, len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2,
            self.test_sth, self.test_sth.get_expected_size() + 14,
            2, self.test_proofs, len(self.test_proofs)))

  def test_icp_entry_invalid_proof_hash_count(self):
    """Tests ICP entry with invalid proof_hash_count."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), -2, self.test_proofs,
            len(self.test_proofs)))

  def test_icp_entry_invalid_proofs(self):
    """Tests ICP entry with invalid proofs / proof size."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, [], len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, '', len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, bytearray(),
            len(self.test_proofs)))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            self.test_sth.get_expected_size(), 2, self.test_proofs,
            len(self.test_proofs) - 3))

  def test_generate_icp_images(self):
    """Test cases for full AFTL ICP structure generation."""
    icp_header = aftltool.AftlIcpHeader()
    icp_header.icp_count = 1

    # Tests ICP header encoding.
    expected_header_bytes = bytearray(b'\x41\x46\x54\x4c\x00\x00\x00\x01\x00'
                                      '\x00\x00\x01\x00\x00\x00\x12\x00\x01')
    icp_header_bytes = icp_header.encode()
    self.assertEqual(icp_header_bytes, expected_header_bytes)

    # Tests ICP header decoding.
    icp_header = aftltool.AftlIcpHeader(expected_header_bytes)
    self.assertTrue(icp_header.is_valid())

    tl_url = 'aftl-test-server.google.com'
    sth = aftltool.TrillianLogRootDescriptor()
    sth.leaf_hash = bytearray('a' * 32)
    sth.tree_size = 2
    sth.root_hash = bytearray('f' * 32)
    sth.root_hash_size = 32
    # Fill each structure with an easily observable pattern for easy validation.
    proof_hashes = []
    proof_hashes.append(bytearray('b' * 32))
    proof_hashes.append(bytearray('c' * 32))
    proof_hashes.append(bytearray('d' * 32))
    proof_hashes.append(bytearray('e' * 32))
    self.assertTrue(self._validate_icp_entry_with_setters(
        tl_url, 1, sth, proof_hashes))

    # Tests ICP entry encoding.
    icp_entry = aftltool.AftlIcpEntry()
    icp_entry.set_log_url(tl_url)
    icp_entry.leaf_index = 1
    icp_entry.set_log_root_descriptor(sth)
    icp_entry.set_proofs(proof_hashes)
    icp_entry.log_root_signature = 'g' * 512  # bytearray('g' * 512)
    icp_entry.log_root_sig_size = 512
    icp_bytes = icp_entry.encode()

    expected_entry_bytes = bytearray(b'\x00\x00\x00\x1b\x00\x00\x00\x00\x00\x00'
                                     '\x00\x01\x00\x00\x00=\x00\x00\x00\x00\x02'
                                     '\x00\x04\x00\x00\x00\x80aftl-test-server.'
                                     'google.com\x00\x01\x00\x00\x00\x00\x00'
                                     '\x00\x00\x02 ffffffffffffffffffffffffffff'
                                     'ffff\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                     '\x00\x00\x00\x00\x00\x00\x00\x00\x00ggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'ggggggggggggggggggggggggggggggggggggggggg'
                                     'gggggggggggggggbbbbbbbbbbbbbbbbbbbbbbbbbb'
                                     'bbbbbbccccccccccccccccccccccccccccccccddd'
                                     'dddddddddddddddddddddddddddddeeeeeeeeeeee'
                                     'eeeeeeeeeeeeeeeeeeee')

    self.assertEqual(icp_bytes, expected_entry_bytes)

    # Tests ICP entry decoding.
    icp_entry = aftltool.AftlIcpEntry(expected_entry_bytes)
    self.assertTrue(icp_entry.is_valid())

    # Tests ICP blob with one entry.
    icp_blob = aftltool.AftlDescriptor()
    icp_blob.add_icp_entry(icp_entry)
    self.assertTrue(icp_blob.is_valid())

    # Now add a 2nd entry (this should fail).
    tl_url2 = 'aftl-test-server.google.ch'
    sth2 = aftltool.TrillianLogRootDescriptor()
    sth2.leaf_hash = bytearray('f' * 32)
    sth2.tree_size = 4
    sth2.root_hash = bytearray('e' * 32)
    sth2.root_hash_size = 32
    proof_hashes2 = []
    proof_hashes2.append(bytearray('g' * 32))
    proof_hashes2.append(bytearray('h' * 32))
    self.assertTrue(self, self._validate_icp_entry_with_setters(
        tl_url2, 2, sth2, proof_hashes2))

    icp_entry2 = aftltool.AftlIcpEntry()
    icp_entry2.set_log_url(tl_url2)
    icp_entry2.leaf_index = 2
    icp_entry2.set_log_root_descriptor(sth2)
    icp_entry2.log_root_signature = bytearray('d' * 512)
    icp_entry2.log_root_sig_size = 512
    icp_entry2.set_proofs(proof_hashes2)
    icp_blob.add_icp_entry(icp_entry2)
    self.assertTrue(icp_blob.is_valid())

    # Reset the ICP count to invalidate the entry.
    icp_blob.icp_header.icp_count = 1
    self.assertFalse(icp_blob.is_valid())

    # Fix the entries so this passes.
    icp_blob.icp_header.icp_count = 2
    self.assertTrue(icp_blob.is_valid())

    expected_blob_bytes = bytearray(b'AFTL\x00\x00\x00\x01\x00\x00\x00\x01\x00'
                                    '\x00\x00\x12\x00\x02\x00\x00\x00\x1b\x00'
                                    '\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00='
                                    '\x00\x00\x00\x00\x02\x00\x04\x00\x00\x00'
                                    '\x80aftl-test-server.google.com\x00\x01'
                                    '\x00\x00\x00\x00\x00\x00\x00\x02 fffffffff'
                                    'fffffffffffffffffffffff\x00\x00\x00\x00'
                                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                    '\x00\x00\x00\x00gggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'gggggggggggggggggggggggggggggggggggggggggg'
                                    'ggggggggggggggggggggggggbbbbbbbbbbbbbbbbbb'
                                    'bbbbbbbbbbbbbbcccccccccccccccccccccccccccc'
                                    'ccccddddddddddddddddddddddddddddddddeeeeee'
                                    'eeeeeeeeeeeeeeeeeeeeeeeeee\x00\x00\x00\x1a'
                                    '\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00'
                                    '\x00=\x00\x00\x00\x00\x02\x00\x02\x00\x00'
                                    '\x00@aftl-test-server.google.ch\x00\x01'
                                    '\x00\x00\x00\x00\x00\x00\x00\x04 eeeeeeeee'
                                    'eeeeeeeeeeeeeeeeeeeeeee\x00\x00\x00\x00'
                                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                    '\x00\x00\x00\x00dddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'dddddddddddddddddddddddddddddddddddddddddd'
                                    'ddddddddddddddddddddddddgggggggggggggggggg'
                                    'gggggggggggggghhhhhhhhhhhhhhhhhhhhhhhhhhhh'
                                    'hhhh')
    self.assertEqual(icp_blob.encode(), expected_blob_bytes)

    icp_blob = aftltool.AftlDescriptor(expected_blob_bytes)
    self.assertTrue(icp_blob.is_valid())

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


class TrillianLogRootDescriptorTest(AftltoolTestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(TrillianLogRootDescriptorTest, self).setUp()
    base_log_root = (
        '0001'                              # version
        '00000000000002e5'                  # tree_size
        '20'                                # root_hash_size
        '2d614759ad408a111a3351c0cb33c099'  # root_hash
        '422c30a5c5104788a343332bde2b387b'
        '15e1c97e3b4bd239'                  # timestamp
        '00000000000002e4'                  # revision
    )
    self.test_log_root_without_metadata = binascii.unhexlify(
        base_log_root + '0000')
    self.test_log_root_with_metadata = binascii.unhexlify(
        base_log_root + '00023132')

  def test_valid_empty_descriptor(self):
    """Tests behavior of instance creation without data."""
    d = aftltool.TrillianLogRootDescriptor()
    self.assertTrue(d.is_valid())

  def test_valid_parsed_descriptor_without_metadata(self):
    """Tests parsing of a Trillian log_root structure."""
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_without_metadata)
    self.assertTrue(d.is_valid())
    self.assertEqual(d.version, 1)
    self.assertEqual(d.tree_size, 741)
    self.assertEqual(d.root_hash_size, 32)
    self.assertEqual(binascii.hexlify(d.root_hash),
                     '2d614759ad408a111a3351c0cb33c099'
                     '422c30a5c5104788a343332bde2b387b')
    self.assertEqual(d.timestamp, 1576762888554271289)
    self.assertEqual(d.revision, 740)
    self.assertEqual(d.metadata_size, 0)
    self.assertEqual(d.metadata, bytearray())

  def test_valid_parsed_descriptor_with_metadata(self):
    """Tests parsing of a Trillian log_root structure with metadata field."""
    d = aftltool.TrillianLogRootDescriptor(self.test_log_root_with_metadata)
    self.assertTrue(d.is_valid())
    self.assertEqual(d.metadata_size, 2)
    self.assertEqual(d.metadata, bytearray('12'))


if __name__ == '__main__':
  unittest.main(verbosity=2)
