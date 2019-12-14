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
"""Unit tests for avbtool."""

# pylint: disable=unused-import
from __future__ import print_function

import os
import sys
import unittest

import avbtool

class AvbtoolTest(unittest.TestCase):

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    self.test_url = "test"
    self.test_sth = "sth"
    self.test_proofs = "proofs"

    # Redirects the stderr to /dev/null when running the unittests. The reason
    # is that soong interprets any output on stderr as an error and marks the
    # unit test as failed although the test itself succeeded.
    self.stderr = sys.stderr
    self.null = open(os.devnull, 'wb')
    sys.stderr = self.null

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    # Reconnects stderr back to the normal stderr; see setUp() for details.
    sys.stdout = self.stderr

  def _validate_icp_header(self, algorithm, icp_count):
    """Validate an ICP header structure and attempt to validate it.

    Arguments:
      algorithm: The algorithm to be used.
      icp_count: Number of ICPs that follow the ICP header.

    Returns:
      True if the ICP header validates; otherwise False.
    """
    icp_header = avbtool.AvbIcpHeader()
    icp_header.algorithm = algorithm
    icp_header.icp_count = icp_count
    return icp_header.is_valid()

  def _validate_icp_entry_with_setters(
      self, log_url, leaf_index, signed_root_blob, proof_hash_count, proofs,
      next_entry):
    """Create an ICP entry structure and attempt to validate it.

    Returns:
      True if the tests pass, False otherwise.
    """
    icp_entry = avbtool.AvbIcpEntry()
    icp_entry.leaf_index = leaf_index
    icp_entry.next_entry = next_entry
    icp_entry.set_log_url(log_url)
    icp_entry.set_signed_root_blob(signed_root_blob)
    icp_entry.set_proofs(proof_hash_count, proofs)
    return icp_entry.is_valid()

  def _validate_icp_entry_without_setters(
      self, log_url, log_url_size, leaf_index, signed_root_blob,
      signed_root_blob_size, proof_hash_count, proofs, proof_size, next_entry):
    """Create an ICP entry structure and attempt to validate it.

    Returns:
      True if the tests pass, False otherwise.
    """
    icp_entry = avbtool.AvbIcpEntry()
    icp_entry.log_url = log_url
    icp_entry.log_url_size = log_url_size
    icp_entry.leaf_index = leaf_index
    icp_entry.signed_root_blob = signed_root_blob
    icp_entry.signed_root_blob_size = signed_root_blob_size
    icp_entry.proof_hash_count = proof_hash_count
    icp_entry.proofs = proofs
    icp_entry.proof_size = proof_size
    icp_entry.next_entry = next_entry
    return icp_entry.is_valid()

  def test_default_icp_header(self):
    """Tests default ICP header structure."""
    icp_header = avbtool.AvbIcpHeader()
    self.assertTrue(icp_header.is_valid())

  def test_valid_icp_header(self):
    """Tests valid ICP header structures."""
    # 1 is SHA256/RSA4096
    self.assertTrue(self._validate_icp_header(algorithm=1, icp_count=4))

  def test_invalid_icp_header(self):
    """Tests invalid ICP header structures."""
    self.assertFalse(self._validate_icp_header(algorithm=-12, icp_count=4))
    self.assertFalse(self._validate_icp_header(algorithm=4, icp_count=-34))
    self.assertFalse(self._validate_icp_header(algorithm=10, icp_count=10))

  def test_default_icp_entry(self):
    """Tests default ICP entry structure."""
    icp_entry = avbtool.AvbIcpEntry()
    self.assertTrue(icp_entry.is_valid())

  def test_icp_entry_valid(self):
    """Tests valid ICP entry structures."""
    self.assertTrue(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), 2, self.test_proofs, len(self.test_proofs), 0))

    self.assertTrue(
        self._validate_icp_entry_with_setters(
            self.test_url, 2, self.test_sth, 2, self.test_proofs, 0))

    self.assertTrue(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), 2, self.test_proofs, len(self.test_proofs), 1))

    self.assertTrue(
        self._validate_icp_entry_with_setters(
            self.test_url, 2, self.test_sth, 2, self.test_proofs, 1))

  def test_icp_entry_invalid_log_url(self):
    """Tests ICP entry with invalid log_url / log_url_size combination."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            None, 10, 2, self.test_sth, len(self.test_sth),
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            '', 10, 2, self.test_sth, len(self.test_sth),
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, -2, 2, self.test_sth, len(self.test_sth),
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url) - 3, 2, self.test_sth,
            len(self.test_sth), 2, self.test_proofs, len(self.test_proofs), 0))

  def test_icp_entry_invalid_leaf_index(self):
    """Tests ICP entry with invalid leaf_index."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), -1, self.test_sth,
            len(self.test_sth), 2, self.test_proofs, len(self.test_proofs), 1))

  def test_icp_entry_invalid_sth(self):
    """Tests ICP entry with invalid STH / STH length."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, None, 3,
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, '', 3,
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, bytearray(), 3,
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth, -2,
            2, self.test_proofs, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2,
            self.test_sth, len(self.test_sth) + 14,
            2, self.test_proofs, len(self.test_proofs), 0))

  def test_icp_entry_invalid_proof_hash_count(self):
    """Tests ICP entry with invalid proof_hash_count."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), -2, self.test_proofs, len(self.test_proofs), 1))

  def test_icp_entry_invalid_proofs(self):
    """Tests ICP entry with invalid proofs / proof size."""
    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), 2, None, len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), 2, '', len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), 2, bytearray(), len(self.test_proofs), 0))

    self.assertFalse(
        self._validate_icp_entry_without_setters(
            self.test_url, len(self.test_url), 2, self.test_sth,
            len(self.test_sth), 2, self.test_proofs,
            len(self.test_proofs) - 3, 0))

  def test_icp_entry_invalid_next_entry(self):
    """Tests ICP entry with invalid next_entry."""
    self.assertFalse(self._validate_icp_entry_without_setters(
        self.test_url, len(self.test_url), 2, self.test_sth, len(self.test_sth),
        2, self.test_proofs, len(self.test_proofs), 2))

  def test_generate_icp_images(self):
    """Test cases for full AFTL ICP structure generation."""
    icp_header = avbtool.AvbIcpHeader()
    icp_header.algorithm = 1
    icp_header.icp_count = 1

    # Tests ICP header encoding.
    expected_header_bytes = bytearray(b'\x41\x46\x54\x4c\x00\x00\x00\x01'
                                      '\x00\x00\x00\x01\x00\x00\x00\x01'
                                      '\x00\x01')
    icp_header_bytes = icp_header.encode()
    self.assertEqual(icp_header_bytes, expected_header_bytes)

    # Tests ICP header decoding.
    icp_header = avbtool.AvbIcpHeader(expected_header_bytes)
    self.assertTrue(icp_header.is_valid())

    tl_url = 'aftl-test-server.google.com'
    sth = bytearray()
    # Fill each structure with an easily observable pattern for easy validation.
    sth.extend('a' * 160)
    proof_hashes = bytearray()
    proof_hashes.extend('b' * 32)
    proof_hashes.extend('c' * 32)
    proof_hashes.extend('d' * 32)
    proof_hashes.extend('e' * 32)
    self.assertTrue(self._validate_icp_entry_with_setters(
        tl_url, 1, sth, 4, proof_hashes, 0))

    # Tests ICP entry encoding.
    icp_entry = avbtool.AvbIcpEntry()
    icp_entry.set_log_url(tl_url)
    icp_entry.leaf_index = 1
    icp_entry.set_signed_root_blob(sth)
    icp_entry.set_proofs(4, proof_hashes)
    icp_entry.next_entry = 0
    expected_entry_bytes = bytearray(b'\x00\x00\x00\x1b\x00\x00\x00\x00\x00\x00'
                                     '\x00\x01\x00\x00\x00\xa0\x04\x00\x00\x00'
                                     '\x80\x00\x61\x66\x74\x6c\x2d\x74\x65\x73'
                                     '\x74\x2d\x73\x65\x72\x76\x65\x72\x2e\x67'
                                     '\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
                                     '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x62'
                                     '\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62'
                                     '\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62'
                                     '\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62'
                                     '\x62\x63\x63\x63\x63\x63\x63\x63\x63\x63'
                                     '\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63'
                                     '\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63'
                                     '\x63\x63\x63\x64\x64\x64\x64\x64\x64\x64'
                                     '\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64'
                                     '\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64'
                                     '\x64\x64\x64\x64\x64\x65\x65\x65\x65\x65'
                                     '\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65'
                                     '\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65'
                                     '\x65\x65\x65\x65\x65\x65\x65')
    self.assertEqual(icp_entry.encode(), expected_entry_bytes)

    # Tests ICP entry decoding.
    icp_entry = avbtool.AvbIcpEntry(expected_entry_bytes)
    self.assertTrue(icp_entry.is_valid())


    # Tests ICP blob with one entry.
    icp_blob = avbtool.AvbIcpBlob()
    icp_blob.set_algorithm(1)
    icp_blob.add_icp_entry(icp_entry)
    self.assertTrue(icp_blob.is_valid())

    # Now add a 2nd entry (this should fail).
    tl_url2 = 'aftl-test-server.google.ch'
    sth2 = bytearray()
    sth2.extend('f' * 192)
    proof_hashes2 = bytearray()
    proof_hashes2.extend('g' * 32)
    proof_hashes2.extend('h' * 32)
    self.assertTrue(self, self._validate_icp_entry_with_setters(
        tl_url2, 2, sth2, 2, proof_hashes2, 0))

    icp_entry2 = avbtool.AvbIcpEntry()
    icp_entry2.set_log_url(tl_url2)
    icp_entry2.leaf_index = 2
    icp_entry2.set_signed_root_blob(sth2)
    icp_entry2.set_proofs(2, proof_hashes2)
    icp_entry2.next_entry = 0
    icp_blob.add_icp_entry(icp_entry2)
    self.assertTrue(icp_blob.is_valid())

    # Reset the ICP count to invalidate the entry.
    icp_blob.icp_header.icp_count = 1
    self.assertFalse(icp_blob.is_valid())

    # Fix the entries so this passes.
    icp_blob.icp_header.icp_count = 2
    icp_blob.icp_entries[0].next_entry = 1
    self.assertTrue(icp_blob.is_valid())

    expected_blob_bytes = bytearray(
        b'\x41\x46\x54\x4c\x00\x00\x00\x01\x00\x00'
        '\x00\x01\x00\x00\x00\x01\x00\x02\x00\x00\x00'
        '\x1b\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00'
        '\x00\xa0\x04\x00\x00\x00\x80\x01\x61\x66\x74'
        '\x6c\x2d\x74\x65\x73\x74\x2d\x73\x65\x72\x76'
        '\x65\x72\x2e\x67\x6f\x6f\x67\x6c\x65\x2e\x63'
        '\x6f\x6d\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61'
        '\x61\x61\x61\x61\x61\x61\x61\x61\x62\x62\x62'
        '\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62'
        '\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62\x62'
        '\x62\x62\x62\x62\x62\x62\x62\x63\x63\x63\x63'
        '\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63'
        '\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63'
        '\x63\x63\x63\x63\x63\x63\x64\x64\x64\x64\x64'
        '\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64'
        '\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64'
        '\x64\x64\x64\x64\x64\x65\x65\x65\x65\x65\x65'
        '\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65'
        '\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65\x65'
        '\x65\x65\x65\x65\x00\x00\x00\x1a\x00\x00\x00'
        '\x00\x00\x00\x00\x02\x00\x00\x00\xc0\x02\x00'
        '\x00\x00\x40\x00\x61\x66\x74\x6c\x2d\x74\x65'
        '\x73\x74\x2d\x73\x65\x72\x76\x65\x72\x2e\x67'
        '\x6f\x6f\x67\x6c\x65\x2e\x63\x68\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
        '\x66\x66\x67\x67\x67\x67\x67\x67\x67\x67\x67'
        '\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67'
        '\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67\x67'
        '\x67\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68'
        '\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68'
        '\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68\x68')
    self.assertTrue(icp_blob.encode(), expected_blob_bytes)

    icp_blob = avbtool.AvbIcpBlob(expected_blob_bytes)
    self.assertTrue(icp_blob.is_valid())


if __name__ == '__main__':
  unittest.main(verbosity=2)
