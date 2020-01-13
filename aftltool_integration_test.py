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
"""Integration tests for aftltool with AFTL.

The test cases directly interact with a transparency log. However,
before using this script the following environment variables
need to be set:

  AFTL_HOST: host:port of the transparency log to test with.
  AFTL_PUBKEY: Transparency log public key in PEM format.
  AFTL_VBMETA_IMAGE: VBMeta image that should be used for submission to AFTL.
  AFTL_MANUFACTURER_KEY: Manufacturer signing key used to sign submissions
      to the transparency log in PEM format.
"""

import os
import unittest

import aftltool
import avbtool


class AFTLIntegrationTest(unittest.TestCase):
  """Test suite for testing aftltool with a AFTL."""

  def setUp(self):
    """Sets up the test bed for the unit tests."""
    super(AFTLIntegrationTest, self).setUp()
    self.aftltool = aftltool.Aftl()
    self.output_filename = 'vbmeta_icp.img'

    self.aftl_host = os.environ.get('AFTL_HOST')
    self.aftl_pubkey = os.environ.get('AFTL_PUBKEY')
    self.vbmeta_image = os.environ.get('AFTL_VBMETA_IMAGE')
    self.manufacturer_key = os.environ.get('AFTL_MANUFACTURER_KEY')

    if (not self.aftl_host or not self.aftl_pubkey or not self.vbmeta_image
        or not self.manufacturer_key):
      self.fail('Environment variables not correctly set up. See description of'
                ' this test case for details')

    self.make_icp_default_params = {
        'vbmeta_image_path': self.vbmeta_image,
        'output': None,
        'signing_helper': None,
        'signing_helper_with_files': None,
        'version_incremental': '1',
        'transparency_log_servers': [self.aftl_host],
        'transparency_log_pub_keys': [self.aftl_pubkey],
        'manufacturer_key': self.manufacturer_key,
        'padding_size': 0
    }

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    try:
      os.remove(self.output_filename)
    except IOError:
      pass
    super(AFTLIntegrationTest, self).tearDown()

  def _read_icp_from_vbmeta_blob(self):
    """Reads the ICP from the output file.

    Returns:
      AftlDescriptor for the ICP included in the given vbmeta image.
    """
    image = avbtool.ImageHandler(self.output_filename)

    # pylint: disable=protected-access
    (footer, header, _, _) = self.aftltool._parse_image(image)
    offset = 0
    if footer:
      offset = footer.vbmeta_offset
    image.seek(offset)
    vbmeta_blob = image.read(header.SIZE +
                             header.authentication_data_block_size +
                             header.auxiliary_data_block_size)
    image.seek(offset + len(vbmeta_blob))
    # TODO(jpm): Fix AftlDescriptor so that the length of it can be derived
    # without having to read the whole descriptor.
    icp_bytes = image.read(100000)
    self.assertGreater(len(icp_bytes), 0)

    icp_blob = aftltool.AftlDescriptor(icp_bytes)
    self.assertTrue(icp_blob.is_valid())
    return icp_blob

  def _make_icp_from_vbmeta(self):
    """Submits vbmeta to AFTL and fetches inclusion proofs.

    Returns:
      True if make_icp_from_vbmeta command succeeds; otherwise False.
    """
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = self.aftltool.make_icp_from_vbmeta(
          **self.make_icp_default_params)
    return result

  def test_make_icp_with_one_transparency_log(self):
    """Tests integration of aftltool with one AFTL."""
    # Submits vbmeta to AFTL and fetches ICP.
    result = self._make_icp_from_vbmeta()
    self.assertTrue(result)

    # Reads back the vbmeta image with the ICP.
    icp_blob = self._read_icp_from_vbmeta_blob()

    # Checks ICP proof blob for correctness.
    icp_header = icp_blob.icp_header
    self.assertIsNotNone(icp_header)
    self.assertEqual(icp_header.magic, 'AFTL')
    self.assertEqual(icp_header.icp_count, 1)

    self.assertEqual(len(icp_blob.icp_entries), 1)
    for icp in icp_blob.icp_entries:
      self.assertEqual(icp.log_url, self.aftl_host)
      self.assertTrue(icp.verify_icp(self.aftl_pubkey))

  def test_make_icp_with_two_transparency_log(self):
    """Tests integration of aftltool with two AFTLs."""
    # Reconfigures default parameters with two transparency logs.
    self.make_icp_default_params['transparency_log_servers'] = [
        self.aftl_host, self.aftl_host]
    self.make_icp_default_params['transparency_log_pub_keys'] = [
        self.aftl_pubkey, self.aftl_pubkey]

    # Submits vbmeta to two AFTLs and fetches their ICPs.
    result = self._make_icp_from_vbmeta()
    self.assertTrue(result)

    # Reads back the vbmeta image with the ICP.
    icp_blob = self._read_icp_from_vbmeta_blob()

    # Checks ICP proof blob for correctness.
    icp_header = icp_blob.icp_header
    self.assertIsNotNone(icp_header)
    self.assertEqual(icp_header.magic, 'AFTL')
    self.assertEqual(icp_header.icp_count, 2)

    self.assertEqual(len(icp_blob.icp_entries), 2)
    for icp in icp_blob.icp_entries:
      self.assertEqual(icp.log_url, self.aftl_host)
      self.assertTrue(icp.verify_icp(self.aftl_pubkey))


if __name__ == '__main__':
  unittest.main()
