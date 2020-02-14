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
"""Integration tests for avbtool with AFTL.

The test cases directly interact with a transparency log. However,
before using this script the following environment variables
need to be set:

  AFTL_HOST: host:port of the transparency log to test with.
  AFTL_PUBKEY: Transparency log public key in PEM format.
  AFTL_VBMETA_IMAGE: VBMeta image that should be used for submission to AFTL.
  AFTL_MANUFACTURER_KEY: Manufacturer signing key used to sign submissions
      to the transparency log in PEM format.
"""

import io
import os
import unittest

import aftltool


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

    self.info_icp_default_params = {
        'vbmeta_image_path': self.output_filename,
        'output': io.BytesIO()
    }

    self.verify_icp_default_params = {
        'vbmeta_image_path': self.output_filename,
        'transparency_log_pub_keys': [self.aftl_pubkey],
        'output': io.BytesIO()
    }

  def tearDown(self):
    """Tears down the test bed for the unit tests."""
    try:
      os.remove(self.output_filename)
    except IOError:
      pass
    super(AFTLIntegrationTest, self).tearDown()

  def test_make_and_verify_icp_with_1_log(self):
    """Tests integration of aftltool with one AFTL."""
    # Make a VBmeta image with ICP.
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = self.aftltool.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      self.assertTrue(result)

    # Checks that there is 1 ICP.
    aftl_descriptor = self.aftltool.get_aftl_descriptor(self.output_filename)
    self.assertEqual(aftl_descriptor.icp_header.icp_count, 1)

    # Verifies the generated image.
    result = self.aftltool.verify_image_icp(**self.verify_icp_default_params)
    self.assertTrue(result)

    # Prints the image details.
    result = self.aftltool.info_image_icp(**self.info_icp_default_params)
    self.assertTrue(result)

  def test_make_and_verify_icp_with_2_logs(self):
    # Reconfigures default parameters with two transparency logs.
    self.make_icp_default_params['transparency_log_servers'] = [
        self.aftl_host, self.aftl_host]
    self.make_icp_default_params['transparency_log_pub_keys'] = [
        self.aftl_pubkey, self.aftl_pubkey]

    # Make a VBmeta image with ICP.
    with open(self.output_filename, 'wb') as output_file:
      self.make_icp_default_params['output'] = output_file
      result = self.aftltool.make_icp_from_vbmeta(
          **self.make_icp_default_params)
      self.assertTrue(result)

    # Checks that there are 2 ICPs.
    aftl_descriptor = self.aftltool.get_aftl_descriptor(self.output_filename)
    self.assertEqual(aftl_descriptor.icp_header.icp_count, 2)

    # Verifies the generated image.
    result = self.aftltool.verify_image_icp(**self.verify_icp_default_params)
    self.assertTrue(result)

    # Prints the image details.
    result = self.aftltool.info_image_icp(**self.info_icp_default_params)
    self.assertTrue(result)


if __name__ == '__main__':
  unittest.main(verbosity=2)
