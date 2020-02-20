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
"""Integration tests for the avbtool with an actual AFTL.

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
import aftltool_test


class AftlIntegrationTest(aftltool_test.AftlTest):
  """Test suite for integration testing aftltool with an actual AFTL.

  Note: The actual testcases are implemented are implemented as part of the
  super class. This class only contains the configuration for running the unit
  tests against as a live log as a means of integration testing.
  """

  def set_up_environment(self):
    """Sets up the environment for integration testing with actual AFTL."""
    self.aftl_host = os.environ.get('AFTL_HOST')
    self.aftl_pubkey = os.environ.get('AFTL_PUBKEY')
    self.vbmeta_image = os.environ.get('AFTL_VBMETA_IMAGE')
    self.manufacturer_key = os.environ.get('AFTL_MANUFACTURER_KEY')

    if (not self.aftl_host or not self.aftl_pubkey or not self.vbmeta_image
        or not self.manufacturer_key):
      self.fail('Environment variables not correctly set up. See description of'
                ' this test case for details')

  def get_aftl_implementation(self, canned_response):
    """Retrieves an instance if aftltool.Aftl for integration testing.

    Arguments:
      canned_response: Since we are using the actual implementation and not a
      mock this gets ignored.

    Returns:
      An instance of aftltool.Aftl()
    """
    return aftltool.Aftl()


if __name__ == '__main__':
  unittest.main(verbosity=2)
